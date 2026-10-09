"""只读核验送神卡专题并生成显式局部清单；不把接口导出算实机闭环。"""
import collections
import hashlib
import json
import runpy
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FILES = ('entry.json', 'helpers.json', 'consumers.json', 'status_inventory.json',
         'followup.json', 'bridge_ui_animation.json', 'god_animation.json', 'animation_fields.json',
         'conditional_6002.json')
# 每条均为人工核读结论；这里只复验证据和引用，不从相似汇编推导业务名称。
REVIEW = {
 0x66FC80: ('40C1校验GmsvID后按序排6007/6003/可选6050/6061/可选6006；目标由+6，扣卡槽/组由+4/+5，扣卡角色由current。', '请求生产者、资格检查、失败回复和精确线长未闭环。'),
 0x7F09B0: ('桥接首参G装ECX、第二参指针push，61071F进入66FC80；本体不取消息长度。', '分派器的外部长度检查另查网络专题。'),
 0x6944A0: ('构造6007首WORD，+5 BYTE=0、+8 DWORD=0，未初始化整个12B。', 'type枚举不能由构造器推出。'),
 0x693370: ('按DWORD[this]+1128*index+660返回元数据名称地址；40C1固定索引1048。', '表装载和index合法域未递归展开。'),
 0x63E1C0: ('返回P+112；40C1使用该位置作目标名字。', '字段总容量与写入约束未恢复。'),
 0x693510: ('读取signed BYTE[P+1488]，与-1比较返回BOOL。', '附身资格规则及所有写入源未穷尽。'),
 0x693570: ('只写首WORD6050并返回this。', '其余记录字节由调用者决定。'),
 0x63F6E0: ('构造6061，+6=1，+7/+8/+9=0；未写+2/+4/+5。', '不代表所有字段在所有分支都消费。'),
 0x63F760: ('比较DWORD[G+0xE28]与DWORD[G+8]，返回当前是否本地槽。', '两槽初始化和同步链未展开。'),
 0x693980: ('只写首WORD6006并返回this。', '控制参数由调用者写入。'),
 0x627B60: ('取A766DC单例，首次分配12B并调用6D7170。', '字符串表装载及线程同步未复原。'),
 0x629D90: ('返回DWORD[this+8]+DWORD[this]*index作为文本槽地址。', '槽长和index总数由装载器决定。'),
 0x627C20: ('A766E0单例getter，首次分配14Ch并调用构造。', '本篇未递归分析构造与所有表。'),
 0x6932B0: ('构造6003，+4/+5/+6清0，DWORD+8/+12/+16/+20清0。', '其他保留字节未初始化。'),
 0x63E5B0: ('读取G+0x640队列当前插入位置。', '队列ABI及容量沿用基础对象与分派专题。'),
 0x64FA50: ('ECX=G按Src/Size/index复制记录并交6980F0指定位置插入；本组链式使用返回位置。', '失败、并发及消费门控不由此调用点证明。'),
 0x64F710: ('输入WORD与WORD[G+0x14784]比较，不一致弹诊断框并返回0。', '消息是否可信、外部长度检查另核。'),
 0x67DA40: ('6003按+4/+5显示隐藏，+16内容交UI，+6非零时+12或回退+8写等待。', 'UI4文本复制时机和+20语义未闭环。'),
 0x67DBE0: ('6006检查+2及当前P+1493/+1494/+1495，与-1比较决定向712610传0/1。', '控件树更新与网络后续未展开。'),
 0x67DC90: ('6007先用类型查表设置P+388及P+864子对象，再按P+40!=-1显示UI/声音/可选等待。', '各type全枚举及UI23实际绘制未穷尽。'),
 0x67F680: ('6050先保存旧P+1488，再清附身三字段，启动动画3；附带文字/声音/条件头像事件。', '全部神明资格和额外UI门条件未穷尽。'),
 0x67FBE0: ('6061真实ECX=G；+8优先加group0，否则+9按slot/group/数量扣库存，P取+4 signed槽。', '负槽/组的上游校验及请求可信性未证明。'),
 0x7F8780: ('group0八槽首空槽插入ID/数量，成功后可配方合成/通知UI12，另有P+1416强制成功门。', '配方全表及额外资格见4050专题，未实机。'),
 0x7F8F90: ('ECX=P，group0调用7F8920，group1/2调用7F8B50并传flag1；retn0Ch。', '非法group路径返回值未规范化。'),
 0x7F8B50: ('group1/2数量WORD相减，<=0清ID及数量，单件flag路径先交旧ID到7D02B0。', '7D02B0附属效果、槽合法域未展开。'),
 0x7F8920: ('group0窄WORD减数量，signed<=0清ID/数量，本机判断后刷新UI12。', '非法数量及slot由上游保证与否未知。'),
 0x693E80: ('读signed BYTE[P+1488]；6050在清除前保存此值。', '神明ID的完整合法域待查。'),
 0x7F7D50: ('P+1488/+1489置-1、+1490置0；7016B0检查P+1740为正时经7FDBA0清该DWORD，不清P+1744。', '附属值产品含义、全部调用资格与三字段全部写入源未穷尽。'),
 0x7FB200: ('首次初始化63项DWORD表；6007本组type47命中值4。', '其余类型与自然动作名不因本组分析算完成。'),
 0x7F7670: ('写P+388并把同值交P+864子对象。', '子对象的头像/步态完整状态规则另查。'),
 0x694C20: ('读取DWORD[this+40]与-1比较；6007调用点this=P。', 'P+40装载及角色资源枚举另查。'),
 0x694BF0: ('返回type+1000*(DWORD[this+40]+1)，6007用作声音编号。', '声音可播放性和表有效域未实机。'),
 0x694790: ('返回DWORD[this+4]+72*index，6050用作旧附身名称指针。', '元数据装载/完整条目边界未展开。'),
 0x6947C0: ('仅判index属于1/2/6/7/18，6050据此补类型3的6002。', '集合完整业务原因未确认。'),
 0x693260: ('构造首WORD6002、BYTE+5=0/+6=1、DWORD+8=0。', '其余字段由调用者填入，不能等同6007。'),
 0x67D880: ('6002先设目标动作，再按P+40!=-1显示UI/声音；record+6非零才取+8或默认1800写等待。', '动作内部与UI消费者未在本篇完全展开。'),
 0x694CF0: ('参数等于4返回BOOL。', '该ID完整神明机制未恢复。'),
 0x694D10: ('参数等于6返回BOOL。', '该ID完整神明机制未恢复。'),
 0x7FB150: ('局部核验附身资格门及资源表二次判断，6050据结果决定UI1通知。', '门内部所有对象归属与资源规则尚未展开。'),
 0x63E560: ('比较传入slot与DWORD[G+8]，用于目标是否本机。', '本地槽赋值链未展开。'),
 0x6D7170: ('文本表对象构造只写DWORD[this+8]=0。', '其余字段装载来自其他路径，不能凭构造补0。'),
 0x6279C0: ('UI管理单例，首次分配6C0h并调用构造。', '全部UI注册/资源装载沿用界面专题。'),
 0x6E4640: ('检查UI槽对象存在后向虚表+10h传通知指针。', 'UI4/23/1/12具体间接消费者未全部展开。'),
 0x6E3B40: ('按UI号进入显示/创建路径；本组UI4/23参数1800与0。', '具体窗口状态/计时器和资源见界面专题。'),
 0x7A5C30: ('按40B槽取对象或工厂，调用启动虚函数、写tick并加入活动列表。', '配置最大时长及完整更新循环沿用动画专题。'),
 0x64FB10: ('写DWORD[this+12]=等待值，DWORD[this+16]=GetTickCount。', '其他消费门和等待解除条件另查。'),
 0x6287F0: ('A766CC单例，首次分配8B并调用构造。', '本篇不复原72B元数据表装载。'),
 0x7A66E0: ('动画3工厂分配1Ch后调用7AA1D0，失败返回0。', '调用方分配失败后处理未闭环。'),
 0x7AA1D0: ('先调用动画基类构造，再写A2BFE0虚表。', '基类全部生命周期另查。'),
 0x6304B0: ('动画3启动取目标坐标/镜头偏移，写x/y、步长6、旧附身图像编号，并启动16ms门。', '地图镜头和图像资源合法性未递归穷尽。'),
 0x630580: ('每次先绘图，16ms门通过才y-=6，返回y<=0。', '绘制后端及管理器配置超时不由本体复原。'),
 0x63E6A0: ('动画3结束虚函数本体为空。', '管理器的资源释放行为不在空回调内。'),
 0x63F4A0: ('signed BYTE[this+1493]!=-1返回BOOL。', '字段自然名称和所有写入源另查。'),
 0x63EF50: ('signed BYTE[this+1494]!=-1返回BOOL。', '住院规则见对应事件专题。'),
 0x63EF80: ('signed BYTE[this+1495]!=-1返回BOOL。', '字段自然名称和所有写入源另查。'),
 0x63E260: ('从72B元数据行+40读DWORD；动画3保存该图像编号。', '行总数、图像资源映射未展开。'),
 0x63E020: ('读DWORD[P+540]，动画3作x来源。', '坐标所有写入源见地图/移动专题。'),
 0x63E050: ('读DWORD[P+544]，动画3作y来源。', '坐标所有写入源见地图/移动专题。'),
 0x63E000: ('返回this+4；动画3用作镜头signed WORD偏移地址。', '镜头对象完整结构另查。'),
 0x81BCB0: ('写DWORD[this]阈值及DWORD[this+4]起始tick。', '调用者可使用不同计时阈值，非动画独有。'),
 0x81BD10: ('now>start且差值>=阈值才通过，通过后更新start。', 'tick回绕时now<=start返回假，未实机观察。'),
}
REUSED = {0x63E5B0, 0x64FA50, 0x64F710, 0x7F8780, 0x7F8920,
          0x64FB10, 0x6279C0, 0x6E4640, 0x7A5C30}


def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    n = struct.unpack_from('<H', blob, pe+6)[0]
    optional = struct.unpack_from('<H', blob, pe+20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8) for i in range(n)]
    checks, spans, thunks = 0, {}, {}
    def verify(row):
        nonlocal checks
        ea, size = int(row['va'], 16), row['size']
        actual = None
        for _, rva, raw_size, raw in sections:
            delta = ea-base-rva
            if 0 <= delta and delta+size <= raw_size:
                actual = blob[raw+delta:raw+delta+size].hex()
                break
        assert actual is not None, row['va']
        assert actual == row['idb_hex'] == row['disk_hex'] and row['matching'], row['va']
        spans[(ea, size)] = row
        checks += 1
    entries = {}
    instruction_bytes = 0
    for name in FILES:
        evidence = json.loads((HERE/'证据'/name).read_text(encoding='utf-8'))
        assert evidence['disk_sha256'] == sha
        for f in evidence['functions']:
            va = int(f['va'], 16)
            assert va not in entries and va in REVIEW, hex(va)
            for span in f['byte_ranges']:
                verify(span)
                instruction_bytes += span['size']
            assert f['declared_chunks'], f['va']
            for chunk in f['declared_chunks']:
                start, end = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                covered = [(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['byte_ranges']]
                assert all(any(a <= value < b for a,b in covered) for value in range(start,end)), (f['va'],chunk)
            conclusion, unknown = REVIEW[va]
            entries[va] = dict(va=f['va'], status='复用接口局部已核' if va in REUSED else '局部语义已审阅',
                conclusion=conclusion, unknown=unknown, evidence='证据/'+name)
        for t in evidence['thunks']:
            verify(t)
            target = int(t['va'],16)+5+int.from_bytes(bytes.fromhex(t['idb_hex'])[1:], 'little', signed=True)
            assert t['target'] == hex(target)
            thunks[t['va']] = t
    assert set(entries) == set(REVIEW) and len(entries) == 61
    layout = json.loads((HERE/'证据/data_layout.json').read_text(encoding='utf-8'))
    assert layout['disk_sha256'] == sha
    for row in layout['byte_ranges']:
        verify(row)
    assert [r['size'] for r in layout['rtcs'][0]['entries']] == [12,24,4,10,4]
    assert [r['size'] for r in layout['rtcs'][1]['entries']] == [128,8,12,8]
    assert layout['registration']['handler'] == '0x66fc80'
    for address, target in zip(layout['vtable_words'][:3], [0x6304B0,0x63E6A0,0x630580]):
        row = next(r for r in layout['byte_ranges'] if int(r['va'],16) == address)
        data = bytes.fromhex(row['idb_hex'])
        assert data[0] == 0xe9 and address+5+int.from_bytes(data[1:], 'little', signed=True) == target
    sample = json.loads((HERE/'证据/resource_samples.json').read_text(encoding='utf-8'))
    parse = runpy.run_path(str(HERE/'证据/inspect_resources.py'))['sections']
    for row in sample['records']:
        source = (ROOT/row['source']).read_bytes()
        assert hashlib.sha256(source).hexdigest() == row['source_sha256']
        key = source[0]
        expanded, packed = struct.unpack('<II', bytes((b-key)&255 for b in source[1:9]))
        assert 0 < expanded <= 64*1024*1024 and 0 < packed <= len(source)-9
        decoded = lzokay.decompress(bytes((b-key)&255 for b in source[9:9+packed]), expanded)
        assert len(decoded) == expanded and hashlib.sha256(decoded).hexdigest() == row['decoded_sha256']
        text = decoded.decode('cp950', errors='strict')
        assert text.encode('cp950') == decoded
        ids = {s['fields']['indx'] for s in row['sections']}
        selected = [s for s in parse(text) if s['fields'].get('indx') in ids]
        assert selected == row['sections']
    docs = sorted(HERE.glob('*.txt'))
    for path in docs:
        lines = path.read_text(encoding='utf-8', errors='strict').splitlines()
        assert lines and all(not line.strip() or line.startswith('//') for line in lines), str(path)
    manifest = dict(scope='送神卡本体与局部消费者；不含实机、递归图像后端和请求资格闭环',
                    functions=[entries[va] for va in sorted(entries)])
    (HERE/'函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    result = dict(disk_sha256=sha, functions=len(entries),
        statuses=dict(collections.Counter(r['status'] for r in entries.values())),
        function_instruction_bytes=instruction_bytes, unique_e9_thunks=len(thunks),
        byte_comparisons=checks, unique_byte_ranges=len(spans), data_range_records=len(layout['byte_ranges']),
        resources=len(sample['records']), all_current_disk_bytes_match=True, doc_format_passed=True,
        boundary='字节相同与格式通过不是语义闭环或游戏运行成功。')
    (HERE/'验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
