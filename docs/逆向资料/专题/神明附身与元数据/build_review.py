"""复验神明专题文件证据，生成显式人工清单；不访问游戏进程、不推导全程序完成率。"""
import collections
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FILES = ('metadata.json', 'attachment.json', 'predicates.json', 'lifecycle_partial.json',
         'consumers_partial.json', 'config_order_partial.json', 'producers_partial.json')

# 每一项仅承诺写明的局部语义；尤其不把大函数全量导出等同于全部分支已理解。
REVIEW = {
    0x623EE0: '初始化数据线程先以6287F0返回对象加载Data/Npc.kpd，失败返回0；其它资源装载仅作顺序参照。',
    0x6287F0: 'A766CC单例首次分配8B，构造7ED400；复用40C1接口并补装载对象归属。',
    0x7ED400: '只初始化管理对象+4表指针为0，不据此将+0条数称已初始化。',
    0x7ED420: '非空表调用7EE290数组析构并清+4，不重置+0条数。',
    0x7ED490: '统计NPC块数，分配72B行数组，按indx写名称/affix/anew/资源/影子/hurt；没有本体indx界限检查。',
    0x7ED340: '72B行构造清指针、绘制状态与计时字段，图像句柄+36/+40=-1；不初始化整行。',
    0x7ED3B0: '析构释放行+32的图像句柄数组并清指针，不直接释放每个图像资源。',
    0x7EE290: '标志控制单行/数组析构；数组步长72并按数组头计数释放。',
    0x694790: '返回表指针+72*id的名称地址；复用40C1接口。',
    0x63E260: '读取表行+40的图像句柄；复用40C1接口并关联bHead装载。',
    0x7FDBD0: '返回表行+63 signed BYTE即affix；7F7DB0用于初始化角色附身计数。',
    0x7ECAC0: '返回表行+64 signed BYTE即anew；7E2810写地图重生记录。',
    0x7D6E00: '返回表行+68 DWORD即hurt；只定义基础量，不等于最终结算值。',
    0x6926A0: 'unsigned id<8或id==18返回真，装载时写行+65浮动绘制分支标志。',
    0x7EDAD0: '按行+65分支绘制NPC，读+32/+36与影子，更新浮动/计时；未见将+60设1。',
    0x7EDEE0: '直接按资源组6/id及参数<=1选择子图绘制，另绘公共影子。',
    0x67F8F0: '6051按record+2选P，+3神明ID/+4标记/+6地图位置交setter，显示UI6并写1800等待。',
    0x7F16D0: '6051桥将首参G置ECX、次参record入栈，转发67F8F0；桥retn、处理器retn4。',
    0x694810: '6051构造只写首WORD和+4 BYTE=1，不能据12B跨度补齐其他字段。',
    0x7F7DB0: '写P+1488神明ID/+1489输入标记/+1490表affix；地图位置非-1时清对应动态物件。',
    0x7F7CF0: '无附身返回-1；有附身先窄BYTE减1，剩余signed>0返回-1，否则返回旧ID而不清附身。',
    0x7F7E30: '窄BYTE加参数，再将signed结果与GValue[37]比较，超出时窄写上限；不是饱和加法。',
    0x7D7430: '窄BYTE减参数写P+1490，无下限钳制、不清附身。',
    0x7F7D50: '复用清三字段逻辑；补证P+1740>0时清P+1740，未直接清P+1744。',
    0x7016B0: '读取DWORD[P+1740]>0作为附属值存在门，不擅名为装备资源。',
    0x7FDBA0: '只将DWORD[P+1740]写0，返回this。',
    0x7E28B0: '按地图动态类型调用相关清理并按末判定清该格三字节；本篇只核setter调用点。',
    0x7E2810: '地图重生表搜索相同ID，写anew至记录+4并减活动数；与角色affix计数分离。',
    0x63E4D0: 'signed BYTE[P+1488]==7。',
    0x693510: 'signed BYTE[P+1488]!=-1；复用附身存在门。',
    0x693D10: 'signed BYTE[P+1488]==2。',
    0x693E80: '返回signed BYTE[P+1488]；复用40C1取旧ID接口。',
    0x694C90: 'signed BYTE[P+1488]==0。',
    0x694CC0: 'signed BYTE[P+1488]==1。',
    0x701530: 'signed BYTE[P+1488]==3。',
    0x727B40: 'signed BYTE[P+1488]==4。',
    0x727B70: 'signed BYTE[P+1488]==6。',
    0x7D61A0: '附身ID不为-1且属于1/2/6/7/18时返回真；集合用途不外推。',
    0x7D7400: 'signed BYTE[P+1488]==5。',
    0x6947C0: '复用ID集合1/2/6/7/18；资源可给名称，完整资格效果尚未恢复。',
    0x694D30: 'ID集合0/3/4/5；6051据此设置目标动作值4。',
    0x7F3840: '仅核角色构造的P+1488/-1、+1489/-1、+1490/0三处写入。',
    0x7F91F0: '仅核状态清理路径经存在门调用7F7D50；库存删除和其它状态不计完整审阅。',
    0x7FAA40: '仅核重置路径只在附身ID7时调用7F7D50，并非清全部附身。',
    0x7BE160: '仅核受参与者资格门控制的清理分支选择P(slot)，有附身则清；业务退出条件未全恢复。',
    0x7BE450: '仅核受参与者资格门控制的清理分支选择P(slot)，有附身则清；其它状态不计全完成。',
    0x7C0C50: '仅核当前角色倒计时调用及返回ID!= -1时排6050，调用节拍/外围门不作日历保证。',
    0x7C6640: '仅核当前角色减少后再减1判到期、正增量延长的局部分支；未恢复整套技能结算。',
    0x7F48D0: '仅核附身头像取行+40，计数>0用资源组10/47绘制数量；其余角色绘制未全审。',
    0x7CE420: '仅核NPC hurt输入后续比例/状态修正链，禁止将hurt直接当最终损伤。',
    0x65EFA0: '仅核4022消费者读取当前附身ID用于后继本地记录；未闭环该消息全部玩法。',
    0x7B9AD0: '从Data/GValue.kpd读取ITEM indx/value写A87080+4*indx，当前37映射A87114。',
    0x7B74C0: '仅核末段调用7B9AD0的配置装载顺序，不据此恢复所有启动设置。',
    0x623B60: '仅核启动初始化调用7B74C0发生在返回主循环前。',
    0x625310: '仅核加载阶段创建线程623EE0、正常退出码1推进；Npc失败码0显示InitData Failed。',
    0x7A3D90: '仅核WinMain先初始化623B60再进入逐帧循环，不运行程序。',
    0x624CA0: '仅核按主状态索引调用表中的625310；其它帧处理未全审。',
    0x673AF0: '仅核6051生产样本显式+3=0/+4=2/+6=-1，证明标记并非永远构造默认1。',
    0x673D50: '仅核6051生产样本显式+3=3/+4=2/+6=-1；完整卡牌请求路径另查。',
}
REUSED = {0x6287F0, 0x694790, 0x63E260, 0x7F7D50, 0x693510, 0x693E80, 0x6947C0}
PARTIAL = {0x623EE0, 0x7E28B0, 0x7F3840, 0x7F91F0, 0x7FAA40, 0x7BE160, 0x7BE450,
           0x7C0C50, 0x7C6640, 0x7F48D0, 0x7CE420, 0x65EFA0, 0x7B74C0, 0x623B60,
           0x625310, 0x7A3D90, 0x624CA0, 0x673AF0, 0x673D50}


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    n = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + i * 40 + 8) for i in range(n)]
    checks, ranges, thunks, entries, byte_count, chunks = 0, set(), set(), {}, 0, 0

    def disk(ea, size):
        for _, rva, raw_size, offset in sections:
            delta = ea - base - rva
            if 0 <= delta and delta + size <= raw_size:
                return blob[offset + delta:offset + delta + size]
        return None

    def verify(row):
        nonlocal checks
        ea, size = int(row['va'], 16), row['size']
        actual = disk(ea, size)
        assert actual is not None and actual.hex() == row['idb_hex'] == row['disk_hex'] and row['matching'], row['va']
        checks += 1
        ranges.add((ea, size))

    for name in FILES:
        evidence = json.loads((HERE / '证据' / name).read_text('utf-8'))
        assert evidence['disk_sha256'] == sha
        for f in evidence['functions']:
            va = int(f['va'], 16)
            assert va not in entries and va in REVIEW
            covered = set()
            for row in f['byte_ranges']:
                verify(row)
                byte_count += row['size']
                covered.update(range(int(row['va'], 16), int(row['va'], 16) + row['size']))
            for chunk in f['declared_chunks']:
                chunks += 1
                assert set(range(int(chunk['start_va'], 16), int(chunk['end_va'], 16))) <= covered, f['va']
            status = '复用接口补证' if va in REUSED else '局部字段或调用链已审阅' if va in PARTIAL else '局部语义已审阅'
            entries[va] = dict(va=f['va'], status=status, conclusion=REVIEW[va], evidence='证据/' + name,
                               unknown='未实机；未声明代码、别名及批量写入、调用节拍、全部UI/技能分支不计完成。')
        for row in evidence['thunks']:
            verify(row)
            data = bytes.fromhex(row['idb_hex'])
            assert data[0] == 0xe9 and int(row['va'], 16) + 5 + int.from_bytes(data[1:], 'little', signed=True) == int(row['target'], 16)
            thunks.add(row['va'])
    assert set(entries) == set(REVIEW) and len(entries) == 59
    layout = json.loads((HERE / '证据/data_layout.json').read_text('utf-8'))
    assert layout['disk_sha256'] == sha and disk(0xA87114, 4) is None
    assert 0xA87080 + 37 * 4 == 0xA87114
    for row in layout['byte_ranges']:
        verify(row)
    decode = runpy.run_path(str(HERE / '证据/inspect_resources.py'))['decode_resource']
    samples = json.loads((HERE / '证据/resource_samples.json').read_text('utf-8'))['records']
    for row in samples:
        assert decode(row['source'], row['encoding']) == row
    npc, values = samples
    assert [int(s['fields']['indx']) for s in npc['sections']] == list(range(34))
    assert next(s['fields']['value'] for s in values['sections'] if s['fields'].get('indx') == '37') == '5'
    for path in HERE.rglob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8', errors='strict').splitlines()), str(path)
    manifest = dict(scope='神明/NPC元数据和附身三字段局部证据；复用接口与大函数局部范围明确分列',
                    functions=[entries[va] for va in sorted(entries)])
    (HERE / '函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    result = dict(disk_sha256=sha, functions=len(entries), statuses=dict(collections.Counter(x['status'] for x in entries.values())),
                  function_bytes=byte_count, declared_chunks=chunks, unique_e9_thunks=len(thunks), byte_comparisons=checks,
                  unique_byte_ranges=len(ranges), resources=len(samples), npc_records=34, data_layout_ranges=len(layout['byte_ranges']),
                  all_disk_bytes_match=True, declared_chunks_covered=True, doc_format_passed=True,
                  boundary='不把数据留档、候选扫描或复用内容计为全程序语义完成，也不代表实机通过。')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
