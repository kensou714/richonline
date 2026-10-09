"""复核本专题原证与当前磁盘，生成逐函数显式审阅记录；不从导出量推断完成度。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
FILES = (
    'handlers.json', 'helpers.json', 'consumers.json', 'followups.json',
    'ui40_ctor.json', 'ui40_vtable.json', 'ui40_state_and_send.json', 'map_writer.json',
)
CONCLUSIONS = {
    0x661280: '4036以ECX=G校验+2 WORD，跳过三个signed WORD中的-1，ECX=G+65C按紧凑type22..24调用地图写入；无直接上行。',
    0x661330: '4037以ECX=G校验后，以signed WORD+4为pos、type28调用Map写入；本处没有pos=-1钳制。',
    0x6613A0: '4038校验GmsvID及G+3624与G+8相等；8B UI1通知{3,signed BYTE+8}；signed DWORD+4为正才扣金豆。',
    0x661470: '4039保存ECX后retn4，当前函数无字段写入、校验、UI或网络调用。',
    0x661490: '403A逐分支核对+14绕过校验、+4/+6 signed BYTE及+12 signed WORD门槛；构造6000/6003/6005/6006/6008，详见03文档。',
    0x661D70: '403B校验后strcpy到RTC确认128B栈缓冲；begin创建显示再隐藏，end先交文字再显示，普通文本交UI40。',
    0x661EC0: '403C以signed BYTE+7为槽，signed WORD+4扩展写Summary+132 DWORD，+6写Summary+136 BYTE；本处无槽范围钳制。',
    0x63E410: '返回DWORD[this+1464]；403A调用时this为P，作为地图位置进入6005。',
    0x63E560: '比较栈参数与DWORD[this+8]；4038调用时参数为DWORD[G+3624]。',
    0x63E5B0: '把ECX=this+640后调用getter；403A用返回值续排本地队列，不采用MFC自动名称。',
    0x63F080: '6000构造器写首WORD编号及+8/+12/+16 DWORD=0；未写+2动画号和+4暂停BYTE。',
    0x63F760: '比较DWORD[this+3624]与DWORD[this+8]；403A据此决定是否排6006。',
    0x64F710: '比较对象内GmsvID与传入WORD，不符弹Error GmsvID后返回0；403A +14非零分支绕过它。',
    0x650110: 'G+8索引下从G+1536金豆DWORD减参数，动画事件41携带扣值地址，再交UI1通知类别2。',
    0x6932B0: '6003构造器写首WORD、+4/+5/+6 BYTE和+8/+12/+16/+20 DWORD默认0；403A调用点按24B排队。',
    0x6937D0: '6005构造器写首WORD编号；403A调用点把+2 WORD设为地图位置并按4B排队。',
    0x693980: '6006构造器只写首WORD编号，403A另写+2 BYTE=1；其余栈填充值未被构造器清零。',
    0x693A80: '6008构造器写首WORD编号；403A调用点补+2 UI槽、+4 payload指针、+8长度并按12B排队。',
    0x694140: '写DWORD[this+4]=0，仅作为已导出构造辅助字段对照，不扩展业务命名。',
    0x694170: '检查参数>=0且参数<DWORD[this+3616]；403A用它确认当前行动槽有效。',
    0x6941D0: '写DWORD[this]=-1、BYTE[this+4]=0；403A动画45静态载荷首次初始化后覆盖首DWORD和BYTE。',
    0x7C0A60: '受共同谓词约束，向G+116对应槽交0标志两次，G+3620减1，BYTE[G+83846]=1。',
    0x7C0AE0: '受共同谓词约束，向G+116对应槽交1标志两次，G+3620加1，BYTE[G+83846]=0。',
    0x7C0BB0: '共同谓词非零才读BYTE[G+3640+DWORD(G+116)]，否则返回0；槽未在本函数钳制。',
    0x7F4550: '局部核对403A选中的配置记录同步当前P，涉及名字、状态和装备；内部资源/UI链不计为闭环。',
    0x7F72A0: '局部核对403A以ECX=当前P、signed WORD+8写P+1464并更新坐标；地图坐标映射待展开。',
    0x7F7940: '局部核对写P+1460并把值交P+864子对象；403A来源为signed WORD记录+10。',
    0x8073C0: '以ID扫最多30个568B配置记录，基址this+736，命中返回记录，遇ID=-1停止。',
    0x807440: '扫DWORD[this+17796]个568B配置记录选择当前项；调用谓词和配置装载未展开。',
    0x8074F0: '局部核对按选择ID取配置首DWORD及+8并调用两条同步路径；不把伪码stdcall签名直接当ABI。',
    0x67D750: '6000消费者以signed WORD+2事件和+12指针交动画管理器；BYTE+4非零按+8时长或默认时长再加100暂停。',
    0x67DE20: '6008消费者以signed WORD+2选择UI槽，将+4指针交UI通知桥，不把本地6008当网络消息。',
    0x6E3B40: '局部核对132B槽、工厂及窗口虚表；UI40调用点创建/显示，最终vtable+60及槽标志清0。',
    0x6E4020: '局部核对对象存在且vtable+80为真时调用+64隐藏，管理器槽标志置1；子对象开关仍依虚表。',
    0x6E4640: '从管理器+68所指132B UI槽查+4对象，非空才调用虚表+16交payload；间接UI语义另核。',
    0x71E760: 'UI40文本消费者：begin清count/total，普通文本按128B无界槽复制并加10000时长，end启计时、显示首项并暂停。',
    0x71E8C0: '10000ms后未完翻下一项；完成构造8B0036并经6BF380提交，再解暂停、扣未用pending，返回1。',
    0x71EA30: '按钮controlID2先调用窗口虚表+152；未完翻页，完成执行0036提交/解暂停/扣pending，再6E4020隐藏。',
    0x71EC10: '以DWORD比较返回max(total-(GetTickCount-startTick),0)；tick回绕/异常组时序未动态验证。',
    0x7EFD70: '4036桥接将首参数装ECX、push第二记录指针转thiscall661280。',
    0x7EFD90: '4037桥接将首参数装ECX、push第二记录指针转thiscall661330。',
    0x7EFDB0: '4038桥接将首参数装ECX、push第二记录指针转thiscall6613A0。',
    0x7EFDD0: '4039桥接将首参数装ECX、push第二记录指针转thiscall661470。',
    0x7EFDF0: '403A桥接将首参数装ECX、push第二记录指针转thiscall661490。',
    0x7EFE10: '403B桥接将首参数装ECX、push第二记录指针转thiscall661D70。',
    0x7EFE30: '403C桥接将首参数装ECX、push第二记录指针转thiscall661EC0。',
    0x63E440: '返回DWORD[this+4]；UI40完成时this为G+C44，故取得G+3144用于0036+2 WORD。',
    0x63E590: '返回this+C44共享对象地址；与63E440组合定位UI40上行0036的校验字段来源。',
    0x694BC0: '只导出供6000默认时长检索线索；未独立穷尽事件索引和表容量。',
    0x6E6D90: '只导出UI工厂注册原证；本批未逐分支解释全部UI工厂。',
    0x6E8380: 'UI40工厂分配0x25C字节，成功调用构造6FB9A0，失败返回0。',
    0x71EB50: '局部核对cursor自增选128B槽，调用文本转换/控件更新并写最近显示tick；媒体与控件调用未展开。',
    0x7289B0: '0036构造器只写首WORD0x36；8B长度和后续字段由UI40完成调用点确定。',
    0x7A5C30: '只导出动画管理器分派原证；调用点事件26/41/45已核，间接工厂/资源尚未穷尽。',
    0x6FB9A0: 'UI40构造先调用基础构造后写虚表A26280；派生计数/文本字段由begin协议重置而非本构造。',
    0x6FA100: '把BYTE参数交this+4子窗口虚表+196；UI40 begin/end用它传0/1。',
    0x6E26E0: '窗口虚表+152实现通过单例向另一对象提交(1,0,0)，该间接对象语义未展开。',
    0x6E2520: '窗口显示槽实现对子窗口虚表+200/+196均传1，写窗口+56=0。',
    0x6E2590: '窗口隐藏槽实现对子窗口虚表+200传0，写窗口+56=2。',
    0x71E730: 'UI40隐藏槽先清基础暂停，再调用6E2590隐藏子窗口。',
    0x6FA1E0: '以this+4子窗口作ECX转发6FA210，供虚表+80存在状态门槛使用。',
    0x6FA210: '返回BYTE[this+385]；产品状态名称未独立确认。',
    0x64FB50: '写DWORD[this+12]=0；UI40完成及隐藏槽调用用于清基础暂停。',
    0x64FB10: '写DWORD[this+12]=时长、DWORD[this+16]=GetTickCount；UI40 end传total暂停。',
    0x728970: 'DWORD[this+83792]累加参数；UI40每条普通文字传10000增加pending时长。',
    0x7BB490: 'DWORD[this+83792]以无符号量扣参数，不足置0；UI40完成扣剩余未用时长。',
    0x6BF380: '局部核对状态<12与连接门槛，包装后向事件9交记录；进入此函数不证明实际发送成功。',
    0x7E2380: '从Map+60所指4B位置记录写type/a4/a5前三BYTE，再按类型谓词登记并刷新位置；本处无pos钳制。',
}
ONLY_EXPORTED = {0x694BC0, 0x6E6D90, 0x7A5C30}


def main():
    blob = (PROJECT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count, optional = struct.unpack_from('<H', blob, pe + 6)[0], struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + i * 40 + 8)
                for i in range(count)]

    def check(item):
        va, size = int(item['va'], 16), item['size']
        for _, rva, raw_size, raw in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                current = blob[raw + relative:raw + relative + size].hex()
                assert current == item['disk_hex'] == item['idb_hex'], item['va']
                return
        raise AssertionError('无PE原始映射：' + item['va'])

    records, thunks, total = [], {}, 0
    for name in FILES:
        evidence = json.loads((HERE / '证据' / name).read_text(encoding='utf-8'))
        assert evidence['disk_sha256'] == digest
        for function in evidence['functions']:
            va = int(function['va'], 16)
            assert va in CONCLUSIONS
            for chunk in function['byte_ranges']:
                check(chunk)
                total += chunk['size']
            status = '仅导出' if va in ONLY_EXPORTED else '局部静态语义已审阅'
            if va == 0x661470:
                status = '已分析（空实现）'
            records.append(dict(va=function['va'], status=status,
                                conclusion=CONCLUSIONS[va], evidence='证据/' + name,
                                unknown='未实机验证；上游长度/槽校验、间接虚表、资源映射及连接后实际发送均不计为已闭环。'))
        for thunk in evidence['thunks']:
            check(thunk)
            thunks[thunk['va']] = thunk
    layout = json.loads((HERE / '证据/data_layout.json').read_text(encoding='utf-8'))
    assert layout['disk_sha256'] == digest
    for item in layout['data_ranges']:
        check(item)
    assert len(records) == len(CONCLUSIONS) == 68
    assert len({r['va'] for r in records}) == len(records)
    output = dict(scope='4036系列及直接消费者、UI40布局与局部上行链静态审阅', functions=records)
    (HERE / '审阅清单.json').write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    result = dict(disk_sha256=digest, functions=len(records), function_instruction_bytes=total,
                  unique_e9_thunks=len(thunks), data_byte_ranges=len(layout['data_ranges']),
                  all_current_disk_bytes_match=True, runtime_verified=False,
                  review_counts={'局部静态语义已审阅': len(records) - len(ONLY_EXPORTED) - 1,
                                 '仅导出': len(ONLY_EXPORTED), '已分析（空实现）': 1})
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
