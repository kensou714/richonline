"""复验当前磁盘、IDA 原证、资源和局部模型；不启动游戏、不修改数据库。"""
import collections
import hashlib
import json
import struct
from pathlib import Path
from inspect_resources import collect
from model import verify_boundaries

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REVIEW = {
    0x69DF50: '只核条目数组指针与两组计数构造；总槽数字段未在本函数初始化。',
    0x69E600: '只核条目数组删除并清零；未清两组视图或计数。',
    0x6A8C20: '本地分派50接收8字节两标识，返回后将+4/+8置-1；RTC补证见独审，不证明线上删除。',
    0x6A8E00: '两类别倒序重建，先类别0，过滤特殊编码，普通共享70限额，礼物不套70上限。',
    0x6A90E0: '有效类别0存在查询；参数仅读低8位，非零时只计入谓词返回0的条目。',
    0x6A91A0: '有效类别0计数；参数仅读低8位，非零时排除谓词返回1的条目。',
    0x6A9270: '复制8字节到9字节局部；索引3为1且索引5为2时返回AL=1。',
    0x6A9330: '类别0正序查首条；参数仅读低8位，零查谓词0、非零查谓词1，失败返回0。',
    0x6A9430: '删除旧数组，设置100槽并分配33200字节；逐槽构造只初始化有效标识。',
    0x6AEBE0: '只核数据号39单条内存复制、满槽局部分支缺失、分组和UI108通知。',
    0x6AEF10: '只核数据号38的108/332步长映射、输入count循环、分组及Remove(1)，未直接通知UI108。',
    0x6AF1E0: '只核重建分组并通知UI108；其他UI和提示路径未完整恢复。',
    0x6AF490: '只核重建分组并通知UI108路径。',
    0x6AF4D0: '只核重建分组并通知UI108路径。',
    0x6B8170: '条目构造只设置+4=-1，不清整槽。',
    0x757640: '只核普通/礼物视图消费、12行控件ID和显示字段；发件箱及setter未完整恢复。',
    0x759DD0: '只核根据输入与礼物计数选择按钮2/4并调自身虚表+120。',
    0x798580: 'signed两组计数之和>=100的容量查询；不扫原槽。',
    0x798740: '返回普通组计数owner+2728。',
    0x798770: '返回礼物组计数owner+2732。',
    0x7987A0: '返回普通组视图owner+1924地址。',
    0x7987C0: '返回礼物组视图owner+2324地址。',
    0x828F60: '只核本地case50通向843BC0的路径；其他分派分支仅保存原证。',
    0x843BC0: '只核请求/服务对象链入口；最终发包、线上编号和回执未闭合。',
    0x91FBB0: '只核正常cookie比较路径不改EAX；失败路径安全处理不作完整恢复。',
}
PARTIAL = {0x69DF50, 0x69E600, 0x6AEBE0, 0x6AEF10, 0x6AF1E0, 0x6AF490,
           0x6AF4D0, 0x757640, 0x759DD0, 0x828F60, 0x843BC0, 0x91FBB0}
UNKNOWN = {
    0x69DF50: '宿主其他成员与完整构造依赖未审阅；总槽数的后续初始化时序未闭合。',
    0x69E600: '其他成员析构依赖未审阅；外部是否在销毁后读取派生视图未知。',
    0x6A8C20: '最终线上包、服务端回执与失败处理未闭合。',
    0x6A8E00: '特殊编码官方含义、动态别名改上限、total>100可达性和线程时序未知。',
    0x6A9430: '分配失败的异常策略、外部视图失效管理与实际调用时序未闭合。',
    0x6AEBE0: '数据39生产方长度验证、满槽上游防护、6B20A0返回对象及Remove副作用未知。',
    0x6AEF10: '数据38生产方count/长度验证、刷新前清槽、字符串容量、线上布局与Remove间接副作用未知。',
    0x6AF1E0: '完整UI/提示链、数据输入来源和外部状态改变未恢复。',
    0x6AF490: '完整事件来源、UI通知外部依赖和线程时序未闭合。',
    0x6AF4D0: '完整事件来源、UI通知外部依赖和线程时序未闭合。',
    0x757640: '发件箱生产者、显示名查询、完整setter/鼠标事件和颜色官方语义未恢复。',
    0x759DD0: '完整事件输入与虚表+120后续页面状态未恢复。',
    0x798580: '调用者74C990/757370的容量防护逻辑未完整审阅。',
    0x828F60: 'case50之外的分支未审阅；编号50与线上opcode的关系未知。',
    0x843BC0: '构建对象的全生命周期、最终发包器、线上字段和回执链未闭合。',
    0x91FBB0: '失败路径安全处理只定位；不得把失败路径寄存器变化套用到正常返回。',
}


def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    start = pe+24+struct.unpack_from('<H', blob, pe+20)[0]
    sections = [struct.unpack_from('<IIII', blob, start+40*i+8)
                for i in range(struct.unpack_from('<H', blob, pe+6)[0])]
    checked, intervals = 0, []

    def check(row):
        nonlocal checked
        ea, size = int(row['va'], 16), row['size']
        actual = None
        for _, rva, raw_size, raw_start in sections:
            delta = ea-base-rva
            if 0 <= delta and delta+size <= raw_size:
                actual = blob[raw_start+delta:raw_start+delta+size].hex()
                break
        assert actual == row['disk_hex'] == row['idb_hex'] and row['matching'], row['va']
        intervals.append((ea, ea+size))
        checked += 1

    evidence = json.loads((HERE/'证据/functions.json').read_text(encoding='utf-8'))
    assert evidence['disk_sha256'] == sha
    entries, assembly = [], {}
    assert len(evidence['functions']) == len(REVIEW)
    for function in evidence['functions']:
        ea = int(function['va'], 16)
        assert ea in REVIEW and ea not in assembly
        assembly[ea] = '\n'.join(row['text'] for row in function['assembly'])
        for row in function['byte_ranges'] + function['chunk_byte_ranges']:
            check(row)
        assert function['bytes_match_disk']
        chunks = [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']]
        assert chunks == [(int(r['va'], 16), int(r['va'], 16)+r['size'])
                          for r in function['chunk_byte_ranges']]
        for row in function['byte_ranges']:
            at, end = int(row['va'], 16), int(row['va'], 16)+row['size']
            assert any(a <= at and end <= b for a, b in chunks)
        entries.append(dict(va=function['va'], status='局部路径已核' if ea in PARTIAL else '局部语义已审阅',
                            conclusion=REVIEW[ea], evidence='证据/functions.json',
                            unknown=UNKNOWN.get(ea, '未实机；外部调用者的完整业务链与线程时序未闭合。')))
    for thunk in evidence['thunks']:
        check(thunk)
        raw = bytes.fromhex(thunk['idb_hex'])
        assert raw[0] == 0xe9 and len(raw) == 5
        assert int(thunk['va'], 16)+5+int.from_bytes(raw[1:], 'little', signed=True) == int(thunk['target'], 16)

    data = json.loads((HERE/'证据/data.json').read_text(encoding='utf-8'))
    assert data['disk_sha256'] == sha
    for row in data['byte_ranges']:
        if row['disk_mapped']:
            check(row)
        else:
            assert row['disk_hex'] is None and row['matching'] is None
            ea, size = int(row['va'], 16), row['size']
            mapping = row['mapping']
            matching_section = next((s for s in sections if s[1] == int(mapping['section_rva'], 16)), None)
            assert matching_section is not None
            virtual_size, rva, raw_size, raw_start = matching_section
            delta = ea-base-rva
            assert raw_size <= delta and delta+size <= virtual_size
            assert mapping['classification'] == '仅虚拟区'
            assert (mapping['relative_offset'], mapping['raw_size'], mapping['raw_offset'], mapping['virtual_size']) == (delta, raw_size, raw_start, virtual_size)
    raw_data = {int(row['va'], 16): bytes.fromhex(row['idb_hex']) for row in data['byte_ranges']}
    assert raw_data[0xA80D1C] == b'\xff'*4
    assert struct.unpack('<IIiII', raw_data[0x6A9311]) == (1, 0x6A9319, -24, 9, 0x6A9325)
    refs = data['xrefs']['0xa80d1c']
    assert len(refs) == 3 and {r['function'] for r in refs} == {'0x6a8e00'}
    assert "mov     dword_A80D1C, 46h" in assembly[0x6A8E00]
    assert "var_18+3" in assembly[0x6A9270] and "31h" in assembly[0x6A9270]
    assert "var_14+1" in assembly[0x6A9270] and "32h" in assembly[0x6A9270]
    assert "pop     eax" in assembly[0x6A9270] and "mov     al, 1" in assembly[0x6A9270]
    assert '14Ch' in assembly[0x6A8E00] and '81B0h' in assembly[0x6A9430]
    assert collect() == json.loads((HERE/'证据/resources.json').read_text(encoding='utf-8'))
    docs = sorted(HERE.glob('*.txt'))
    required_docs = {'00阅读入口.txt', '01字段与生命周期.txt', '02分组规则与副作用.txt',
                     '03资源与界面消费.txt', '04更新布局与协作边界.txt'}
    assert required_docs <= {path.name for path in docs}
    for path in docs:
        lines = path.read_text(encoding='utf-8').splitlines()
        assert lines and all(not line.strip() or line.startswith('//') for line in lines), path.name
    cases = verify_boundaries()

    # 合并所有重叠区间，避免把指令、声明块和 RTC 重叠字节重复计为覆盖。
    merged = []
    for begin, end in sorted(intervals):
        if merged and begin <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([begin, end])
    review = dict(scope='邮件与礼物分组；25入口按各自局部范围审阅，不等同全部业务或全客户端恢复',
                  functions=entries)
    (HERE/'函数审阅清单.json').write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding='utf-8')
    result = dict(disk_sha256=sha, functions=len(entries),
                  statuses=dict(collections.Counter(e['status'] for e in entries)),
                  unique_e9_thunks=len(evidence['thunks']), byte_comparisons=checked,
                  merged_unique_bytes=sum(end-begin for begin, end in merged),
                  declared_chunks_covered=True, all_current_disk_bytes_match=True,
                  data_ranges=2, disk_mapped_data_ranges=1, virtual_only_data_ranges=1,
                  virtual_only_boundary='A80D1C的IDA基线FFFFFFFF不代表磁盘初值；此范围无原始文件字节可比。',
                  resources=2, required_document_files=len(required_docs),
                  document_files=len(docs), doc_format_passed=True,
                  model_boundary_cases=cases,
                  boundary='仅静态字节、资源和规则模型复核，不代表实机成功或线上协议闭合。')
    (HERE/'验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
