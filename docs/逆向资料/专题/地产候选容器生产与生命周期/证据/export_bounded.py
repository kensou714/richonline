"""第二十七批地产候选容器；只由主代理串行调用 export，加载不访问 IDA。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
LEGACY_SOURCE = '专题/地图与路径/证据/map_runtime_core.json'
LEGACY_REUSE = ((5, 0x7ECDB0, 95), (4, 0x7ECE30, 216),
                (8, 0x63F540, 90), (9, 0x692030, 114))
CONFIG = dict(
    topic='地产候选容器生产与生命周期',
    seeds=(0x7ECD50, 0x7ECD80),
    owner_sites=(0x7DE375, 0xA153F7, 0x7DED59, 0xA1541D,
                 0x7DF54F, 0x7DF9BC, 0x7DF9D4, 0x7DFBF8,
                 0x7DFC4E, 0x7DFC7C, 0x7DFC91, 0x7DFCC7),
    data_windows=(),
    reuse_navigation=(LEGACY_SOURCE,
        '专题/地图地产候选筛选/证据/bounded_raw.json',
        '专题/TeachMode序号生产与根对象/证据/load_source_raw.json',
        '专题/动态物件同步与触发/证据/dynamic_support.json'),
)


def audit_legacy(core):
    """旧中文已完整导出的四体只复核字节；不重新导出反编译或扩张函数集。"""
    import ida_bytes

    source_bytes = (DOCS / LEGACY_SOURCE).read_bytes()
    source = json.loads(source_bytes)
    assert source['磁盘SHA256'].lower() == core['EXPECTED_SHA']
    disk = (core['ROOT'] / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(disk).hexdigest() == core['EXPECTED_SHA']
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<4I', disk, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', disk, pe + 6)[0])]
    results = []
    for index, va, size in LEGACY_REUSE:
        function = source['函数'][index]
        assert int(function['地址'], 16) == va and function['大小'] == size
        assert function['状态'] == '已逐函数分析'
        rows = []
        cursor = va
        for instruction_index, row in enumerate(function['完整汇编']):
            ea = int(row['地址'], 16)
            old = row['字节核验']
            raw = bytes.fromhex(old['IDB字节'])
            assert old['匹配'] is True and raw == bytes.fromhex(old['磁盘字节'])
            assert va <= ea < ea + len(raw) <= va + size
            assert ea == cursor, ('固定四旧体应为单一连续主块，不可丢尾块或跨洞', hex(ea))
            cursor += len(raw)
            matches = [(rva, off) for _, rva, length, off in sections
                       if 0 <= ea - base - rva and ea - base - rva + len(raw) <= length]
            assert len(matches) == 1
            rva, off = matches[0]
            at = off + ea - base - rva
            current = ida_bytes.get_bytes(ea, len(raw))
            assert current == raw == disk[at:at + len(raw)], hex(ea)
            rows.append(dict(site_va=hex(ea), size=len(raw), text=row['汇编'],
                             source_pointer=f'/函数/{index}/完整汇编/{instruction_index}',
                             current_idb_hex=current.hex(), current_disk_hex=disk[at:at + len(raw)].hex(),
                             matching=True,
                             sha256=hashlib.sha256(raw).hexdigest()))
        assert sum(row['size'] for row in rows) == size
        results.append(dict(seed_va=hex(va), source_path=LEGACY_SOURCE,
            source_pointer=f'/函数/{index}',
            source_sha256=hashlib.sha256(source_bytes).hexdigest(),
            main_size=size, audited_instruction_bytes=sum(row['size'] for row in rows),
            range_scope='本四旧体均为连续主块；不将主大小推广为含尾块的通用大小',
            original_status=function['状态'], instruction_audits=rows,
            pending_status='旧中文完整原证当前逐指令补核；不是新增导出或新增审阅'))
    return results


def export():
    output = HERE / 'bounded_raw.json'
    assert not output.exists(), '禁止覆盖既有原证'
    core = runpy.run_path(str(CORE))
    legacy = audit_legacy(core)
    report = core['export'](CONFIG, HERE)
    result = json.loads(output.read_text(encoding='utf-8'))
    wrapper_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['legacy_reused_byte_audits'] = legacy
    result['prepared_wrapper_sha256'] = wrapper_sha
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(report, legacy_reused_byte_audit_count=len(legacy),
                prepared_wrapper_sha256=wrapper_sha)
