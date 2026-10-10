"""只读导出 TeachBoard 有限函数群与数据窗口；不修改 IDA 数据库。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x6DFD80, 0x6E0100, 0x6E01B0, 0x6E0210, 0x6E0250, 0x6E02B0, 0x6E03B0)
CONSUMERS = (0x798CE0, 0x798D80, 0x799F70, 0x768470)


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, SEEDS, str(HERE / 'functions_raw.json'))


def export_consumers(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, CONSUMERS, str(HERE / 'consumers_raw.json'))


def export_helpers(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, (0x6466C0, 0x6E0370, 0x6E0400, 0x6E0490,
                                         0x6E0A80, 0x6E0AF0, 0x6E0DC0, 0x79B020),
                                     str(HERE / 'helpers_raw.json'))


def export_line(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, (0x81A2E0,), str(HERE / 'line_raw.json'))


def export_closure(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, (0x646960, 0x6E0AC0, 0x6E0CE0, 0x6E0D10,
                                         0x79C850, 0x6E1290, 0x81A2E0),
                                     str(HERE / 'closure_raw.json'))


def export_constants(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, size):
        matching = [(rva, off) for _, rva, length, off in sections
                    if base + rva <= ea and ea + size <= base + rva + length]
        assert len(matching) <= 1, hex(ea)
        disk = None
        if matching:
            rva, off = matching[0]
            disk = image[off + ea - base - rva:off + ea - base - rva + size]
        raw = db.bytes.get_bytes_at(ea, size)
        virtual = [hex(base + rva) for virtual_size, rva, _, _ in sections
                   if base + rva <= ea and ea + size <= base + rva + virtual_size]
        return dict(va=hex(ea), size=size, idb_hex=raw.hex(),
                    disk_hex=disk.hex() if disk is not None else None, matching=disk == raw,
                    section_start_candidates=virtual,
                    storage='raw-backed' if disk is not None else '无磁盘原字节；按节区虚拟范围另核')

    constants = {}
    for name in ('functions_raw.json', 'consumers_raw.json'):
        for function in json.loads((HERE / name).read_text('utf-8'))['functions']:
            for instruction in function['assembly']:
                for edge in db.xrefs.from_ea(int(instruction['va'], 16)):
                    if 1 <= int(edge.type) < 16 and 0xA00000 <= edge.to_ea < 0xA66000:
                        constants[edge.to_ea] = identity(edge.to_ea, 128)
    result = dict(disk_sha256=hashlib.sha256(image).hexdigest(), constant_windows=list(constants.values()),
                  globals=[identity(0xA839A4, 32)],
                  boundary='数据窗口仅供地址与字符串核验，不凭相邻内存推断对象边界。')
    (HERE / 'constants_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    return dict(constants=len(constants), mismatches=[row['va'] for row in constants.values() if not row['matching']])
