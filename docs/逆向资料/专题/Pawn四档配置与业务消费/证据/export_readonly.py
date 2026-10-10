"""只读导出 Pawn 加载与消费者；复用完整原证，不修改 IDA 数据库。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x7F1D70, 0x7BA0B0, 0x7F26E0, 0x75CE30)
REUSED = (
    ('TeachMode对象与消费者/证据/teachmode_raw.json', (0x628C10, 0x623EE0, 0x64F200)),
    ('角色1416字段来源/证据/functions.json', (0x75E6F0, 0x63E1A0, 0x63EDD0)),
    ('随机地图候选与配置索引/证据/functions_raw.json', (0x629DD0, 0x629DF0, 0x629E10)),
)


def refresh_reused():
    reused = []
    provenance = []
    for relative, addresses in REUSED:
        source = ROOT / 'docs/逆向资料/专题' / relative
        blob = source.read_bytes()
        selected = [function for function in json.loads(blob)['functions']
                    if int(function['va'], 16) in addresses]
        assert len(selected) == len(addresses)
        reused.extend(selected)
        provenance.append(dict(source=str(source.relative_to(ROOT)),
                               source_sha256=hashlib.sha256(blob).hexdigest(),
                               functions=[hex(address) for address in addresses]))
    (HERE / 'reused_raw.json').write_text(json.dumps(dict(functions=reused, provenance=provenance),
                                                     ensure_ascii=False, indent=2), 'utf-8')
    return len(reused)


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    result = namespace['export_group'](db, SEEDS, str(HERE / 'functions_raw.json'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, size):
        disk = None
        for _, rva, length, offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= length:
                disk = image[offset + relative:offset + relative + size]
                break
        raw = db.bytes.get_bytes_at(ea, size)
        return dict(va=hex(ea), size=size, idb_hex=raw.hex(),
                    disk_hex=disk.hex() if disk is not None else None, matching=disk == raw)

    bridges = []
    for ea, target in ((0x60104E, 0x628C10), (0x60264C, 0x7F1D70), (0x610981, 0x7F26E0)):
        row = identity(ea, 5)
        raw = bytes.fromhex(row['idb_hex'])
        assert raw[0] == 0xE9 and ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target
        row['target'] = hex(target)
        bridges.append(row)
    data = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    constants = {}
    for function in data['functions']:
        for instruction in function['assembly']:
            for edge in db.xrefs.from_ea(int(instruction['va'], 16)):
                if 1 <= int(edge.type) < 16 and 0xA00000 <= edge.to_ea < 0xA70000:
                    constants[edge.to_ea] = identity(edge.to_ea, 128)
    reused_count = refresh_reused()
    (HERE / 'bridges_constants_raw.json').write_text(json.dumps(
        dict(disk_sha256=hashlib.sha256(image).hexdigest(), bridges=bridges,
             constant_windows=list(constants.values()),
             singleton_storage=dict(va='0xa76700', size=4, storage='raw-backed .data',
                                    disk_hex=identity(0xA76700, 4)['disk_hex'],
                                    initialization='磁盘初值00000000；复用getter汇编核实懒分配')),
        ensure_ascii=False, indent=2), 'utf-8')
    return dict(functions=result, reused=reused_count, bridges=len(bridges), constant_windows=len(constants))


def export_helpers(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, (0x7F2630, 0x7F2790, 0x7B9EF0,
                                         0x7B9F80, 0x7B9FD0, 0x7BA020),
                                     str(HERE / 'helpers_raw.json'))


def export_tables(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    windows = []
    for site in (0x7F265D, 0x7F270D, 0x7F27EE):
        candidates = [edge.to_ea for edge in db.xrefs.from_ea(site) if 1 <= int(edge.type) < 16]
        assert len(candidates) == 1, (hex(site), candidates)
        ea = candidates[0]
        raw = db.bytes.get_bytes_at(ea, 16)
        mapped = [(rva, offset) for _, rva, length, offset in sections
                  if base + rva <= ea and ea + 16 <= base + rva + length]
        assert len(mapped) == 1
        rva, offset = mapped[0]
        disk = image[offset + ea - base - rva:offset + ea - base - rva + 16]
        windows.append(dict(site=hex(site), va=hex(ea), size=16, idb_hex=raw.hex(),
                            disk_hex=disk.hex(), matching=raw == disk,
                            targets=[hex(value) for value in struct.unpack('<4I', raw)]))
    (HERE / 'jump_tables_raw.json').write_text(json.dumps(windows, ensure_ascii=False, indent=2), 'utf-8')
    return dict(tables=len(windows), mismatches=[row['va'] for row in windows if not row['matching']])
