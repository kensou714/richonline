"""只读补证：构造函数赋值的虚表、+10 槽桥和实际消费者。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional_size + 40 * i + 8)
                for i in range(count)]

    def identity(ea, size):
        original = db.bytes.get_bytes_at(ea, size)
        disk = None
        for _, rva, raw_size, raw_offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= raw_size:
                disk = blob[raw_offset + relative:raw_offset + relative + size]
                break
        return dict(va=hex(ea), size=size, idb_hex=original.hex(),
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=original == disk)

    table = identity(0xA27120, 24)
    slots = list(struct.unpack('<6I', bytes.fromhex(table['idb_hex'])))
    target, bridges = slots[4], []
    while target not in [int(row['va'], 16) for row in bridges]:
        raw = db.bytes.get_bytes_at(target, 5)
        if raw[0] != 0xE9:
            break
        row = identity(target, 5)
        target += 5 + struct.unpack('<i', raw[1:])[0]
        row['target'] = hex(target)
        bridges.append(row)
    assert target == 0x73A590, hex(target)
    shared = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))
    summary = shared['export_group'](db, [target], str(HERE / 'actual_consumer_raw.json'))
    output = dict(disk_sha256=hashlib.sha256(blob).hexdigest(),
                  scope='6FC035 明确赋值的虚表前六槽；仅 +10 槽沿 E9 进入实际消费者',
                  constructor_site='0x6fc035', table=table,
                  slots=[dict(offset=hex(i * 4), target=hex(ea)) for i, ea in enumerate(slots)],
                  selected_offset='0x10', bridges=bridges, implementation=hex(target))
    (HERE / 'actual_consumer_vtable.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(summary, table_match=table['matching'],
                bridge_mismatches=[r['va'] for r in bridges if not r['matching']])
