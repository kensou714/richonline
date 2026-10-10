"""在 IDA-MCP 中只读重放本专题原证，不修改数据库。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/整数键树容器契约')
GROUPS = {
    'entries': [0x8BC3A0, 0x8BC6C0, 0x8BE000, 0x8C0F70],
    'direct_dependencies': [0x8BC4E0, 0x8BC5B0, 0x8BD380, 0x8BD580, 0x8BD5E0,
        0x8BDDA0, 0x8C0030, 0x8C0080, 0x8C0390, 0x8C0510, 0x8C0550, 0x8C05D0,
        0x8C3FA0, 0x91F6D0, 0x91F700, 0x9295F0],
    'tree_helpers': [0x8BC550, 0x8BDEE0, 0x8BDF40, 0x8BDFA0, 0x8BFFD0,
        0x8C0590, 0x8C0610, 0x8C06C0, 0x8C0700, 0x8C09C0, 0x8C0F70,
        0x8C1050, 0x8C3610, 0x8C3730, 0x8C3780, 0x8C3D50, 0x8C3D90,
        0x8C3DF0, 0x8C4000, 0x8C41B0, 0x8C5410],
    'callers_and_node': [0x8BA950, 0x8BB700, 0x8BBFA0, 0x8BC040, 0x8C59D0,
        0x8C5A40, 0x8C6AD0, 0x8C6DD0],
    'lifecycle': [0x697780, 0x8BB180, 0x8BCD30, 0x8C1090, 0x8C6F50, 0x8C8F90],
    'head_and_clear': [0x8BC610, 0x8BDE10, 0x8C6FC0, 0x8C7040, 0x8C7080,
        0x8C7140, 0x8C71C0, 0x8C7200, 0x8C7420, 0x8C7480, 0x8C7570,
        0x8C7610, 0x8C76C0, 0x8C8FE0, 0x8C9030, 0x8C9150],
    'reader_and_cleanup': [0x8BA830, 0x8BAF70, 0x8C10F0, 0x8C6D10,
        0x8C7500, 0x8C7640, 0x8CC740],
}


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    results = {name: namespace['export_group'](db, addresses, HERE / '证据' / (name + '.json'))
               for name, addresses in GROUPS.items()}
    disk = (HERE.parents[3] / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    opt = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + opt + 40 * i + 8)
                for i in range(count)]
    windows = []
    for lo, hi in [(0xA1E390, 0xA1E3DA), (0xA20640, 0xA2067C)]:
        saved, actual = db.bytes.get_bytes_at(lo, hi - lo), None
        for _, rva, size, offset in sections:
            relative = lo - base - rva
            if 0 <= relative and relative + hi - lo <= size:
                actual = disk[offset + relative:offset + relative + hi - lo]
                break
        windows.append(dict(va=hex(lo), size=hi-lo, idb_hex=saved.hex(),
            disk_hex=actual.hex() if actual is not None else None, matching=saved == actual,
            scope='原始观察窗口，不计入已审阅声明函数',
            assembly=[dict(va=hex(i.ea), text=db.instructions.get_disassembly(i))
                      for i in db.instructions.get_between(lo, hi)]))
    (HERE / '证据' / 'startup_windows.json').write_text(json.dumps(dict(
        disk_sha256=hashlib.sha256(disk).hexdigest(), windows=windows),
        ensure_ascii=False, indent=2), encoding='utf-8')
    results['startup_windows'] = dict(windows=len(windows),
        mismatches=[w['va'] for w in windows if not w['matching']])
    return results
