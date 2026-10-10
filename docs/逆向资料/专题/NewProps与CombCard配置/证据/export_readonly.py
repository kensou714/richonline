"""主代理串行执行的有限只读导出；定义入口不会自动访问或修改IDA。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/NewProps与CombCard配置/证据'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = (0x8009A0, 0x8012A0, 0x800BF0, 0x8015B0)


def export(db):
    assert hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, SEEDS, str(HERE / 'functions_raw.json'))


def export_constants(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    functions = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    assert functions['disk_sha256'] == EXPECTED_SHA
    assert {int(row['va'], 16) for row in functions['functions']} == set(SEEDS)
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, requested):
        candidates = [(rva, off, length) for _, rva, length, off in sections
                      if base + rva <= ea < base + rva + length]
        assert len(candidates) == 1, hex(ea)
        rva, off, length = candidates[0]
        size = min(requested, base + rva + length - ea)
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        raw = db.bytes.get_bytes_at(ea, size)
        assert raw is not None and len(raw) == size
        return dict(va=hex(ea), size=size, idb_hex=raw.hex(), disk_hex=disk.hex(), matching=raw == disk)

    constants = {}
    for function in functions['functions']:
        for instruction in function['assembly']:
            for edge in db.xrefs.from_ea(int(instruction['va'], 16)):
                if 1 <= int(edge.type) < 16 and 0xA00000 <= edge.to_ea < 0xA66000:
                    constants[edge.to_ea] = identity(edge.to_ea, 128)
    result = dict(disk_sha256=EXPECTED_SHA, constant_windows=list(constants.values()),
                  boundary='数据窗口供字符串与原字节核验，不把相邻数据或自动符号当字段定义。')
    (HERE / 'constants_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    return dict(constants=len(constants), mismatches=[row['va'] for row in constants.values() if not row['matching']])
