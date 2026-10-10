"""只读导出实际字节写者、参数游标与格式状态表窗口。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    namespace = {'__file__': str(source)}
    exec(compile(source.read_text(encoding='utf-8'), str(source), 'exec'), namespace)
    result = namespace['export_group'](
        db, [0x934100, 0x9341D0, 0x934220, 0x9342B0, 0x9342D0, 0x934300],
        HERE / 'helpers_raw.json')
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + 40*i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    ranges = []
    for ea, size, role in ((0xA33F80, 128, '低半字节字符类别与高半字节状态迁移表采样'),
                           (0x933C88, 384, 'switch表窗口；相邻字节不自动归于同一表'),
                           (0xA69DA4, 32, '默认字符串及浮点回调指针窗口'),
                           (0xA69D74, 4, '字符分类表指针槽')):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base+rva <= ea and ea+size <= base+rva+raw]
        assert len(matches) == 1
        rva, off = matches[0]
        disk = blob[off+ea-base-rva:off+ea-base-rva+size]
        idb = db.bytes.get_bytes_at(ea, size)
        ranges.append(dict(va=hex(ea), size=size, role=role, idb_hex=idb.hex(),
                           disk_hex=disk.hex(), matching=idb == disk))
    (HERE / 'tables_raw.json').write_text(json.dumps(dict(
        disk_sha256=hashlib.sha256(blob).hexdigest(), ranges=ranges),
        ensure_ascii=False, indent=2), encoding='utf-8')
    result['table_matches'] = [r['matching'] for r in ranges]
    return result
