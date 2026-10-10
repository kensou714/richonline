"""补足默认窄/宽字符串的完整NUL窗口及入口桥，不导出额外函数。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + 40*i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    rows = []
    for ea, size in ((0xA33FEC, 24), (0x60361E, 5)):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base+rva <= ea and ea+size <= base+rva+raw]
        assert len(matches) == 1
        rva, off = matches[0]
        disk = blob[off+ea-base-rva:off+ea-base-rva+size]
        idb = db.bytes.get_bytes_at(ea, size)
        rows.append(dict(va=hex(ea), size=size, idb_hex=idb.hex(), disk_hex=disk.hex(),
                         matching=idb == disk))
    (HERE / 'labels_raw.json').write_text(json.dumps(dict(
        disk_sha256=hashlib.sha256(blob).hexdigest(), ranges=rows),
        ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(ranges=len(rows), matching=[r['matching'] for r in rows])
