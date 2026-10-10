"""只读保留区域配置键窗口与 WinINet 导入槽；不发起网络请求。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    rows = []
    for ea, size in ((0xA2201C, 0xE4), (0xAD4004, 20)):
        match = [(rva, off) for _, rva, raw, off in sections
                 if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(match) == 1
        rva, off = match[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        idb = db.bytes.get_bytes_at(ea, size)
        if ea == 0xA2201C:
            assert idb == disk, hex(ea)
        rows.append(dict(va=hex(ea), size=size, idb_hex=idb.hex(),
                         disk_hex=disk.hex(), matching=idb == disk,
                         role='常量窗口' if ea == 0xA2201C else '导入槽观察；不得计为字节一致证据'))
    result = dict(disk_sha256=hashlib.sha256(image).hexdigest(), ranges=rows,
                  scope='常量采样窗口；相邻字节不自动归为同一结构或业务字段')
    (HERE / 'constants_raw.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(ranges=len(rows), matching=[r['matching'] for r in rows])
