"""只读回读16.0与两条跳板；仅记录pow运行时开关地址，不采集开关初值。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/界面数值与颜色解析契约/证据'


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe+6)[0]
    optional = struct.unpack_from('<H', blob, pe+20)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8) for i in range(count)]
    ranges = []
    for ea, size, meaning in [(0xA305A0, 8, '颜色指数的底数16.0'),
                              (0x60F464, 5, 'CIpow的pentium4分派跳板'),
                              (0x610B6B, 5, '四态颜色setter跳板')]:
        for virtual, rva, raw_size, offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= raw_size:
                disk = blob[offset+relative:offset+relative+size]
                actual = db.bytes.get_bytes_at(ea, size)
                assert actual == disk
                row = dict(va=hex(ea), size=size, disk_hex=disk.hex(), idb_hex=actual.hex(),
                           matching=True, meaning=meaning)
                if disk[0] == 0xE9 and size == 5:
                    row['target'] = hex(ea+5+int.from_bytes(disk[1:], 'little', signed=True))
                ranges.append(row)
                break
        else:
            raise ValueError(hex(ea))
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), ranges=ranges,
                  runtime_flag=dict(va='0xad0e80', scope='只记录分派使用的地址，不把运行时值当常量'))
    (HERE / 'color_data.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(ranges=len(ranges))
