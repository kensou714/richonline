"""只读保存 defaultBuild 使用的十项指针表及 ASCII token。"""
from pathlib import Path
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'
TABLE = 0xA676DC


def export(db):
    raw = db.bytes.get_bytes_at(TABLE, 40)
    if raw is None or len(raw) != 40:
        raise ValueError('token 表无法读取')
    records = []
    for index, (address,) in enumerate(struct.iter_unpack('<I', raw)):
        data = bytearray()
        for offset in range(64):
            char = db.bytes.get_bytes_at(address + offset, 1)
            if char is None:
                raise ValueError('token 字符串无法读取：' + hex(address))
            data.extend(char)
            if char == b'\0':
                break
        else:
            raise ValueError('token 未在 64 字节内终止：' + hex(address))
        records.append(dict(index=index, result=index + 11, va=hex(address),
                            raw_hex=data.hex(), token=data[:-1].decode('ascii')))
    result = dict(table_va=hex(TABLE), table_hex=raw.hex(), records=records)
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'build_tokens.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result
