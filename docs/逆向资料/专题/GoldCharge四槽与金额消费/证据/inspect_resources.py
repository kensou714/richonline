"""只读转录当前 GoldCharge 包；原字节与词法，不替客户端解析器赋语义。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def inspect():
    raw = (ROOT / 'Data/GoldCharge.kpd').read_bytes()
    packed = bytes((value - raw[0]) & 255 for value in raw[1:])
    length, compressed_length = struct.unpack_from('<II', packed)
    assert compressed_length == len(packed) - 8
    plain = lzokay.decompress(packed[8:], length)
    assert len(plain) == length
    lines, sections, entries, cursor, section_index = [], [], [], 0, -1
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        content = line.rstrip(b'\r\n')
        trimmed = content.strip(b' \t')
        lines.append(dict(number=number, offset=cursor, size=len(line), bytes=line.hex()))
        if trimmed.startswith(b'[') and trimmed.endswith(b']'):
            section_index += 1
            sections.append(dict(index=section_index, line=number, offset=cursor,
                                 name_hex=trimmed[1:-1].hex(), name_ascii=trimmed[1:-1].decode('ascii')))
        elif b'=' in content and not trimmed.startswith(b'//'):
            key, _, value = content.partition(b'=')
            normalized = key.strip(b' \t')
            entries.append(dict(section_index=section_index, line=number, key_offset=cursor,
                                key_hex=key.hex(), key_ascii=normalized.decode('ascii'),
                                value_offset=cursor + len(key) + 1, value_hex=value.hex(),
                                normalized_ascii=value.strip(b' \t').decode('ascii')))
        cursor += len(line)
    assert cursor == len(plain)
    decoding = {}
    for codec in ('gbk', 'cp950'):
        try:
            value = plain.decode(codec)
            decoding[codec] = dict(roundtrip=value.encode(codec) == plain, text=value)
        except UnicodeError:
            decoding[codec] = dict(roundtrip=False)
    result = dict(schema='richonline-resource-lexical-1', path='Data/GoldCharge.kpd', key=raw[0],
                  source_size=len(raw), source_sha256=hashlib.sha256(raw).hexdigest(),
                  packed_size=len(packed), compressed_size=compressed_length,
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  decoding_candidates=decoding, lines=lines, sections=sections, entries=entries,
                  scope='当前磁盘包词法原证；候选编码往返不证明运行时编码或全局容量')
    (HERE / 'resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (HERE / 'GoldCharge.kpd.decoded.bin').write_bytes(plain)
    text = decoding['gbk']['text']
    (HERE / 'GoldCharge_kpd_只读转录.txt').write_text(''.join('// ' + line + '\n' for line in text.splitlines()), encoding='utf-8')
    return dict(source_size=len(raw), decoded_size=len(plain), sections=len(sections), entries=len(entries))


if __name__ == '__main__':
    print(json.dumps(inspect(), ensure_ascii=True))
