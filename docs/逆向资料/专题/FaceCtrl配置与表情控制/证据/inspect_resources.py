"""只读解包 FaceCtrl.kpd，保存原始字段字节及编码候选，不改动原资源。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def inspect():
    raw = (ROOT / 'Data/FaceCtrl.kpd').read_bytes()
    assert len(raw) >= 9
    packed = bytes((value - raw[0]) & 255 for value in raw[1:])
    decoded_size, compressed_size = struct.unpack_from('<II', packed)
    assert compressed_size == len(packed) - 8, '包长度与头字段不一致'
    plain = lzokay.decompress(packed[8:], decoded_size)
    assert len(plain) == decoded_size
    lines, entries, sections = [], [], []
    cursor, section, section_index = 0, None, -1
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        content = line.rstrip(b'\r\n')
        lines.append(dict(number=number, offset=cursor, size=len(line), bytes=line.hex()))
        trimmed = content.strip(b' \t')
        if trimmed.startswith(b'[') and trimmed.endswith(b']'):
            section = trimmed[1:-1]
            section_index += 1
            sections.append(dict(index=section_index, line=number, offset=cursor, bytes=section.hex(),
                                 ascii=section.decode('ascii') if section.isascii() else None))
        elif b'=' in content:
            key, _, value = content.partition(b'=')
            key_clean, value_clean = key.strip(b' \t'), value.strip(b' \t')
            row = dict(line=number, line_offset=cursor, section_index=section_index,
                       section_hex=section.hex() if section is not None else None,
                       key_offset=cursor, key_hex=key.hex(), value_offset=cursor + len(key) + 1,
                       value_hex=value.hex(), key_ascii=key_clean.decode('ascii') if key_clean.isascii() else None)
            row['leading_space_trimmed_value_hex'] = value.lstrip(b' \t').hex()
            row['decoding_candidates'] = {}
            for codec in ('cp950', 'gb18030'):
                try:
                    text = value.lstrip(b' \t').decode(codec)
                    row['decoding_candidates'][codec] = dict(text=text, roundtrip=text.encode(codec) == value.lstrip(b' \t'))
                except UnicodeError:
                    row['decoding_candidates'][codec] = dict(roundtrip=False)
            if re.fullmatch(rb'[+-]?[0-9]+', value_clean):
                row['decimal_literal'] = int(value_clean)
            entries.append(row)
        cursor += len(line)
    assert cursor == len(plain)
    groups = {}
    for row in entries:
        group = (row['section_index'], row['key_hex'])
        groups.setdefault(group, []).append(row['line'])
    result = dict(schema=1, scope='词法字节记录；字段含义以加载与消费者汇编为准',
                  path='Data/FaceCtrl.kpd', source_size=len(raw), source_sha256=hashlib.sha256(raw).hexdigest(),
                  key=raw[0], packed_size=len(packed), packed_sha256=hashlib.sha256(packed).hexdigest(),
                  compressed_size=compressed_size, compressed_sha256=hashlib.sha256(packed[8:]).hexdigest(),
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  sections=sections, entries=entries, lines=lines,
                  duplicate_keys=[dict(section_index=s, key_hex=k, lines=v) for (s, k), v in groups.items() if len(v) > 1])
    (HERE / 'FaceCtrl.kpd.decoded.bin').write_bytes(plain)
    (HERE / 'resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(source_size=len(raw), decoded_size=len(plain), sections=len(sections), entries=len(entries))


if __name__ == '__main__':
    print(json.dumps(inspect(), ensure_ascii=False))
