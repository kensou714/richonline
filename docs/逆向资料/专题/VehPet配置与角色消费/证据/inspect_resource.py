"""只读解包VehPet，保存词法原字节；不替代游戏配置解析器。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def inspect():
    source = (ROOT / 'Data/VehPet.kpd').read_bytes()
    assert len(source) >= 9
    packed = bytes((value - source[0]) & 255 for value in source[1:])
    decoded_size, compressed_size = struct.unpack_from('<II', packed)
    assert 0 < decoded_size <= 16 * 1024 * 1024
    assert compressed_size == len(packed) - 8
    plain = lzokay.decompress(packed[8:], decoded_size)
    assert len(plain) == decoded_size
    lines, entries, sections = [], [], []
    cursor, section, section_index = 0, None, -1
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        content = line.rstrip(b'\r\n')
        lines.append(dict(number=number, offset=cursor, size=len(line), hex=line.hex()))
        trimmed = content.strip(b' \t')
        if trimmed.startswith(b'[') and trimmed.endswith(b']'):
            section = trimmed[1:-1]
            section_index += 1
            sections.append(dict(index=section_index, line=number, offset=cursor,
                                 hex=section.hex(), ascii=section.decode('ascii') if section.isascii() else None))
        elif b'=' in content:
            key, _, value = content.partition(b'=')
            clean_key, clean_value = key.strip(b' \t'), value.strip(b' \t')
            item = dict(line=number, line_offset=cursor, section_index=section_index,
                        section_hex=section.hex() if section else None, key_hex=key.hex(),
                        key_ascii=clean_key.decode('ascii') if clean_key.isascii() else None,
                        value_offset=cursor + len(key) + 1, value_hex=value.hex(), decoding_candidates={})
            for codec in ('cp950', 'gb18030'):
                try:
                    text = value.lstrip(b' \t').decode(codec)
                    item['decoding_candidates'][codec] = dict(text=text, roundtrip=text.encode(codec) == value.lstrip(b' \t'))
                except UnicodeError:
                    item['decoding_candidates'][codec] = dict(roundtrip=False)
            if re.fullmatch(rb'[+-]?[0-9]+', clean_value):
                item['decimal_literal'] = int(clean_value)
            entries.append(item)
        cursor += len(line)
    assert cursor == len(plain)
    groups = {}
    for item in entries:
        groups.setdefault((item['section_index'], item['key_hex']), []).append(item['line'])
    result = dict(scope='仅词法转录；字段业务与运行时规则须由汇编证明', path='Data/VehPet.kpd',
                  source_size=len(source), source_sha256=hashlib.sha256(source).hexdigest(), key=source[0],
                  packed_size=len(packed), packed_sha256=hashlib.sha256(packed).hexdigest(),
                  compressed_size=compressed_size, compressed_sha256=hashlib.sha256(packed[8:]).hexdigest(),
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  decoded_hex=plain.hex(), sections=sections, entries=entries, lines=lines,
                  duplicate_keys=[dict(section_index=s, key_hex=k, lines=v)
                                  for (s, k), v in groups.items() if len(v) > 1])
    (HERE / 'resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(source_size=len(source), decoded_size=len(plain), sections=len(sections), entries=len(entries))


if __name__ == '__main__':
    print(json.dumps(inspect(), ensure_ascii=True))
