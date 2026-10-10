"""只读转录 PlusPrize.kpd；字段含义由后续汇编审阅决定。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def inspect():
    raw = (ROOT / 'Data/PlusPrize.kpd').read_bytes()
    assert len(raw) >= 9
    packed = bytes((value-raw[0]) & 255 for value in raw[1:])
    length, compressed_length = struct.unpack_from('<II', packed)
    assert compressed_length == len(packed)-8
    plain = lzokay.decompress(packed[8:], length)
    assert len(plain) == length
    lines, sections, entries, cursor, section_index = [], [], [], 0, -1
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        content = line.rstrip(b'\r\n')
        trimmed = content.strip(b' \t')
        lines.append(dict(number=number, offset=cursor, size=len(line), bytes=line.hex()))
        if trimmed.startswith(b'[') and trimmed.endswith(b']'):
            section_index += 1
            name = trimmed[1:-1]
            sections.append(dict(index=section_index, line=number, offset=cursor,
                                 name_hex=name.hex(), ascii=name.decode('ascii') if name.isascii() else None))
        elif b'=' in content:
            key, _, value = content.partition(b'=')
            normalized = key.strip(b' \t')
            row = dict(line=number, section_index=section_index, key_offset=cursor,
                       key_hex=key.hex(), key_ascii=normalized.decode('ascii') if normalized.isascii() else None,
                       value_offset=cursor+len(key)+1, value_hex=value.hex(),
                       leading_space_trimmed_value_hex=value.lstrip(b' \t').hex(), decoding_candidates={})
            for codec in ('cp950', 'gb18030'):
                try:
                    text = value.lstrip(b' \t').decode(codec)
                    row['decoding_candidates'][codec] = dict(text=text, roundtrip=text.encode(codec) == value.lstrip(b' \t'))
                except UnicodeError:
                    row['decoding_candidates'][codec] = dict(roundtrip=False)
            entries.append(row)
        cursor += len(line)
    assert cursor == len(plain)
    duplicates = {}
    for row in entries:
        duplicates.setdefault((row['section_index'], row['key_hex']), []).append(row['line'])
    result = dict(schema=1, path='Data/PlusPrize.kpd', scope='词法原字节；不声明运行编码、字段类型或奖励语义',
                  key=raw[0], source_size=len(raw), source_sha256=hashlib.sha256(raw).hexdigest(),
                  packed_size=len(packed), packed_sha256=hashlib.sha256(packed).hexdigest(),
                  compressed_size=compressed_length, compressed_sha256=hashlib.sha256(packed[8:]).hexdigest(),
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  lines=lines, sections=sections, entries=entries,
                  duplicate_keys=[dict(section_index=s, key_hex=k, lines=v) for (s, k), v in duplicates.items() if len(v)>1])
    (HERE / 'PlusPrize.kpd.decoded.bin').write_bytes(plain)
    (HERE / 'resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(source_size=len(raw), decoded_size=len(plain), sections=len(sections), entries=len(entries))


if __name__ == '__main__':
    print(json.dumps(inspect(), ensure_ascii=False))
