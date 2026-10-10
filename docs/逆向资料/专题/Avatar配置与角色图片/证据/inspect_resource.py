"""只读转录Avatar资源；容器探针和词法转录均不代替游戏格式语义。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
LIMIT = 16 * 1024 * 1024


def lexical(plain):
    lines, sections, entries = [], [], []
    cursor, section, section_index = 0, None, -1
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        content = line.rstrip(b'\r\n')
        lines.append(dict(number=number, offset=cursor, size=len(line), hex=line.hex()))
        trimmed = content.strip(b' \t')
        if trimmed.startswith(b'[') and trimmed.endswith(b']'):
            section, section_index = trimmed[1:-1], section_index + 1
            sections.append(dict(index=section_index, line=number, offset=cursor,
                                 hex=section.hex(), ascii=section.decode('ascii') if section.isascii() else None))
        elif b'=' in content:
            key, _, value = content.partition(b'=')
            clean_key, clean_value = key.strip(b' \t'), value.strip(b' \t')
            item = dict(line=number, line_offset=cursor, section_index=section_index,
                        section_hex=section.hex() if section is not None else None,
                        key_hex=key.hex(), key_ascii=clean_key.decode('ascii') if clean_key.isascii() else None,
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
    return dict(decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                decoded_hex=plain.hex(), lines=lines, sections=sections, entries=entries,
                duplicate_keys=[dict(section_index=s, key_hex=k, lines=v)
                                for (s, k), v in groups.items() if len(v) > 1])


def inspect():
    folder = ROOT / 'Avatar'
    paths = sorted(path for path in folder.iterdir() if path.is_file() and path.suffix.lower() in ('.avt', '.kpd'))
    assert folder / 'AvatList.kpd' in paths
    records = []
    for path in paths:
        assert path.stat().st_size <= LIMIT
        source = path.read_bytes()
        row = dict(path=path.relative_to(ROOT).as_posix(), source_size=len(source),
                   source_sha256=hashlib.sha256(source).hexdigest(), source_hex=source.hex(),
                   scope='原文件转录；扩展名不证明包装或业务类型')
        try:
            if len(source) < 9:
                raise ValueError('不足包装头长度')
            packed = bytes((value - source[0]) & 255 for value in source[1:])
            decoded_size, compressed_size = struct.unpack_from('<II', packed)
            if not 0 < decoded_size <= LIMIT or compressed_size != len(packed) - 8:
                raise ValueError('减法包装长度门未通过')
            plain = lzokay.decompress(packed[8:], decoded_size)
            assert len(plain) == decoded_size
            row.update(container_probe='减法包装与LZO长度门通过；游戏消费待指令证明', key=source[0],
                       packed_size=len(packed), packed_sha256=hashlib.sha256(packed).hexdigest(),
                       compressed_size=compressed_size, compressed_sha256=hashlib.sha256(packed[8:]).hexdigest(),
                       lexical=lexical(plain))
        except (ValueError, AssertionError, lzokay.LzokayError) as exc:
            row.update(container_probe='探针未通过，保留原字节，不推断其他格式', probe_error=str(exc))
        records.append(row)
    result = dict(schema=1, scope='目录快照、原字节、有限容器探针和词法转录；ACP与字段语义未证', files=records)
    (HERE / 'resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(files=len(records), decoded=sum('lexical' in row for row in records))


if __name__ == '__main__':
    print(json.dumps(inspect(), ensure_ascii=True))
