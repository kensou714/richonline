"""只读独立解包 Rank 样本；保留完整字节与重复段，不模拟客户端解析。"""
import hashlib
import json
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent


def main():
    import lzokay

    path = ROOT / 'Data/Rank.kpd'
    blob = path.read_bytes()
    if len(blob) < 9:
        raise ValueError('KPD 头不足')
    key = blob[0]
    size, packed = struct.unpack('<II', bytes((value - key) & 255 for value in blob[1:9]))
    if not 0 < size <= 16 * 1024 * 1024 or not 0 < packed <= len(blob) - 9:
        raise ValueError('KPD 长度不符合现有格式')
    plain = lzokay.decompress(bytes((value - key) & 255 for value in blob[9:9 + packed]), size)
    if len(plain) != size:
        raise ValueError('解包长度不符')
    rows, segments, offset, current = [], [], 0, None
    for index, raw in enumerate(plain.splitlines(keepends=True), 1):
        content = raw.rstrip(b'\r\n')
        row = dict(line=index, offset=offset, size=len(raw), raw_hex=raw.hex(),
                   content_hex=content.hex(), ascii_text=content.decode('ascii') if content.isascii() else None)
        for encoding in ('big5', 'gbk'):
            try:
                row[encoding + '_reading_candidate'] = content.decode(encoding, errors='strict')
            except UnicodeDecodeError:
                row[encoding + '_reading_candidate'] = None
        rows.append(row)
        match = re.fullmatch(rb'\s*\[([^\]\r\n]+)\]\s*', content)
        if match:
            current = dict(name_hex=match[1].hex(), name_ascii=match[1].decode('ascii')
                           if match[1].isascii() else None, header_line=index,
                           header_offset=offset, fields=[])
            segments.append(current)
        elif current is not None and b'=' in content:
            field, value = content.split(b'=', 1)
            current['fields'].append(dict(line=index, offset=offset, key_hex=field.hex(),
                                           key_ascii=field.decode('ascii') if field.isascii() else None,
                                           value_hex=value.hex(), value_size=len(value)))
        offset += len(raw)
    result = dict(source='Data/Rank.kpd', source_size=len(blob), source_sha256=hashlib.sha256(blob).hexdigest(),
                  key=key, packed_size=packed, tail_size=len(blob) - 9 - packed,
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  decoded_hex=plain.hex(), rows=rows, segments=segments,
                  boundary='段与等号识别仅为样本索引，不证明客户端语法、结束规则或代码页')
    (HERE / 'Rank.kpd.decoded.bin').write_bytes(plain)
    (HERE / 'rank_resource_raw.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(source_size=len(blob), decoded_size=len(plain), rows=len(rows), segments=len(segments))


if __name__ == '__main__':
    print(json.dumps(main(), ensure_ascii=False))
