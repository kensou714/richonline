"""Rank 资源独立复算；词法索引不代替客户端解析语义。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
resource_path = ROOT / 'Data/Rank.kpd'
source = resource_path.read_bytes()
assert len(source) >= 9
decoded_header = bytes((value - source[0]) % 256 for value in source[1:9])
output_size, compressed_size = struct.unpack('<II', decoded_header)
assert 0 < output_size <= 16 * 1024 * 1024
assert 0 < compressed_size <= len(source) - 9
compressed = bytes((value - source[0]) % 256 for value in source[9:9 + compressed_size])
decoded = lzokay.decompress(compressed, output_size)
assert len(decoded) == output_size
rows, sections = [], []
cursor = 0
for line, raw in enumerate(decoded.splitlines(keepends=True), 1):
    content = raw.rstrip(b'\r\n')
    row = {'line': line, 'offset': cursor, 'size': len(raw), 'raw_hex': raw.hex(),
           'content_hex': content.hex()}
    rows.append(row)
    header = re.fullmatch(rb'\s*\[([^\]\r\n]+)\]\s*', content)
    if header:
        sections.append({'name_hex': header[1].hex(), 'header_line': line,
                         'header_offset': cursor, 'fields': []})
    elif sections and b'=' in content:
        key, value = content.split(b'=', 1)
        sections[-1]['fields'].append({'line': line, 'offset': cursor,
                                      'key_hex': key.hex(), 'value_hex': value.hex()})
    cursor += len(raw)
assert cursor == len(decoded)
assert b''.join(bytes.fromhex(row['raw_hex']) for row in rows) == decoded
author_path = HERE / 'rank_resource_raw.json'
author_check = '尚无作者资源原证；当前结果仅为独立资源事实'
if author_path.exists():
    author = json.loads(author_path.read_text(encoding='utf-8'))
    assert author['source_sha256'] == hashlib.sha256(source).hexdigest()
    assert author['source_size'] == len(source)
    assert author['decoded_size'] == len(decoded)
    assert author['decoded_hex'] == decoded.hex()
    assert author['decoded_sha256'] == hashlib.sha256(decoded).hexdigest()
    assert author['key'] == source[0] and author['packed_size'] == compressed_size
    assert len(author['rows']) == len(rows) and len(author['segments']) == len(sections)
    for ours, theirs in zip(rows, author['rows']):
        for name in ('line', 'offset', 'size', 'raw_hex', 'content_hex'):
            assert ours[name] == theirs[name]
    for ours, theirs in zip(sections, author['segments']):
        for name in ('name_hex', 'header_line', 'header_offset'):
            assert ours[name] == theirs[name]
        assert len(ours['fields']) == len(theirs['fields'])
        for our_field, their_field in zip(ours['fields'], theirs['fields']):
            for name in ('line', 'offset', 'key_hex', 'value_hex'):
                assert our_field[name] == their_field[name]
    author_check = 'PASS'
result = {'status': 'PASS', 'source_size': len(source), 'source_key': source[0],
          'source_sha256': hashlib.sha256(source).hexdigest(),
          'compressed_size': compressed_size, 'compressed_sha256': hashlib.sha256(compressed).hexdigest(),
          'tail_size': len(source) - 9 - compressed_size,
          'decoded_size': len(decoded), 'decoded_sha256': hashlib.sha256(decoded).hexdigest(),
          'decoded_hex': decoded.hex(), 'rows': rows, 'sections': sections,
          'author_comparison': author_check,
          'scope': '完整资源字节和词法索引；不证明客户端停止规则或运行文本编码'}
(HERE / 'independent_resource.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({key: result[key] for key in ('status', 'source_size', 'compressed_size',
                                              'decoded_size', 'tail_size', 'author_comparison')}, ensure_ascii=False))
print(json.dumps({'sections': [bytes.fromhex(row['name_hex']).decode('ascii') for row in sections],
                  'rows': len(rows), 'fields': sum(len(row['fields']) for row in sections)}, ensure_ascii=False))
