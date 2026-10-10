"""独立只读解包当前两份配置；文本分节用于样本清点，不模拟客户端解析器。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def review():
    records = []
    for name in ('NewProps', 'CombCard'):
        relative = f'Data/{name}.kpd'
        source = (ROOT / relative).read_bytes()
        key = source[0]
        unmasked = bytes((byte - key) & 255 for byte in source[1:])
        raw_size, packed_size = struct.unpack_from('<II', unmasked)
        assert 0 < raw_size < 64 * 1024 * 1024
        assert packed_size == len(source) - 9
        raw = lzokay.decompress(unmasked[8:], raw_size)
        assert len(raw) == raw_size
        encoding = 'cp950' if name == 'NewProps' else 'gb18030'
        text = raw.decode(encoding, errors='strict')
        assert text.encode(encoding) == raw
        sections, current = [], None
        for number, line in enumerate(text.splitlines(), 1):
            match = re.fullmatch(r'\s*\[([^\]]+)\]\s*', line)
            if match:
                current = {'section': match[1], 'line': number, 'fields': []}
                sections.append(current)
            elif current is not None and '=' in line and not line.lstrip().startswith(('//', ';', '#')):
                field, value = line.split('=', 1)
                current['fields'].append({'line': number, 'key': field.strip(), 'value': value.strip()})
        records.append(dict(source=relative, source_size=len(source), source_sha256=digest(source),
                            key=key, raw_size=raw_size, packed_size=packed_size,
                            decoded_sha256=digest(raw), encoding=encoding + '严格往返，仅当前样本事实',
                            line_count=len(text.splitlines()), sections=sections))
        (HERE / f'independent_{name}_sample.txt').write_text(
            '\n'.join('// ' + line for line in text.splitlines()) + '\n', encoding='utf-8')
    previous = ROOT / 'docs/逆向资料/专题/主界面角色通知/证据/主界面资源样本.json'
    old = json.loads(previous.read_bytes())
    new = next(row for row in records if row['source'] == 'Data/NewProps.kpd')
    original = next(row for row in old['records'] if row['source'] == new['source'])
    assert original['sha256'] == new['source_sha256']
    assert original['decoded_sha256'] == new['decoded_sha256']
    author_path = HERE / 'resources_author.json'
    author = json.loads(author_path.read_bytes())
    author_records = {row['source']: row for row in author['records']}
    for row in records:
        authored = author_records[row['source']]
        for key in ('source_size', 'source_sha256', 'key', 'raw_size', 'packed_size',
                    'decoded_sha256', 'line_count', 'sections'):
            assert row[key] == authored[key], (row['source'], key)
        decoded = bytes.fromhex(authored['decoded_hex'])
        assert len(decoded) == row['raw_size'] and digest(decoded) == row['decoded_sha256']
        if row['source'] == 'Data/NewProps.kpd':
            assert authored['limit'] == 5
            expected = [{'prop': number, 'pri': 0} for number in range(1893, 1929)]
            assert authored['new_records'] == expected
            assert authored['unique_prop_ids'] == 36 and authored['pri_values'] == [0]
        else:
            expected = []
            for section in row['sections']:
                fields = {field['key']: field['value'] for field in section['fields']}
                slots = []
                for index in range(8):
                    value = fields.get(f'src{index}')
                    if value is None:
                        break
                    prop, count = map(int, value.split(','))
                    slots.append({'prop': prop, 'required_slots': count})
                expected.append({'sources': slots, 'dest': int(fields['dest']),
                                 'enabled': fields['enable'] == 'true'})
            assert authored['recipes'] == expected
    result = dict(status='当前资源独立解包通过', records=records,
                  author_sha256=digest(author_path.read_bytes()), author_fields_compared=True,
                  reused_newprops_evidence=dict(source=str(previous.relative_to(ROOT)),
                                               sha256=digest(previous.read_bytes())),
                  boundary='不导入作者脚本；离线分节非游戏解析器；未运行游戏；既有资源不计新增')
    (HERE / 'independent_resources.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], [(row['source'], len(row['sections']), row['line_count']) for row in result['records']])
