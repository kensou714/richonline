"""只读解包两配置，保留节顺序与重复键；不调用客户端或改资源。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def sections(text):
    records, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('//'):
            continue
        if stripped.startswith('[') and stripped.endswith(']'):
            current = dict(section=stripped[1:-1], line=number, fields=[])
            records.append(current)
        elif '=' in line and current is not None:
            key, value = line.split('=', 1)
            current['fields'].append(dict(line=number, key=key.strip(), value=value.strip()))
        else:
            raise ValueError((number, line))
    return records


def inspect():
    records = []
    for name, encoding in (('NewProps', 'cp950'), ('CombCard', 'gb18030')):
        relative = 'Data/' + name + '.kpd'
        blob = (ROOT / relative).read_bytes()
        key = blob[0]
        size, packed = struct.unpack('<II', bytes((value-key) & 255 for value in blob[1:9]))
        assert 0 < size <= 64 * 1024 * 1024 and packed == len(blob) - 9
        decoded = lzokay.decompress(bytes((value-key) & 255 for value in blob[9:]), size)
        assert len(decoded) == size
        text = decoded.decode(encoding, errors='strict')
        assert text.encode(encoding) == decoded
        parsed = sections(text)
        row = dict(source=relative, source_size=len(blob), source_sha256=hashlib.sha256(blob).hexdigest(),
                   key=key, raw_size=size, packed_size=packed, decoded_hex=decoded.hex(),
                   decoded_sha256=hashlib.sha256(decoded).hexdigest(), encoding=encoding,
                   line_count=len(text.splitlines()), sections=parsed,
                   boundary='本脚本的有界离线文本解析不模拟客户端容错或代码页。')
        if name == 'NewProps':
            assert parsed[0]['section'] == 'PRI'
            assert len(parsed) == 37 and all(s['section'] == 'NEW' for s in parsed[1:])
            assert [f['key'] for f in parsed[0]['fields']] == ['limit']
            assert all([f['key'] for f in s['fields']] == ['prop', 'pri'] for s in parsed[1:])
            values = [{f['key']: int(f['value']) for f in s['fields']} for s in parsed[1:]]
            row.update(limit=int(parsed[0]['fields'][0]['value']), new_records=values,
                       unique_prop_ids=len({v['prop'] for v in values}),
                       pri_values=sorted({v['pri'] for v in values}))
        else:
            assert len(parsed) == 6 and all(s['section'] == 'ITEM' for s in parsed)
            recipes = []
            for section in parsed:
                keys = [f['key'] for f in section['fields']]
                assert len(keys) == len(set(keys))
                fields = {f['key']: f['value'] for f in section['fields']}
                sources = []
                for index in range(8):
                    value = fields.get('src' + str(index))
                    if value is None:
                        break
                    pair = [int(v) for v in value.split(',')]
                    assert len(pair) == 2 and all(-32768 <= v <= 32767 for v in pair)
                    sources.append(dict(prop=pair[0], required_slots=pair[1]))
                assert keys == ['src' + str(i) for i in range(len(sources))] + ['dest', 'enable']
                assert sources and fields['enable'] == 'true'
                recipes.append(dict(sources=sources, dest=int(fields['dest']), enabled=True))
            row['recipes'] = recipes
        records.append(row)
    return dict(scope='当前资源样本；解包工作不重复认领原有NewProps资源发现。', records=records)


if __name__ == '__main__':
    result = inspect()
    (HERE / '证据/resources_author.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps([dict(source=r['source'], sections=len(r['sections']), raw_size=r['raw_size'],
                           pri_values=r.get('pri_values'), recipes=r.get('recipes')) for r in result['records']], ensure_ascii=False))
