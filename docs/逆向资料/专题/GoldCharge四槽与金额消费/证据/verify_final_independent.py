"""终审绑定：重跑独立核验，再验证作者清单和正文来源。"""
import hashlib
import json
from pathlib import Path

import independent_resource
import verify_bounded_independent
import verify_dependencies_independent
import verify_semantics_independent
import verify_supplement_independent

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pointer(data, path):
    for token in path.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        data = data[int(token)] if isinstance(data, list) else data[token]
    return data


def verify():
    results = {}
    for module in (independent_resource, verify_bounded_independent, verify_dependencies_independent,
                   verify_semantics_independent, verify_supplement_independent):
        results[module.__name__] = module.verify()
    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    assert formal['disk_sha256'] == EXPECTED
    assert formal['source_sha256'] == sha(HERE / 'bounded_raw.json')
    assert len(formal['functions']) == len(raw['functions']) == 5
    for n, (original, converted) in enumerate(zip(raw['functions'], formal['functions'])):
        assert converted['source'] == dict(path='证据/bounded_raw.json', sha256=formal['source_sha256'],
                                           json_pointer='/functions/' + str(n))
        assert converted['va'] == original['seed_va'] and converted['end_va'] == original['end_va']
        for key in ('name', 'pseudocode', 'decompile_error'):
            assert converted[key] == original[key]
        assert converted['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code'])
                                          for i in original['assembly']]
        assert converted['chunk_byte_ranges'] == [dict(va=c['start_va'], **{k: v for k, v in c.items()
                                                                          if k != 'start_va'})
                                                  for c in original['chunk_byte_ranges']]
        assert converted['declared_chunks'] == [dict(start_va=c['start_va'],
                                                     end_va=hex(int(c['start_va'], 16) + c['size']),
                                                     is_main=c['start_va'] == original['seed_va'])
                                                for c in original['chunk_byte_ranges']]
    review = json.loads((TOPIC / 'function_review.json').read_bytes())
    assert review['disk_sha256'] == EXPECTED
    source_names = ['formal_functions.json', 'dependency_raw.json', 'display_loader_raw.json']
    records = {f['va']: f for name in source_names
               for f in json.loads((HERE / name).read_bytes())['functions']}
    assert len(review['functions']) == len(records) == 19
    assert {f['va'] for f in review['functions']} == set(records)
    counts, byte_counts, head_counts, anchors = {}, {}, {}, 0
    for row in review['functions']:
        assert row['status'] == '局部语义已审阅' and row['conclusion'] and row['unknown']
        expected_category = ('桥接复核' if row['va'] in ('0x5ffd89', '0x601f7b', '0x604fb9')
                             else '已有入口补证' if row['va'] == '0x7b9ca0' else '新入口局部审阅')
        assert row['counting_category'] == expected_category
        source_ref, = row['source_records']
        source_path = TOPIC / source_ref['path']
        assert source_path.resolve().is_relative_to(TOPIC.resolve())
        assert sha(source_path) == source_ref['sha256']
        source = pointer(json.loads(source_path.read_bytes()), source_ref['pointer'])
        assert source == records[row['va']]
        assert source['name'] == row['name'] and source['va'] == row['va']
        assert source['declared_chunks'] == row['declared_chunks']
        assert source['chunk_byte_ranges'] == row['original_byte_ranges']
        source_heads = {i['va']: i for i in source['assembly']}
        assert len(row['anchors']) == len(source_heads)
        for anchor in row['anchors']:
            assert anchor['path'] == source_ref['path']
            assert anchor['pointer'].startswith(source_ref['pointer'] + '/assembly/')
            assert pointer(json.loads(source_path.read_bytes()), anchor['pointer']) == anchor['value']
            assert anchor['site_va'] in source_heads
            assert anchor['value'] == source_heads[anchor['site_va']]['text']
            anchors += 1
        counts[expected_category] = counts.get(expected_category, 0) + 1
        byte_counts[expected_category] = byte_counts.get(expected_category, 0) + sum(c['size'] for c in row['original_byte_ranges'])
        head_counts[expected_category] = head_counts.get(expected_category, 0) + len(source_heads)
    assert counts == {'新入口局部审阅': 15, '桥接复核': 3, '已有入口补证': 1}
    assert byte_counts == {'新入口局部审阅': 4104, '桥接复核': 15, '已有入口补证': 428}
    assert head_counts == {'新入口局部审阅': 1331, '桥接复核': 3, '已有入口补证': 108}
    reused = json.loads((HERE / 'reused_raw.json').read_bytes())
    assert review['reused'] == [dict(va=r['va'], source=r['source'], status='已有原证复用；新完成数0')
                                for r in reused['records']]
    author_resource = json.loads((HERE / 'resources.json').read_bytes())
    own_resource = json.loads((HERE / 'independent_resource.json').read_bytes())
    for key in ('source_size', 'source_sha256', 'decoded_size', 'decoded_sha256'):
        assert author_resource[key] == own_resource[key]
    decoded = (HERE / 'GoldCharge.kpd.decoded.bin').read_bytes()
    assert sha(HERE / 'GoldCharge.kpd.decoded.bin') == own_resource['decoded_sha256']
    assert decoded == own_resource['source_text'].encode('gbk')
    offset = 0
    for number, line in enumerate(author_resource['lines'], 1):
        assert line['number'] == number and line['offset'] == offset
        piece = bytes.fromhex(line['bytes'])
        assert len(piece) == line['size'] and decoded[offset:offset + len(piece)] == piece
        offset += len(piece)
    assert offset == len(decoded)
    assert [(r['index'], r['charge']) for r in own_resource['records']] == [
        (0, 160), (1, 240), (2, 160), (3, 300), (4, 250), (5, 300), (6, 2000)]
    docs = sorted(TOPIC.glob('*.txt')) + [HERE / '独立审阅.txt']
    for path in docs:
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    files = docs + [TOPIC / 'function_review.json'] + sorted(HERE.glob('*.py'))
    files += [HERE / name for name in source_names + ['bounded_raw.json', 'reused_raw.json',
                                                     'resources.json', 'table_supplement/bounded_raw.json',
                                                     'table_head_supplement/bounded_raw.json']]
    result = dict(schema='richonline-independent-goldcharge-final-1', status='PASS', disk_sha256=EXPECTED,
                  checks=results, counts=counts, byte_counts=byte_counts, instruction_counts=head_counts,
                  manifest_anchors=anchors, reused_records=len(reused['records']),
                  bound_files={str(p.relative_to(TOPIC)).replace('\\', '/'): sha(p) for p in files},
                  boundary='独立静态局部审阅；不代表实机显示、扣款或网络闭环')
    (HERE / 'independent_final_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status='PASS', functions=len(records), fresh=counts['新入口局部审阅'], anchors=anchors)


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
