"""独立终审入口：先复跑字节检查，再核机械适配、正文和审阅锚点。"""
import hashlib
import json
import runpy
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent


def pointer(value, path):
    assert path.startswith('/')
    for part in path[1:].split('/'):
        key = part.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def verify():
    mechanical = []
    for filename in ('verify_legacy_network_independent.py', 'verify_bounded_independent.py',
                     'verify_dependencies_independent.py'):
        mechanical.append(runpy.run_path(str(HERE / filename))['verify']())
    original_bytes = (HERE / 'bounded_raw.json').read_bytes()
    original = json.loads(original_bytes)
    formal_bytes = (HERE / 'formal_functions.json').read_bytes()
    formal = json.loads(formal_bytes)
    digest = hashlib.sha256(original_bytes).hexdigest()
    assert formal['source_sha256'] == digest
    assert len(formal['functions']) == len(original['functions']) == 6
    for row in formal['functions']:
        ref = row['source']
        assert ref['path'] == '证据/bounded_raw.json' and ref['sha256'] == digest
        old = pointer(original, ref['json_pointer'])
        assert row['va'] == old['seed_va'] and row['end_va'] == old['end_va']
        assert row['pseudocode'] == old['pseudocode'] and row['decompile_error'] == old['decompile_error']
        assert row['assembly'] == [dict(va=item['site_va'], text=item['text'], is_code=item['is_code'])
                                   for item in old['assembly']]
        assert row['chunk_byte_ranges'] == [dict(va=chunk['start_va'],
                                            **{key: value for key, value in chunk.items() if key != 'start_va'})
                                            for chunk in old['chunk_byte_ranges']]
    review_path = TOPIC / 'function_review.json'
    review_bytes = review_path.read_bytes()
    review = json.loads(review_bytes)
    source_names = ('formal_functions.json', 'dependency_raw.json',
                    'dependency_helpers_raw.json', 'dependency_leaf_raw.json')
    sources = {}
    for name in source_names:
        payload = (HERE / name).read_bytes()
        sources['证据/' + name] = (json.loads(payload), hashlib.sha256(payload).hexdigest())
    assert review['disk_sha256'] == original['disk_sha256']
    assert review['source_files'] == [dict(path=path, sha256=entry[1])
                                     for path, entry in sources.items()]
    records = review['functions']
    seen, anchors = set(), 0
    for row in records:
        assert {'va', 'status', 'conclusion', 'unknown', 'evidence', 'anchors'} <= row.keys()
        assert row['va'] not in seen and row['unknown'] and row['evidence'] and row['anchors']
        assert row['status'] == row['review_status'] == '局部语义已审阅'
        assert row['full_dependency_closure'] is False
        seen.add(row['va'])
        assert len(row['source_records']) == 1
        binding = row['source_records'][0]
        source, source_sha = sources[binding['path']]
        assert binding['sha256'] == source_sha
        original_row = pointer(source, binding['pointer'])
        assert original_row['va'] == row['va']
        assert row['name_from_idb'] == original_row['name']
        assert row['declared_chunks'] == original_row['declared_chunks']
        assert row['original_byte_ranges'] == original_row['chunk_byte_ranges']
        for anchor in row['anchors']:
            path = (TOPIC / anchor['path']).resolve()
            assert path.is_relative_to(TOPIC.resolve())
            assert anchor['path'] in row['evidence'] and anchor['path'] in sources
            source = sources[anchor['path']][0]
            assert pointer(source, anchor['pointer']) == anchor['value']
            instruction = pointer(source, anchor['pointer'].rsplit('/', 1)[0])
            assert instruction['va'] == anchor['site_va']
            owner = pointer(source, '/'.join(anchor['pointer'].split('/')[:3]))
            assert owner['va'] == anchor.get('dependency_va', row['va'])
            anchors += 1
    expected = {row['seed_va'] for row in original['functions']}
    for path in HERE.glob('dependency*_raw.json'):
        expected.update(row['va'] for row in json.loads(path.read_bytes())['functions'])
    assert seen == expected, (seen - expected, expected - seen)
    reused = json.loads((HERE / 'reused_network.json').read_bytes())['functions']
    assert len(reused) == review['reused_ranges']['count'] == 4
    assert review['reused_ranges']['new_completion_count'] == 0
    assert review['reused_ranges']['path'] == '证据/reused_network.json'
    assert not seen.intersection(row['seed_va'] for row in reused)
    documents = []
    for path in sorted(TOPIC.glob('*.txt')):
        raw = path.read_bytes()
        assert all(not line.strip() or line.startswith('//') for line in raw.decode('utf-8').splitlines())
        documents.append(dict(path=path.name, sha256=hashlib.sha256(raw).hexdigest()))
    report = (HERE / '独立审阅.txt').read_bytes()
    assert all(not line.strip() or line.startswith('//') for line in report.decode('utf-8').splitlines())
    result = dict(schema='richonline-independent-final-1', status='PASS',
                  scope='原证机械复核、机械适配及逐函数锚点；正文由独审逐篇人工核验',
                  mechanical=mechanical, functions=len(records), anchors=anchors,
                  reused_ranges=len(reused), reused_new_completion_count=0,
                  completion_level='局部语义已审阅；完整声明块原样绑定，不证明全依赖闭环',
                  review_sha256=hashlib.sha256(review_bytes).hexdigest(),
                  independent_report_sha256=hashlib.sha256(report).hexdigest(),
                  formal_sha256=hashlib.sha256(formal_bytes).hexdigest(), documents=documents,
                  limitation='静态语义终审，不证明线程、网络实录或游戏实机行为')
    (HERE / 'independent_final_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: result[key] for key in ('status', 'functions', 'anchors')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
