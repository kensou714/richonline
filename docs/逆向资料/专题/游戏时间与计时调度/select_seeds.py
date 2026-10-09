"""从既有全量数据边、调用图和人工台账筛选时间来源候选；结果只作导航。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ARCHIVE = ROOT / 'docs/逆向资料/全量分析'


def read(name):
    return json.loads((ARCHIVE / name).read_text(encoding='utf-8'))


imports = {r['va']: r['name'] for r in read('names.json')
           if r['name'] in ('GetTickCount', 'timeGetTime', 'QueryPerformanceCounter',
                            'QueryPerformanceFrequency', 'Sleep', 'GetSystemTimeAsFileTime')}
reviews = {r['va']: r.get('reviews', []) for r in read('review_coverage.json')['functions']}
functions = {r['va']: r for r in read('functions.json')}
result = []
for item in read('all_data_edges.json')['items']:
    if item['va'] not in imports:
        continue
    by_function = {}
    for ref in item['references']:
        by_function.setdefault(ref['function_va'], []).append(ref['site'])
    for va, sites in by_function.items():
        result.append(dict(va=va, source=imports[item['va']], import_va=item['va'], sites=sites,
                           span=functions.get(va, {}).get('span_bytes'),
                           reviews=[{key: review.get(key) for key in ('source', 'status', 'conclusion')}
                                    for review in reviews.get(va, [])]))
callers = {}
for path in (ARCHIVE / 'callgraph').glob('batch_*.json'):
    for function in json.loads(path.read_text(encoding='utf-8')):
        for edge in function['edges']:
            target = edge['normalized_target_va']
            callers.setdefault(target, set()).add(function['va'])
for item in result:
    item['callers'] = sorted(callers.get(item['va'], []))
HERE.mkdir(parents=True, exist_ok=True)
(HERE / '种子导航.json').write_text(json.dumps({'scope': '旧全量归档导航；导出当前原证后再下语义结论', 'candidates': result}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
for item in result:
    if not item['reviews'] or item['source'].startswith('Query'):
        print(json.dumps(item, ensure_ascii=True))
