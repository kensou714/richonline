"""从已有原证打印配置读写点的局部汇编上下文；不新增分析结论。"""
import json
import sys
from inspect_resource import HERE

data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
functions = {f['va']: f for f in data['functions']}
refs = json.loads((HERE / '证据/references.json').read_text(encoding='utf-8'))
if sys.argv[1] == 'summary':
    print('LOADER DEPENDENCIES', refs['loader_direct_dependencies'])
    for va in functions:
        direct = sorted(set(r['index'] for r in refs['references'] if r['function'] == va))
        print(va, 'INSTRUCTIONS', len(functions[va]['assembly']), 'INDICES', direct)
    raise SystemExit(0)
if sys.argv[1] == 'calls':
    for va in sys.argv[2:]:
        print(va, functions[va]['calls'])
    raise SystemExit(0)
if sys.argv[1] == 'functions':
    for va in sys.argv[2:]:
        print('FUNCTION', va)
        for line in functions[va]['pseudocode']:
            print(line)
    raise SystemExit(0)
low, high = map(int, sys.argv[1:3])
for ref in refs['references']:
    if not low <= ref['index'] <= high or not ref['function']:
        continue
    function = functions[ref['function']]
    rows = function['assembly']
    index = next(i for i, r in enumerate(rows) if r['va'] == ref['site'])
    print('INDEX', ref['index'], 'FUNCTION', ref['function'], 'SITE', ref['site'])
    for row in rows[max(0, index - 3):index + 8]:
        print(row['va'], row['text'])
