"""生成注释式伪码、调用边和完整已解码指令摘录，不改变审阅状态。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
lines, assembly = ['// 地图新闻索引与所有权：伪码仅供阅读，类型以汇编复核。'], ['// 地图新闻索引与所有权：完整已解码指令。']
for row in data['functions']:
    lines += ['//', '// ' + row['va'] + '  ' + row['name'], '// ' + '-' * 76]
    pseudo = row.get('pseudocode', [])
    if isinstance(pseudo, str):
        pseudo = pseudo.splitlines()
    lines += ['// ' + text for text in pseudo]
    lines += ['// 调用边：'] + ['// ' + e['site'] + ' -> ' + e['target'] + ' -> ' + e['implementation'] for e in row['calls']]
    assembly += ['//', '// ' + row['va'] + '  ' + row['name'], '// ' + '-' * 76]
    assembly += ['// ' + i['va'] + '  ' + i['text'] for i in row['assembly']]
(HERE / '证据/伪码与调用边.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(HERE / '证据/完整汇编.txt').write_text('\n'.join(assembly) + '\n', encoding='utf-8')
print(json.dumps({'functions': len(data['functions']), 'lines': len(lines)}))
