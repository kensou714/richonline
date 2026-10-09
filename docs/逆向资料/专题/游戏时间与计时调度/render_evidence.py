"""把当前IDA导出转为中文注释式阅读原证；不提升函数审阅状态。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
lines = ['// ============================================================================',
         '// 游戏时间与计时调度：当前IDA伪码与完整调用边',
         '// ============================================================================',
         '// 伪码是阅读辅助，符号名、类型和有符号比较需由汇编复核。',
         '// SHA256：' + data['disk_sha256'], '//']
for row in data['functions']:
    lines += ['// ' + row['va'] + '  ' + row['name'], '// ' + '-' * 76,
              '// 声明块：' + ', '.join(c['start_va'] + '..' + c['end_va'] for c in row['declared_chunks'])]
    pseudo = row.get('pseudocode', [])
    if isinstance(pseudo, str):
        pseudo = pseudo.splitlines()
    lines += ['// ' + text for text in pseudo]
    lines += ['// 调用边：']
    lines += ['//   ' + edge['site'] + ' -> ' + edge['target'] + ' -> ' + edge['implementation']
              for edge in row['calls']]
    lines += ['//']
(HERE / '证据/伪码与调用边.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
assembly = ['// 游戏时间与计时调度：完整已解码指令摘录',
            '// 声明块内原始数据另见functions.json的chunk_byte_ranges。', '//']
for row in data['functions']:
    assembly += ['// ' + row['va'] + '  ' + row['name'], '// ' + '-' * 76]
    assembly += ['// ' + ins['va'] + '  ' + ins['text'] for ins in row['assembly']]
    assembly += ['//']
(HERE / '证据/完整汇编.txt').write_text('\n'.join(assembly) + '\n', encoding='utf-8')
print(json.dumps({'functions': len(data['functions']), 'lines': len(lines)}))
