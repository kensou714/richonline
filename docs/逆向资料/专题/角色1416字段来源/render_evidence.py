"""把已保存函数伪码与调用目标整理为可审阅摘录；不把自动命名当成业务结论。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
lines = ['// IDA伪码及调用映射原证摘录；类型和函数自动命名须结合汇编修正。']
for function in data['functions']:
    lines += ['//', '// ========== ' + function['va'] + ' ==========']
    lines += ['// ' + row for row in function['pseudocode']]
    lines += ['// 调用映射：']
    lines += ['// ' + row['site'] + ' -> ' + row['target'] + ' -> ' + row['implementation']
              for row in function['calls']]
(HERE / '证据/伪码摘录.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
contexts = ['// 字段位移、角色getter与初始化调用点附近汇编；完整函数见functions.json。']
for function in data['functions']:
    interesting = {row['site'] for row in function['calls']
                   if row['implementation'] in ('0x7fd7a0', '0x7f3c70', '0x7f3840', '0x642740', '0x69b600', '0x7de310', '0x7f4550')}
    assembly = function['assembly']
    for i, row in enumerate(assembly):
        if row['va'] in interesting or '+588h]' in row['text']:
            contexts += ['//', '// 函数' + function['va'] + ' / 使用点' + row['va']]
            contexts += ['// ' + item['va'] + '  ' + item['text'] for item in assembly[max(0, i - 12):i + 9]]
(HERE / '证据/关键汇编上下文.txt').write_text('\n'.join(contexts) + '\n', encoding='utf-8')
