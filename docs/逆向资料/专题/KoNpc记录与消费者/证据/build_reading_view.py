"""机械摘出反编译与调用地址，便于阅读；不是语义审阅清单。"""
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent


def main():
    lines = []
    for name in ('npc_methods_raw.json', 'npc_consumers_raw.json', 'npc_dependencies_raw.json'):
        raw = json.loads((HERE / name).read_text('utf-8'))
        lines.append('// SOURCE ' + name)
        for function in raw['functions']:
            lines.append('// FUNCTION ' + function['va'] + ' ' + function['name'])
            lines.extend('// ' + line for line in function['pseudocode'])
            lines.append('// CALLS ' + json.dumps(function['calls'], ensure_ascii=False))
    (HERE / 'pseudocode_reading_view.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
