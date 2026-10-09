"""经已有IDA-MCP只读db上下文重导当前专题六组函数，不修改IDB。"""
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/二进制读写游标'


def run(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    plans = []
    for name in ['cursor_seeds.json', 'cursor_dependencies.json', 'cursor_family.json',
                 'cursor_consumers.json', 'cursor_extensions.json', 'cursor_widths.json']:
        path = HERE / '证据' / name
        data = json.loads(path.read_text(encoding='utf-8'))
        plans.append((path, [int(f['va'], 16) for f in data['functions']]))
    return {path.name: exporter(db, addresses, str(path)) for path, addresses in plans}
