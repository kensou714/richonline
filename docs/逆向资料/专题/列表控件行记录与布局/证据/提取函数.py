"""由持有当前IDA租约的会话调用export(db)；只读函数与引用。"""
import json
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/列表控件行记录与布局/证据'


def export(db):
    namespace = {}
    script = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(script.read_text(encoding='utf-8-sig'), str(script), 'exec'), namespace)
    functions = json.loads((ROOT / 'docs/逆向资料/全量分析/functions.json').read_text(encoding='utf-8'))
    addresses = [int(f['va'], 16) for f in functions
                 if 0x8F4050 <= int(f['va'], 16) <= 0x8F5017]
    return namespace['export_group'](db, addresses, HERE / 'list_functions.json')


def export_dependencies(db):
    namespace = {}
    script = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(script.read_text(encoding='utf-8-sig'), str(script), 'exec'), namespace)
    addresses = [0x8F30A0, 0x8F39D0, 0x8F5080, 0x8F5260, 0x8F5300,
                 0x8F5DE0, 0x8F5E60, 0x8F6B00, 0x8F6B50, 0x8F6C10,
                 0x8E1620, 0x8E1800, 0x8E2260, 0x8E0AA0, 0x8F8080]
    return namespace['export_group'](db, addresses, HERE / 'list_dependencies.json')
