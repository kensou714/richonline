"""由持有IDA租约的会话调用；只读导出颜色入口和窄CRT依赖。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/界面数值与颜色解析契约/证据'


def export(db):
    namespace = {}
    script = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(script.read_text(encoding='utf-8-sig'), str(script), 'exec'), namespace)
    return namespace['export_group'](db, [0x8E0450, 0x92BE08, 0x92BE80, 0x93EBC0, 0x924720], HERE / 'color_functions.json')


def export_narrow(db):
    namespace = {}
    script = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(script.read_text(encoding='utf-8-sig'), str(script), 'exec'), namespace)
    return namespace['export_group'](db, [0x8E1C40, 0x92BEDD, 0x93EBD9], HERE / 'color_narrow.json')
