"""由持有 IDA lease 的主代理运行；仅导出格式化器与收尾依赖。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    namespace = {'__file__': str(source)}
    exec(compile(source.read_text(encoding='utf-8'), str(source), 'exec'), namespace)
    return namespace['export_group'](db, [0x932FC0, 0x932CD0], HERE / 'dependencies_raw.json')
