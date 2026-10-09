"""只读导出atoi/atol与发现的直接依赖；不得改动IDA数据库。"""
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    return exporter(db, [0x91F950, 0x91F800], HERE / '证据/seeds.json')
