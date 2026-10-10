"""补齐借用开关、字库删除包装和配置默认值；保持有限生命周期边界。"""
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/627830懒单例'


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    return export(db, [0x698C70, 0x6DFC10, 0x6DFBA0], str(HERE / '证据/gate_and_delete.json'))
