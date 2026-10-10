"""补采字体管理单例的生命周期、字号映射与门面；不展开字形渲染内部。"""
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/627830懒单例'
ENTRIES = [0x6DD2B0, 0x6DD3D0, 0x6DD600, 0x6DD710, 0x6DD810,
           0x6DD880, 0x6DDCF0, 0x627520, 0x6DF790]


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    return export(db, ENTRIES, str(HERE / '证据/lifetime_and_facade.json'))
