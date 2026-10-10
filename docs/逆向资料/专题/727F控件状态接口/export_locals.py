"""只读补采种子相邻局部接口；相邻地址不预设属于同一个对象。"""
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/727F控件状态接口'
ENTRIES = [0x727EC0, 0x727F50, 0x727F90, 0x727FC0, 0x727FE0,
           0x728150, 0x7281B0, 0x728220]


def export(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    return exporter(db, ENTRIES, str(HERE / '证据/local_interfaces.json'))
