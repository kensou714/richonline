"""仅补两个代表消费者，确认计数表与388字节记录的所属对象和实参。"""
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/727F控件状态接口'


def export(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    return exporter(db, [0x7113A0, 0x712750], str(HERE / '证据/representative_consumers.json'))
