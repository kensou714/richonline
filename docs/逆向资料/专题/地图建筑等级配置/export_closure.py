"""只读导出地图建筑等级配置的默认值、索引及消费链。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'
SEEDS = (0x600A9A, 0x60C048, 0x60CBCE, 0x67B890, 0x8053C0)


def export(db):
    namespace = {}
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(source.read_text(encoding='utf-8'), namespace)
    result = namespace['export_group'](db, SEEDS, str(BASE / 'closure_raw.json'))
    return dict(export=result, addresses=[hex(ea) for ea in SEEDS])
