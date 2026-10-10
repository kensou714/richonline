"""只读导出地图上限、建筑类型与消费函数的跳板目标。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'
SEEDS = (0x63F2D0, 0x8054A0, 0x807BD0)


def export(db):
    namespace = {}
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(source.read_text(encoding='utf-8'), namespace)
    result = namespace['export_group'](db, SEEDS, str(BASE / 'implementations_raw.json'))
    return dict(export=result, addresses=[hex(ea) for ea in SEEDS])
