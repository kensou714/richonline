"""只读补足模式谓词、索引步长、树payload、空值与lower_bound实现。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNews记录与消费者/证据'
SEEDS = (0x63E990, 0x695D40, 0x695F80, 0x695F50, 0x80B490,
         0x8090E0, 0x80B140, 0x80ABB0)


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, SEEDS, str(BASE / 'helpers_raw.json'))
