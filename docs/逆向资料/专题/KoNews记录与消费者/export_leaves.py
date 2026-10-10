"""只读补取包装层下游的模式、迭代器、payload和指针初始化叶函数。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNews记录与消费者/证据'
SEEDS = (0x629E10, 0x696EC0, 0x696F00, 0x696F40, 0x80A730, 0x809FF0, 0x697880)


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, SEEDS, str(BASE / 'leaves_raw.json'))
