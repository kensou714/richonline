"""只读补充 KoNews 值容器与模式4的索引/文本消费，未知依赖单列。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNews记录与消费者/证据'
SEEDS = (0x809210, 0x809170, 0x809330, 0x809270, 0x809BF0,
         0x809D60, 0x809000, 0x809DE0, 0x809460,
         0x695260, 0x694FD0, 0x807CD0, 0x6827E0)


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, SEEDS, str(BASE / 'consumer_raw.json'))
