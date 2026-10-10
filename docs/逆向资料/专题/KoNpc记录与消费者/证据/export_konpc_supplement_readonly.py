"""补齐记录构造和现金/骰子消费者的直接字段访问器；只读 IDA。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNpc记录与消费者/证据'


def export(db):
    namespace = {}
    exec((BASE / 'export_konpc_readonly.py').read_text('utf-8'), namespace)
    resolve = namespace['resolve']
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    bridges = (0x60D295, 0x60C3B3, 0x611D8B, 0x60EE6F)
    targets, links = set(), []
    for bridge in bridges:
        target, chain = resolve(db, bridge)
        targets.add(target)
        links.append(dict(bridge=hex(bridge), target=hex(target), chain=[hex(v) for v in chain],
                          bridge_hex=db.bytes.get_bytes_at(bridge, 5).hex()))
    namespace['export_group'](db, targets, str(BASE / 'npc_supplement_raw.json'))
    (BASE / 'npc_supplement_links.json').write_text(json.dumps(links, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(targets=[hex(v) for v in sorted(targets)], output=str(BASE))
