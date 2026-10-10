"""只读补未声明 harm 调用窗口的桥与入口引用，及容器析构/构造叶依赖。"""
import json
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNpc生成与生命周期/证据'


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    namespace = {}
    exec(compile(helper.read_text('utf-8'), str(helper), 'exec'), namespace)
    result = namespace['export_group'](db, {0x809C40, 0x80AB10, 0x80B250, 0x80B2D0},
                                       str(BASE / 'lifecycle_leaves_raw.json'))
    links, bridges = [], []
    for start in (0x603DDF, 0x60D3F8, 0x5FF843, 0x609FE1, 0x6059AA, 0x611313):
        raw = db.bytes.get_bytes_at(start, 5)
        if raw[0] != 0xE9:
            raise ValueError('不是 E9 桥：' + hex(start))
        target = start + 5 + int.from_bytes(raw[1:], 'little', signed=True)
        bridges.append(dict(va=hex(start), size=5, idb_hex=raw.hex(), target=hex(target)))
        for edge in db.xrefs.to_ea(start):
            owner = db.functions.get_at(edge.from_ea)
            links.append(dict(target=hex(start), site=hex(edge.from_ea), kind=int(edge.type),
                              owner=hex(owner.start_ea) if owner else None))
    (BASE / 'window_bridges.json').write_text(json.dumps(dict(bridges=bridges, incoming=links),
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(result=result, bridges=len(bridges), links=len(links))
