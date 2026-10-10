"""只读导出地图建筑等级配置入口；不改动 IDB、EXE 或运行资源。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'
SEEDS = (0x805660, 0x8056C0, 0x806670, 0x806A30, 0x7AF4A0)


def export(db):
    namespace = {}
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(source.read_text(encoding='utf-8'), namespace)
    funcs = {f.start_ea for f in db.functions.get_between(0x805600, 0x806700)}
    funcs.update(SEEDS)
    result = namespace['export_group'](db, funcs, str(BASE / 'functions_raw.json'))
    incoming = []
    for target in sorted(funcs):
        edges = []
        for edge in db.xrefs.to_ea(target):
            owner = db.functions.get_at(edge.from_ea)
            edges.append(dict(site=hex(edge.from_ea), kind=int(edge.type),
                              owner=hex(owner.start_ea) if owner else None))
        incoming.append(dict(target=hex(target), edges=edges))
    (BASE / 'incoming.json').write_text(
        json.dumps(incoming, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(export=result, addresses=[hex(ea) for ea in sorted(funcs)])
