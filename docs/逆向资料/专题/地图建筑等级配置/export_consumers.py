"""只读枚举 Ko 配置全局对象取得点及调用现场，供消费者筛选。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'


def resolve(db, ea):
    seen = set()
    while ea not in seen:
        seen.add(ea)
        raw = db.bytes.get_bytes_at(ea, 5)
        if not raw or raw[0] != 0xE9:
            return ea
        ea += 5 + int.from_bytes(raw[1:], 'little', signed=True)
    return ea


def export(db):
    namespace = {}
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(source.read_text(encoding='utf-8'), namespace)
    funcs = {0x628010, 0x60FD83}
    main = namespace['export_group'](db, funcs, str(BASE / 'dependencies_raw.json'))
    targets = {0x628010}
    sites = {}
    for f in db.functions:
        # 仅扫描以 E9 直达取得器的 5 字节桥，不解释普通函数体。
        if f.end_ea - f.start_ea != 5:
            continue
        if resolve(db, f.start_ea) == 0x628010:
            targets.add(f.start_ea)
    for target in sorted(targets):
        for edge in db.xrefs.to_ea(target):
            owner = db.functions.get_at(edge.from_ea)
            if owner is None or owner.start_ea == target:
                continue
            site = edge.from_ea
            window = [dict(va=hex(i.ea), text=db.instructions.get_disassembly(i))
                      for i in db.instructions.get_between(max(owner.start_ea, site - 24),
                                                            min(owner.end_ea, site + 52))]
            sites[(site, target)] = dict(site=hex(site), target=hex(target),
                                         owner=hex(owner.start_ea), kind=int(edge.type),
                                         window=window)
    result = dict(targets=[hex(t) for t in sorted(targets)],
                  callsites=[sites[key] for key in sorted(sites)])
    (BASE / 'consumer_callsites.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(dependencies=main, targets=len(targets), callsites=len(sites))
