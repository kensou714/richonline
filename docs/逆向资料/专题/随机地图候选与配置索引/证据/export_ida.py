"""只读导出随机地图种子、候选选择、128字节条目容器及直接边。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT/'docs/逆向资料/专题/随机地图候选与配置索引/证据'
SEEDS = {0x6A9D50, 0x6AA450, 0x6AA530, 0x6AAA80, 0x6B8D20,
         0x6B8C50, 0x6B8E00, 0x6B8EA0, 0x6B9100, 0x6B8CB0,
         0x629DD0, 0x629DF0, 0x629E10}

def resolve(db, address):
    seen = set()
    while address not in seen:
        seen.add(address)
        raw = db.bytes.get_bytes_at(address, 5)
        if not raw or raw[0] != 0xE9:
            break
        address += 5 + int.from_bytes(raw[1:], 'little', signed=True)
    return address

def export(db):
    namespace = {}
    exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    result = namespace['export_group'](db, SEEDS, str(BASE/'functions_raw.json'))
    addresses = set()
    for site in [0x6B8D8C, 0x6AAA9D, 0x6AAAA9, 0x6AAAB0, 0x6B8CDD, 0x6B8CE4, 0x6B8CEB]:
        for edge in db.xrefs.from_ea(site):
            if edge.type in (16, 17):
                addresses.add(resolve(db, edge.to_ea))
    addresses.update(resolve(db, a) for a in [0x6010C6, 0x601404])
    dependencies = namespace['export_group'](db, addresses-SEEDS, str(BASE/'dependencies_raw.json'))
    inbound = []
    for target in [0x6A9D50, 0x6AA450, 0x6AA530, 0x6AAA80, 0x6B8D20]:
        pending, seen, edges = [target], set(), []
        while pending:
            address = pending.pop()
            if address in seen:
                continue
            seen.add(address)
            for edge in db.xrefs.to_ea(address):
                source = edge.from_ea
                owner = db.functions.get_at(source)
                raw = db.bytes.get_bytes_at(source, 5)
                bridge = bool(raw and raw[0] == 0xE9 and resolve(db, source) == target)
                edges.append(dict(site=hex(source), target=hex(address), kind=int(edge.type),
                                  owner=hex(owner.start_ea) if owner else None,
                                  bridge=bridge, idb_hex=raw.hex()))
                if bridge:
                    pending.append(source)
        inbound.append(dict(target=hex(target), edges=edges))
    (BASE/'inbound.json').write_text(json.dumps(inbound, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    return dict(core=result, dependencies=dependencies, dependency_addresses=[hex(a) for a in sorted(addresses)])

def supplement(db):
    namespace = {}
    exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    extra = {0x6B9990, 0x6B92E0, 0x6B99E0, 0x6B9960, 0x6B9A60,
             0x6BA5C0, 0x6BA620, 0x6BA800, 0x6BA970, 0x6B9A90}
    result = namespace['export_group'](db, extra, str(BASE/'supplement_raw.json'))
    data = []
    for address, size in [(0xA239D0, 19), (0x6AAB34, 16)]:
        raw = db.bytes.get_bytes_at(address, size)
        data.append(dict(va=hex(address), size=size, idb_hex=raw.hex()))
    (BASE/'data_raw.json').write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    return result
