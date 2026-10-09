"""只读导出地图新闻索引、默认插入与地图筛选候选，逐块保留当前原证。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/地图新闻索引与所有权')
ROOT = HERE.parents[3]
SEEDS = {0x6950D0, 0x695520, 0x6963F0, 0x696660, 0x691AB0, 0x7AFE70}


def collect(db, extra=()):
    path = HERE / '证据/functions.json'
    addresses = set(SEEDS)
    if path.exists():
        addresses.update(int(row['va'], 16) for row in json.loads(path.read_text(encoding='utf-8'))['functions'])
    addresses.update(extra)
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), namespace)
    result = namespace['export_group'](db, addresses, str(path))
    data = json.loads(path.read_text(encoding='utf-8'))
    for function in data['functions']:
        for row in function['assembly']:
            row['size'] = db.instructions.get_at(int(row['va'], 16)).size
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


def recheck(db):
    data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    rows, mismatches = [], []
    for saved in data['functions']:
        function = db.functions.get_at(int(saved['va'], 16))
        chunks = list(db.functions.get_chunks(function))
        declared = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]
        actual = {hex(i.ea): i.size for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
        expected = {i['va']: i['size'] for i in saved['assembly']}
        if declared != saved['declared_chunks'] or actual != expected:
            mismatches.append(saved['va'])
        if any(db.bytes.get_bytes_at(int(r['va'], 16), r['size']).hex() != r['idb_hex']
               for r in saved['byte_ranges'] + saved['chunk_byte_ranges']):
            mismatches.append(saved['va'])
        rows.append(dict(va=saved['va'], declared_chunks=declared,
                         instruction_count=len(actual), instruction_bytes=sum(actual.values())))
    result = dict(disk_sha256=data['disk_sha256'], functions=rows, mismatches=sorted(set(mismatches)))
    (HERE / '证据/ida_recheck.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if mismatches:
        raise ValueError(mismatches)
    return dict(functions=len(rows), mismatches=[])


def supplement(db):
    extra = {0x695300, 0x695330, 0x695360, 0x695CB0, 0x695D00,
             0x695E40, 0x695EA0, 0x695EC0, 0x7B4B50, 0x7B4B90,
             0x6953E0, 0x695440, 0x696010, 0x696BF0, 0x698430, 0x696E80,
             0x7B4CC0, 0x7B4D20, 0x7B4D60, 0x7B4E20, 0x7B69D0,
             0x696190, 0x696250, 0x696050, 0x696370, 0x698570,
             0x696FE0, 0x7B5000, 0x7B6750, 0x7B6980, 0x697CE0}
    result = collect(db, extra)
    inbound = []
    for target in sorted(SEEDS | extra):
        pending, seen, edges = [target], set(), []
        while pending:
            address = pending.pop()
            if address in seen:
                continue
            seen.add(address)
            for x in db.xrefs.to_ea(address):
                owner = db.functions.get_at(x.from_ea)
                raw = db.bytes.get_bytes_at(x.from_ea, 5)
                is_bridge = bool(raw and raw[0] == 0xE9 and
                                 x.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == address)
                edges.append(dict(source=hex(x.from_ea), target=hex(address), kind=int(x.type),
                                  owner=hex(owner.start_ea) if owner else None,
                                  bridge=is_bridge))
                if is_bridge:
                    pending.append(x.from_ea)
        inbound.append(dict(target=hex(target), edges=edges))
    (HERE / '证据/inbound.json').write_text(json.dumps(inbound, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(export=result, recheck=recheck(db), targets=len(inbound))
