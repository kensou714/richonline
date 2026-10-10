"""只读追踪 NPC 绑定字段、生成候选与 Ko 配置对象销毁；交主任务 IDA lease 执行。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNpc生成与生命周期/证据'
SEEDS = (0x8054E0, 0x805550, 0x806A30, 0x8073C0, 0x807440,
         0x8074F0, 0x808CB0, 0x808CE0, 0x808D10,
         0x808BA0, 0x808BD0, 0x808DF0)
DISPLACEMENTS = (0x14788, 0x1478C, 0x4584)


def resolve(db, ea):
    chain = []
    while ea not in chain and len(chain) < 16:
        raw = db.bytes.get_bytes_at(ea, 5)
        if not raw or raw[0] != 0xE9:
            break
        chain.append(ea)
        ea += 5 + int.from_bytes(raw[1:], 'little', signed=True)
    return ea, chain


def incoming(db, seed):
    rows, owners = [], set()
    pending, visited = [seed], set()
    while pending:
        target = pending.pop()
        if target in visited:
            continue
        visited.add(target)
        for edge in db.xrefs.to_ea(target):
            owner = db.functions.get_at(edge.from_ea)
            final, chain = resolve(db, edge.from_ea)
            bridge = bool(chain) and final == seed
            rows.append(dict(seed=hex(seed), target=hex(target), site=hex(edge.from_ea),
                             kind=int(edge.type), owner=hex(owner.start_ea) if owner else None,
                             bridge=bridge))
            if bridge:
                pending.append(edge.from_ea)
            elif owner:
                owners.add(owner.start_ea)
    return rows, owners


def disk_candidates(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    hits, owners = [], set()
    # 原字节仅用于找到候选声明函数；匹配立即数、内嵌数据不直接认作字段访问。
    for index in range(count):
        header = pe + 24 + optional_size + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, header + 12)
        flags = struct.unpack_from('<I', blob, header + 36)[0]
        if not flags & 0x20000000:
            continue
        section = blob[offset:offset + size]
        for displacement in DISPLACEMENTS:
            pattern, cursor = struct.pack('<I', displacement), 0
            while True:
                found = section.find(pattern, cursor)
                if found < 0:
                    break
                ea = image_base + rva + found
                owner = db.functions.get_at(ea)
                hits.append(dict(operand_va=hex(ea), candidate_displacement=hex(displacement),
                                 owner=hex(owner.start_ea) if owner else None))
                if owner:
                    owners.add(owner.start_ea)
                cursor = found + 1
    return hits, owners


def export(db):
    BASE.mkdir(parents=True, exist_ok=True)
    namespace = {}
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(helper.read_text('utf-8'), str(helper), 'exec'), namespace)
    links, candidates = [], set(SEEDS)
    for seed in SEEDS:
        rows, owners = incoming(db, seed)
        links.extend(rows)
        candidates.update(owners)
    hits, owners = disk_candidates(db)
    candidates.update(owners)
    old = json.loads((ROOT / 'docs/逆向资料/全量分析/evidence_coverage.json').read_text('utf-8'))
    old_index = {int(row['va'], 16): row for row in old['functions']}
    reuse = [old_index[ea] for ea in sorted(candidates) if ea in old_index]
    fresh = sorted(candidates - old_index.keys())
    if len(fresh) > 96:
        raise ValueError('候选范围过大，先收窄导出：' + str(len(fresh)))
    result = namespace['export_group'](db, fresh, str(BASE / 'generation_raw.json'))
    for name, value in [('incoming.json', links), ('operand_candidates.json', hits),
                        ('reuse_sources.json', dict(reused= reuse,
                         inventory_sha256=hashlib.sha256((ROOT / 'docs/逆向资料/全量分析/evidence_coverage.json').read_bytes()).hexdigest()))]:
        (BASE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(new_functions=len(fresh), reused_functions=len(reuse), incoming=len(links),
                raw_operand_candidates=len(hits), result=result)
