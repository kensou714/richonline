"""只读导出两个映射入口、真实E9入边及直接调用者；不修改数据库。"""
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SEEDS = (0x6C22E0, 0x6F4AA0)


def collect(db, followups=()):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    callers, bridges, edges = set(), {}, []
    for seed in SEEDS:
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for xref in db.xrefs.to_ea(target):
                source = xref.from_ea
                owner = db.functions.get_at(source)
                raw = db.bytes.get_bytes_at(source, 5)
                bridge = bool(raw and raw[0] == 0xE9 and
                              source + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
                edges.append(dict(seed=hex(seed), source=hex(source), target=hex(target),
                                  kind=int(xref.type), owner=hex(owner.start_ea) if owner else None,
                                  e9_bridge=bridge, source_hex=raw.hex() if raw else None))
                if bridge:
                    bridges[source] = target
                    pending.append(source)
                elif owner:
                    callers.add(owner.start_ea)
    # 入口和直接调用者分别保留；调用者只作为数据来源证据，不自动记为已分析。
    seed_result = export(db, SEEDS, str(HERE / '证据/entries.json'))
    caller_result = export(db, callers - set(SEEDS), str(HERE / '证据/callers.json'))
    extra_result = export(db, followups, str(HERE / '证据/followups.json')) if followups else None
    data = dict(scope='只沿真实E9入边递归；其余xref所属函数作为直接调用者证据，不证明间接调用穷尽',
                seeds=[hex(a) for a in SEEDS], callers=[hex(a) for a in sorted(callers)],
                edges=edges, e9_bridges=[dict(va=hex(a), target=hex(b)) for a, b in sorted(bridges.items())])
    path = HERE / '证据/references.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(entries=seed_result, callers=caller_result, followups=extra_result,
                caller_addresses=data['callers'], e9_bridges=len(bridges))
