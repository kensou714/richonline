"""只读导出大厅 URL 对象、直接消费者和频道构造；不访问网络或修改 IDB。"""
import json
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x81E0C0, 0x81E100, 0x81E130, 0x81E1C0, 0x81E290,
         0x6B7290, 0x623030, 0x82C470, 0x87DFE0,
         0x6B7610, 0x6B7640, 0x629070, 0x627060, 0x819250, 0x8198E0)


def export(db):
    ns = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), ns)
    group = ns['export_group']
    result = group(db, SEEDS, str(HERE / 'functions_raw.json'))
    incoming, bridges, consumers = [], {}, set()

    def resolve(ea):
        chain = []
        while ea not in chain and len(chain) < 16:
            raw = db.bytes.get_bytes_at(ea, 5)
            if not raw or raw[0] != 0xE9:
                break
            chain.append(ea)
            target = ea + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            bridges[ea] = dict(va=hex(ea), idb_hex=raw.hex(), target=hex(target))
            ea = target
        return ea, chain

    for seed in SEEDS[:6]:
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for edge in db.xrefs.to_ea(target):
                if int(edge.type) not in (16, 17, 18, 19):
                    continue
                owner = db.functions.get_at(edge.from_ea)
                final, chain = resolve(edge.from_ea)
                bridge = bool(chain) and final == seed
                incoming.append(dict(seed=hex(seed), target=hex(target),
                                     site=hex(edge.from_ea), kind=int(edge.type),
                                     owner=hex(owner.start_ea) if owner else None,
                                     bridge=bridge))
                if bridge:
                    pending.append(edge.from_ea)
                elif owner and owner.start_ea not in SEEDS:
                    consumers.add(owner.start_ea)
    callers = group(db, consumers, str(HERE / 'consumers_raw.json'))
    raw = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    helpers = set()
    for row in raw['functions']:
        if row['va'] != '0x623030':
            continue
        for call in row['calls']:
            ea = int(call['implementation'], 16)
            f = db.functions.get_at(ea)
            if f and f.start_ea == ea and 0 < f.end_ea - ea <= 128:
                helpers.add(ea)
    getters = group(db, helpers, str(HERE / 'short_helpers_raw.json'))
    (HERE / 'incoming.json').write_text(json.dumps(dict(edges=incoming, bridges=list(bridges.values())),
                                                   ensure_ascii=False, indent=2), 'utf-8')
    return dict(seeds=result, consumers=callers, short_helpers=getters)
