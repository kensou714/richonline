"""只读导出 KoNpc 记录构造、访问器、效果链和直接消费者；仅写本专题证据。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNpc记录与消费者/证据'


def resolve(db, ea):
    chain = []
    while ea not in chain and len(chain) < 16:
        raw = db.bytes.get_bytes_at(ea, 5)
        if not raw or raw[0] != 0xE9:
            break
        chain.append(ea)
        ea += 5 + int.from_bytes(raw[1:], 'little', signed=True)
    return ea, chain


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    group = namespace['export_group']
    methods = {f.start_ea for f in db.functions.get_between(0x807370, 0x807BD0)}
    constructors = {f.start_ea for f in db.functions.get_between(0x805000, 0x805660)}
    group(db, methods | constructors, str(BASE / 'npc_methods_raw.json'))
    incoming, consumers = [], set()
    for target in sorted(methods):
        pending, visited = [target], set()
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            for edge in db.xrefs.to_ea(current):
                owner = db.functions.get_at(edge.from_ea)
                final, chain = resolve(db, edge.from_ea)
                is_bridge = bool(chain) and final == target
                incoming.append(dict(target=hex(target), referenced=hex(current),
                                     site=hex(edge.from_ea), kind=int(edge.type),
                                     owner=hex(owner.start_ea) if owner else None,
                                     bridge=is_bridge))
                if is_bridge:
                    pending.append(edge.from_ea)
                elif owner and owner.start_ea not in methods:
                    consumers.add(owner.start_ea)
    group(db, consumers, str(BASE / 'npc_consumers_raw.json'))
    dependencies = set()
    for ea in methods:
        function = db.functions.get_at(ea)
        for chunk in db.functions.get_chunks(function):
            for ins in db.instructions.get_between(chunk.start_ea, chunk.end_ea):
                for edge in db.xrefs.from_ea(ins.ea):
                    if edge.type not in (16, 17):
                        continue
                    final, _ = resolve(db, edge.to_ea)
                    callee = db.functions.get_at(final)
                    if callee and callee.start_ea == final and final not in methods:
                        dependencies.add(final)
    group(db, dependencies, str(BASE / 'npc_dependencies_raw.json'))
    (BASE / 'npc_incoming.json').write_text(json.dumps(incoming, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(methods=len(methods), constructors=len(constructors), consumers=len(consumers),
                dependencies=len(dependencies), output=str(BASE))
