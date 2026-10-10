"""固定七种子只读导出；待父级冻结上一批后持租约执行，不自动扩展依赖。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SEEDS = (0x7FDE40, 0x727A50, 0x7D7EB0, 0x7D7F00, 0x7D02B0, 0x7D03C0, 0x727E00)
REUSE = (
    ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', (0x628D20, 0x623EE0)),
    ('专题/事件文字记录器/证据/shutdown.json', (0x624080,)),
)


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 60)[0]
    base = struct.unpack_from('<I', image, pe+52)[0]
    start = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, start+40*i+8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]
    bridges = {}

    def identity(ea, size):
        data = ida_bytes.get_bytes(ea, size)
        assert data is not None, hex(ea)
        matches = [(rva, raw_at) for _, rva, raw_size, raw_at in sections
                   if 0 <= ea-base-rva and ea-base-rva+size <= raw_size]
        assert len(matches) <= 1
        original = None
        if matches:
            rva, raw_at = matches[0]
            original = image[raw_at+ea-base-rva:raw_at+ea-base-rva+size]
            assert original == data, hex(ea)
        return dict(va=hex(ea), size=size, idb_hex=data.hex(),
                    disk_hex=original.hex() if original is not None else None,
                    matching=data==original if original is not None else None, disk_backed=original is not None)

    def resolve(ea):
        seen = []
        while ea not in seen and len(seen)<16:
            raw = ida_bytes.get_bytes(ea, 5)
            if raw is None or raw[0] != 0xE9:
                break
            seen.append(ea)
            target = ea+5+struct.unpack_from('<i', raw, 1)[0]
            bridges[hex(ea)] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea, seen

    def incoming(ea):
        pending, visited, rows = [ea], set(), []
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            for x in idautils.XrefsTo(target, 0):
                owner = ida_funcs.get_func(x.frm)
                rows.append(dict(site=hex(x.frm), target=hex(target), iscode=bool(x.iscode), kind=int(x.type),
                                 owner=hex(owner.start_ea) if owner else None,
                                 text=idc.generate_disasm_line(x.frm, 0) or ''))
                if x.iscode:
                    endpoint, chain = resolve(x.frm)
                    if chain and endpoint==target:
                        pending.append(x.frm)
        return rows

    covered = {int(row['va'],16): row['evidence'] for row in
               json.loads((DOCS/'全量分析/evidence_coverage.json').read_bytes())['functions']}
    fresh = [ea for ea in SEEDS if ea not in covered]
    reused, sources = [], []
    for relative, addresses in REUSE:
        raw = (DOCS/relative).read_bytes()
        functions = json.loads(raw)['functions']
        lookup = {int(row['va'],16): row for row in functions}
        digest = hashlib.sha256(raw).hexdigest()
        for ea in addresses:
            assert ea in lookup, (relative, hex(ea))
            reused.append(dict(va=hex(ea), source=relative, source_sha256=digest, record=lookup[ea]))
        sources.append(dict(path=relative, sha256=digest))
    calls, data_refs, strings, rejected = [], [], {}, {}
    for ea in SEEDS:
        function = ida_funcs.get_func(ea)
        assert function and function.start_ea==ea, hex(ea)
        for chunk_start, chunk_end in idautils.Chunks(ea):
            for head in idautils.Heads(chunk_start, chunk_end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                    continue
                for x in idautils.XrefsFrom(head, 0):
                    if x.iscode and int(x.type) in (16,17):
                        target, chain = resolve(x.to)
                        calls.append(dict(owner=hex(ea), site=hex(head), target=hex(x.to),
                                          implementation=hex(target), thunks=[hex(t) for t in chain],
                                          reuse_sources=covered.get(target, [])))
                    elif not x.iscode:
                        data_refs.append(dict(owner=hex(ea), site=hex(head), target=hex(x.to), kind=int(x.type),
                                              text=idc.generate_disasm_line(head, 0) or ''))
                        value = idc.get_strlit_contents(x.to, -1, idc.STRTYPE_C)
                        if value is not None:
                            row = dict(identity(x.to, len(value)+1), value_hex=value.hex())
                            if bytes.fromhex(row['idb_hex'])==value+b'\0':
                                strings[hex(x.to)] = row
                            else:
                                rejected[hex(x.to)] = dict(row, reason='IDA候选末字节非NUL，不认定C串')
    shared = runpy.run_path(str(DOCS/'全量分析/export_function_group.py'))
    summary = shared['export_group'](db, fresh, str(HERE/'plusprize_raw.json'))
    assert not summary['function_mismatches'] and not summary['thunk_mismatches']
    context = dict(schema=1, scope='固定七种子与真实引用；727E00归道具对象，候选与导出不等于已审阅',
                   disk_sha256=hashlib.sha256(image).hexdigest(), seeds=[hex(ea) for ea in SEEDS],
                   fresh=[hex(ea) for ea in fresh], covered_seeds=[dict(va=hex(ea), sources=covered[ea]) for ea in SEEDS if ea in covered],
                   reused_functions=reused, reuse_sources=sources, calls=calls, data_references=data_refs,
                   strings=list(strings.values()), rejected_string_candidates=list(rejected.values()),
                   incoming={hex(ea): incoming(ea) for ea in (*SEEDS,0x628D20)},
                   singleton=dict(identity(0xA76708,4), incoming=incoming(0xA76708)))
    context['bridges'] = list(bridges.values())
    (HERE/'plusprize_context.json').write_text(json.dumps(context,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(summary, reused=len(reused), bridges=len(bridges), data_references=len(data_refs))
