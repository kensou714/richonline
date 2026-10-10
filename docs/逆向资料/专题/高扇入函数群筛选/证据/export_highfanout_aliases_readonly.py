"""追踪 E9 别名后的调用边；只读 IDB，只写本专题第二份原证。"""
import importlib.util
import json
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils


HERE = Path(__file__).resolve().parent
TARGETS = (0x91F7E0, 0x9CA953, 0x9DB4B6, 0x85BB10)


def export(db):
    path = HERE / 'export_highfanout_readonly.py'
    spec = importlib.util.spec_from_file_location('highfanout_base', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base = json.loads((HERE / 'highfanout_raw.json').read_text(encoding='utf-8'))

    def resolve(ea):
        chain = []
        while ida_bytes.get_byte(ea) == 0xE9 and len(chain) < 16:
            assert ea not in chain, 'E9 cycle ' + hex(ea)
            raw = ida_bytes.get_bytes(ea, 5)
            assert raw and len(raw) == 5
            chain.append(ea)
            ea += 5 + struct.unpack('<i', raw[1:])[0]
        return ea, chain

    aliases = {target: [] for target in TARGETS}
    for ea in idautils.Functions():
        if ida_bytes.get_byte(ea) != 0xE9:
            continue
        terminal, chain = resolve(ea)
        if terminal in aliases:
            aliases[terminal].append((ea, chain))

    # 复用主原证的同一 PE/IDB 身份与磁盘字节；逐条标记调用别名。
    result = dict(schema=1, base_evidence='highfanout_raw.json',
                  disk_sha256=base['disk_sha256'],
                  idb_input_sha256=base['idb_input_sha256'],
                  targets=[])
    for target in TARGETS:
        entries = {target} | {ea for ea, _ in aliases[target]}
        direct = []
        for entry in sorted(entries):
            for xref in idautils.XrefsTo(entry, 0):
                owner = ida_funcs.get_func(xref.frm)
                direct.append(dict(site=hex(xref.frm), entry=hex(entry),
                                   owner=hex(owner.start_ea) if owner else None,
                                   xref_type=int(xref.type), iscode=bool(xref.iscode)))
        result['targets'].append(dict(va=hex(target),
                                      aliases=[dict(entry=hex(ea), chain=[hex(c) for c in chain])
                                               for ea, chain in sorted(aliases[target])],
                                      incoming=direct,
                                      totals=dict(entries=len(entries),
                                                  incoming=len(direct),
                                                  code_incoming=sum(x['iscode'] for x in direct),
                                                  nonfunction_sites=sum(x['iscode'] and not x['owner']
                                                                        for x in direct))))
    out = HERE / 'highfanout_aliases.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), targets=[dict(va=t['va'], **t['totals']) for t in result['targets']])
