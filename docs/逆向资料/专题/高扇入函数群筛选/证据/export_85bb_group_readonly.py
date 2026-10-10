"""只读导出 85BB10 包装后的实现和高密度调用者。"""
import importlib.util
import json
import hashlib
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc


HERE = Path(__file__).resolve().parent
SELECTED = (0x85C710, 0x85EA60, 0x85FEA0, 0x860000, 0x85F190, 0x860370)


def export(db):
    raw = json.loads((HERE / 'highfanout_raw.json').read_text(encoding='utf-8'))
    alias = json.loads((HERE / 'highfanout_aliases.json').read_text(encoding='utf-8'))
    image = Path(raw['input']).read_bytes()
    assert hashlib.sha256(image).hexdigest() == raw['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, size):
        mapping = [(rva, off) for _, rva, count, off in sections
                   if base + rva <= ea and ea + size <= base + rva + count]
        assert len(mapping) == 1, hex(ea)
        rva, off = mapping[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        ida = ida_bytes.get_bytes(ea, size)
        assert ida and ida == disk, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    ida_hex=ida.hex(), disk_hex=disk.hex(), equal=True)

    def instructions(start, end):
        rows = []
        for ea in idautils.Heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                size = idc.get_item_size(ea)
                rows.append(dict(va=hex(ea), size=size,
                                 hex=ida_bytes.get_bytes(ea, size).hex(),
                                 text=idc.generate_disasm_line(ea, 0) or ''))
        return rows

    def function(ea):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks = []
        for start, end in idautils.Chunks(ea):
            chunks.append(identity(start, end - start))
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        return dict(va=hex(ea), end_va=hex(f.end_ea), name=idc.get_func_name(ea),
                    chunks=chunks,
                    instructions=[row for start, end in idautils.Chunks(ea)
                                  for row in instructions(start, end)],
                    pseudocode=pseudo, pseudocode_error=error)

    target = next(t for t in alias['targets'] if t['va'] == '0x85bb10')
    owners = {int(row['owner'], 16) for row in target['incoming'] if row['owner']}
    assert set(SELECTED[1:]) <= owners
    result = dict(schema=1, base_evidence=['highfanout_raw.json', 'highfanout_aliases.json'],
                  disk_sha256=raw['disk_sha256'],
                  idb_input_sha256=raw['idb_input_sha256'],
                  scope='完整选定函数及包装后实际实现；声明块逐块核对当前PE磁盘字节',
                  functions=[function(ea) for ea in SELECTED])
    out = HERE / '85bb_group_raw.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), functions=[f['va'] for f in result['functions']])
