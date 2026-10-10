"""只读导出 82D820 的表项、构造和分配来源；不修改 IDB。"""
import hashlib
import json
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_nalt
import idautils
import idc


ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def block(ea, size):
        mapped = [(rva, off) for _, rva, raw, off in sections
                  if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(mapped) == 1, hex(ea)
        rva, off = mapped[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        ida = ida_bytes.get_bytes(ea, size)
        assert ida is not None and len(ida) == size and ida == disk, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    ida_hex=ida.hex(), disk_hex=disk.hex(), equal=True)

    def instructions(start, end):
        return [dict(va=hex(ea), size=idc.get_item_size(ea),
                     hex=ida_bytes.get_bytes(ea, idc.get_item_size(ea)).hex(),
                     text=idc.generate_disasm_line(ea, 0) or '')
                for ea in idautils.Heads(start, end)
                if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]

    def function(ea):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea
        chunks = [block(start, end - start) for start, end in idautils.Chunks(ea)]
        return dict(va=hex(ea), name=idc.get_func_name(ea), chunks=chunks,
                    instructions=[row for start, end in idautils.Chunks(ea)
                                  for row in instructions(start, end)])

    def xrefs(ea):
        return [dict(from_va=hex(x.frm), type=int(x.type), iscode=bool(x.iscode),
                     owner=hex(f.start_ea) if (f := ida_funcs.get_func(x.frm)) else None)
                for x in idautils.XrefsTo(ea, 0)]

    slot_start, slot_end = 0xA2F050, 0xA2F090
    slots = [dict(index=i, slot_va=hex(ea), target=hex(idc.get_wide_dword(ea)))
             for i, ea in enumerate(range(slot_start, slot_end, 4))]
    assert slots[2]['target'] == '0x609a05'
    assert ida_funcs.get_func(0x82D820) is None
    assert ida_funcs.get_func(0x82D864) is None
    result = dict(schema=1, disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  functions=[function(0x82CAD0), function(0x8553F0)],
                  table=dict(block=block(slot_start, slot_end - slot_start), slots=slots,
                             xrefs=xrefs(slot_start)),
                  aliases=[dict(block=block(ea, 5), xrefs=xrefs(ea))
                           for ea in (0x609A05, 0x609DC0)],
                  undeclared=dict(block=block(0x82D820, 0x99),
                                  instructions=instructions(0x82D820, 0x82D8B9),
                                  scope='未声明函数形代码；不得计作已声明函数'),
                  links=dict(table_slot=xrefs(0x609A05),
                             constructor=xrefs(0x82CAD0),
                             allocation=xrefs(0x8553F0)))
    path = HERE / 'table_provenance.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(path), functions=len(result['functions']),
                slots=len(slots), undeclared_instructions=len(result['undeclared']['instructions']))
