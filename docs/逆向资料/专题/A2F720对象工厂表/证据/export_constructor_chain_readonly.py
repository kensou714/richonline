"""只读导出 856180 前置调用到 8563C0 的写表链。"""
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
        assert ida is not None and ida == disk, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    ida_hex=ida.hex(), disk_hex=disk.hex(), equal=True)

    def xrefs(ea):
        return [dict(from_va=hex(x.frm), type=int(x.type), iscode=bool(x.iscode),
                     owner=hex(f.start_ea) if (f := ida_funcs.get_func(x.frm)) else None)
                for x in idautils.XrefsTo(ea, 0)]

    f = ida_funcs.get_func(0x8563C0)
    assert f and f.start_ea == 0x8563C0
    chunks = [block(start, end - start) for start, end in idautils.Chunks(0x8563C0)]
    instructions = [dict(va=hex(ea), size=idc.get_item_size(ea),
                         hex=ida_bytes.get_bytes(ea, idc.get_item_size(ea)).hex(),
                         text=idc.generate_disasm_line(ea, 0) or '')
                    for start, end in idautils.Chunks(0x8563C0)
                    for ea in idautils.Heads(start, end)
                    if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]
    result = dict(schema=1, disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  function=dict(va='0x8563c0', name=idc.get_func_name(0x8563C0),
                                chunks=chunks, instructions=instructions,
                                xrefs=xrefs(0x8563C0)),
                  alias=dict(block=block(0x60810F, 5), xrefs=xrefs(0x60810F),
                             owner=hex(a.start_ea) if (a := ida_funcs.get_func(0x60810F)) else None),
                  table=dict(slot='0xa2f738', value=hex(idc.get_wide_dword(0xA2F738)),
                             xrefs=xrefs(0xA2F738)))
    path = HERE / 'constructor_chain.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(path), chunks=len(chunks), instructions=len(instructions))
