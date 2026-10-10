"""只读导出 A2F720 静态表窗口和对象工厂链；不修改 IDB。"""
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
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
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
        assert f and f.start_ea == ea, hex(ea)
        chunks = [block(start, end - start) for start, end in idautils.Chunks(ea)]
        return dict(va=hex(ea), name=idc.get_func_name(ea), chunks=chunks,
                    instructions=[row for start, end in idautils.Chunks(ea)
                                  for row in instructions(start, end)])

    def xrefs(ea):
        return [dict(from_va=hex(x.frm), type=int(x.type), iscode=bool(x.iscode),
                     owner=hex(f.start_ea) if (f := ida_funcs.get_func(x.frm)) else None)
                for x in idautils.XrefsTo(ea, 0)]

    owner = ida_funcs.get_func(0x8560BE)
    assert owner and owner.start_ea <= 0x8560BE < owner.end_ea
    window_start, window_end = 0xA2F720, 0xA2F7A0
    slots = [dict(index=i, slot_va=hex(ea), target=hex(idc.get_wide_dword(ea)),
                  name=idc.get_name(ea) or '',
                  item_head=hex(idc.get_item_head(ea)), item_size=idc.get_item_size(ea),
                  xrefs=xrefs(ea))
             for i, ea in enumerate(range(window_start, window_end, 4))]
    assert slots[4]['target'] == '0x60ecc6'
    result = dict(schema=1, scope='128 字节表窗口；不预设完整表界',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  function=function(owner.start_ea),
                  adjacent_function=function(0x856180),
                  write_site=dict(va='0x8560be',
                                  owner=hex(owner.start_ea),
                                  text=idc.generate_disasm_line(0x8560BE, 0) or ''),
                  table=dict(block=block(window_start, window_end - window_start),
                             slots=slots, xrefs=xrefs(window_start)),
                  alias=dict(block=block(0x60ECC6, 5), xrefs=xrefs(0x60ECC6),
                             owner=hex(f.start_ea) if (f := ida_funcs.get_func(0x60ECC6)) else None),
                  factory_alias=dict(block=block(0x60EFB4, 5), xrefs=xrefs(0x60EFB4),
                                     owner=hex(f.start_ea) if (f := ida_funcs.get_func(0x60EFB4)) else None),
                  links=dict(factory=xrefs(owner.start_ea),
                             adjacent=xrefs(0x856180),
                             allocator=xrefs(0x8553F0), constructor=xrefs(0x82CAD0),
                             final_table=xrefs(0xA2F050)))
    path = HERE / 'a2f720_raw.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(path), owner=hex(owner.start_ea),
                chunks=len(result['function']['chunks']),
                adjacent_chunks=len(result['adjacent_function']['chunks']), slots=len(slots))
