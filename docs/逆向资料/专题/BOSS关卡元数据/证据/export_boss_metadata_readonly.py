"""只读导出 0x8103B0 BOSS/关卡元数据候选及直接边界。只写本专题 JSON。"""
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
TARGETS = (0x810360, 0x8103B0, 0x810D20)


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        idb = ida_bytes.get_bytes(ea, size)
        assert idb is not None and len(idb) == size, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    idb_hex=idb.hex(), disk_hex=disk.hex(),
                    sha256=hashlib.sha256(idb).hexdigest(), equal=idb == disk)

    def function(ea):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks = [identity(start, end - start) for start, end in idautils.Chunks(ea)]
        instructions = []
        outgoing = []
        for start, end in idautils.Chunks(ea):
            for head in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                    continue
                size = idc.get_item_size(head)
                instructions.append(dict(va=hex(head), size=size,
                                         text=idc.generate_disasm_line(head, 0) or '',
                                         hex=ida_bytes.get_bytes(head, size).hex()))
                for x in idautils.XrefsFrom(head, 0):
                    if x.iscode and f.start_ea <= x.to < f.end_ea:
                        continue
                    outgoing.append(dict(site=hex(head), target=hex(x.to),
                                         target_name=idc.get_name(x.to),
                                         iscode=bool(x.iscode), kind=int(x.type)))
        incoming = []
        for x in idautils.XrefsTo(ea, 0):
            owner = ida_funcs.get_func(x.frm)
            incoming.append(dict(site=hex(x.frm), owner=hex(owner.start_ea) if owner else None,
                                 iscode=bool(x.iscode), kind=int(x.type)))
        try:
            pseudocode, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        return dict(va=hex(ea), end_va=hex(f.end_ea), name=idc.get_func_name(ea),
                    chunks=chunks, instructions=instructions,
                    incoming=incoming, outgoing=outgoing,
                    pseudocode=pseudocode, pseudocode_error=error)

    result = dict(schema=1, subject='0x8103B0 BOSS/关卡元数据候选',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  functions=[function(ea) for ea in TARGETS],
                  note='只读 IDA 导出；完整函数块逐块同当前磁盘 PE 比对。邻接函数仅作边界。')
    assert all(chunk['equal'] for row in result['functions'] for chunk in row['chunks'])
    out = HERE / 'boss_metadata_raw.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), functions=len(result['functions']),
                disk_sha256=result['disk_sha256'],
                instruction_counts=[len(row['instructions']) for row in result['functions']])
