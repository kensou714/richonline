"""只读导出四个高扇入候选与调用现场；仅写本专题证据文件。"""
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
TARGETS = (0x91F7E0, 0x9CA953, 0x9DB4B6, 0x85BB10)


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, size):
        mapping = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(mapping) == 1, hex(ea)
        rva, off = mapping[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        ida = ida_bytes.get_bytes(ea, size)
        assert ida is not None and len(ida) == size, hex(ea)
        return dict(va=hex(ea), end=hex(ea + size), size=size,
                    ida_hex=ida.hex(), disk_hex=disk.hex(),
                    sha256=hashlib.sha256(ida).hexdigest(), equal=ida == disk)

    def instructions(start, end):
        rows = []
        for ea in idautils.Heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                size = idc.get_item_size(ea)
                rows.append(dict(va=hex(ea), size=size,
                                 hex=ida_bytes.get_bytes(ea, size).hex(),
                                 text=idc.generate_disasm_line(ea, 0) or ''))
        return rows

    def function(ea, role):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks = [identity(start, end - start) for start, end in idautils.Chunks(ea)]
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        return dict(va=hex(ea), end_va=hex(f.end_ea), name=idc.get_func_name(ea),
                    role=role, chunks=chunks,
                    instructions=[row for start, end in idautils.Chunks(ea)
                                  for row in instructions(start, end)],
                    pseudocode=pseudo, pseudocode_error=error)

    def window(site, owner):
        start, end = site, site + idc.get_item_size(site)
        for _ in range(14):
            prev = idc.prev_head(start)
            f = ida_funcs.get_func(prev)
            if not f or f.start_ea != owner:
                break
            start = prev
        for _ in range(5):
            nxt = idc.next_head(end - 1)
            f = ida_funcs.get_func(nxt)
            if not f or f.start_ea != owner:
                break
            end = nxt + idc.get_item_size(nxt)
        return dict(owner=hex(owner), site=hex(site),
                    block=identity(start, end - start),
                    instructions=instructions(start, end),
                    scope='局部调用窗口；不代表完整调用者语义')

    result = dict(schema=1, input=str(ROOT / 'RnClient.exe'),
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  targets=[], note='IDB只读；函数块与调用窗口逐块对照当前PE磁盘字节')
    for target in TARGETS:
        incoming = []
        for xref in idautils.XrefsTo(target, 0):
            owner = ida_funcs.get_func(xref.frm)
            incoming.append(dict(site=hex(xref.frm),
                                 owner=hex(owner.start_ea) if owner else None,
                                 xref_type=int(xref.type), iscode=bool(xref.iscode)))
        windows = [window(int(row['site'], 16), int(row['owner'], 16))
                   for row in incoming if row['iscode'] and row['owner']]
        result['targets'].append(dict(va=hex(target), function=function(target, 'target'),
                                      incoming=incoming, windows=windows))
    assert all(block['equal'] for t in result['targets']
               for block in t['function']['chunks'])
    assert all(row['block']['equal'] for t in result['targets']
               for row in t['windows'])
    HERE.mkdir(parents=True, exist_ok=True)
    path = HERE / 'highfanout_raw.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(path), targets=[dict(va=t['va'], incoming=len(t['incoming']),
                                          windows=len(t['windows']))
                                    for t in result['targets']],
                disk_sha256=result['disk_sha256'])
