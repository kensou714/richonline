"""只读导出 4042 附属对象构造与文本写入证据；只写本目录 JSON。"""
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
TARGETS = (0x7FD7F0, 0x640C90, 0x640D60, 0x6629D0)
JUMPS = (0x60BA62, 0x60A536, 0x60968B)


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

    def instructions(start, end):
        return [dict(va=hex(ea), size=idc.get_item_size(ea),
                     text=idc.generate_disasm_line(ea, 0) or '',
                     hex=ida_bytes.get_bytes(ea, idc.get_item_size(ea)).hex())
                for ea in idautils.Heads(start, end)
                if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]

    def function(ea):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks = [identity(start, end - start) for start, end in idautils.Chunks(ea)]
        rows = [row for start, end in idautils.Chunks(ea)
                for row in instructions(start, end)]
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        return dict(va=hex(ea), end_va=hex(f.end_ea), name=idc.get_func_name(ea),
                    chunks=chunks, instructions=rows, pseudocode=pseudo,
                    pseudocode_error=error)

    def window(site, owner):
        start, end = site, site + idc.get_item_size(site)
        for _ in range(12):
            prev = idc.prev_head(start)
            f = ida_funcs.get_func(prev)
            if not f or f.start_ea != owner:
                break
            start = prev
        for _ in range(6):
            nxt = idc.next_head(end - 1)
            f = ida_funcs.get_func(nxt)
            if not f or f.start_ea != owner:
                break
            end = nxt + idc.get_item_size(nxt)
        return dict(site=hex(site), owner=hex(owner), block=identity(start, end - start),
                    instructions=instructions(start, end),
                    scope='调用现场局部窗口，不代表完整调用者语义')

    jump_rows = []
    for ea in JUMPS:
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea and ida_bytes.get_byte(ea) == 0xE9, hex(ea)
        target = ea + 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
        jump_rows.append(dict(**identity(ea, 5), target=hex(target)))

    entry_set = set(TARGETS) | set(JUMPS)
    incoming = []
    for entry in sorted(entry_set):
        for xref in idautils.XrefsTo(entry, 0):
            owner = ida_funcs.get_func(xref.frm)
            incoming.append(dict(site=hex(xref.frm), entry=hex(entry),
                                 owner=hex(owner.start_ea) if owner else None,
                                 iscode=bool(xref.iscode), xref_type=int(xref.type)))
    windows = [window(int(row['site'], 16), int(row['owner'], 16))
               for row in incoming if row['iscode'] and row['owner']
               and int(row['owner'], 16) not in entry_set]
    result = dict(schema=1, subject='4042附属对象文本边界',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  functions=[function(ea) for ea in TARGETS], jumps=jump_rows,
                  incoming=incoming, windows=windows,
                  note='只读 IDA 导出；完整函数块与局部窗口逐块同当前磁盘 PE 比对')
    assert all(c['equal'] for f in result['functions'] for c in f['chunks'])
    assert all(j['equal'] for j in jump_rows)
    assert all(w['block']['equal'] for w in windows)
    out = HERE / '4042_child_raw.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), functions=len(result['functions']), jumps=len(jump_rows),
                incoming=len(incoming), windows=len(windows),
                disk_sha256=result['disk_sha256'])
