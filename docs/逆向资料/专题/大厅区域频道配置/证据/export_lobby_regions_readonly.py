"""只读导出大厅区域/频道配置函数原证；仅在本专题目录写 JSON。"""

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
TARGETS = (0x69EEE0, 0x69F750, 0x6A0130)
CONTEXT = (0x623030, 0x82C470, 0x87DFE0)


def run(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def block(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        idb = ida_bytes.get_bytes(ea, size)
        assert idb is not None and len(idb) == size, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    disk_hex=disk.hex(), idb_hex=idb.hex(),
                    disk_sha256=hashlib.sha256(disk).hexdigest(),
                    idb_sha256=hashlib.sha256(idb).hexdigest(), equal=disk == idb)

    def instructions(start, end):
        return [dict(va=hex(ea), size=idc.get_item_size(ea),
                     text=idc.generate_disasm_line(ea, 0) or '',
                     hex=ida_bytes.get_bytes(ea, idc.get_item_size(ea)).hex(),
                     data_refs=[hex(v) for v in idautils.DataRefsFrom(ea)],
                     code_refs=[hex(v) for v in idautils.CodeRefsFrom(ea, 0)])
                for ea in idautils.Heads(start, end)
                if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]

    def function(ea):
        func = ida_funcs.get_func(ea)
        assert func and func.start_ea == ea, hex(ea)
        chunks = [block(start, end - start) for start, end in idautils.Chunks(ea)]
        rows = [row for start, end in idautils.Chunks(ea)
                for row in instructions(start, end)]
        try:
            pseudocode, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        incoming = []
        for xref in idautils.XrefsTo(ea, 0):
            owner = ida_funcs.get_func(xref.frm)
            incoming.append(dict(site=hex(xref.frm),
                                 owner=hex(owner.start_ea) if owner else None,
                                 iscode=bool(xref.iscode), type=int(xref.type)))
        return dict(va=hex(ea), end_va=hex(func.end_ea), name=idc.get_func_name(ea),
                    chunks=chunks, instructions=rows, pseudocode=pseudocode,
                    pseudocode_error=error, incoming=incoming)

    def call_window(site, owner_ea):
        start = site
        end = site + idc.get_item_size(site)
        for _ in range(16):
            prev = idc.prev_head(start)
            owner = ida_funcs.get_func(prev)
            if not owner or owner.start_ea != owner_ea:
                break
            start = prev
        for _ in range(10):
            nxt = idc.next_head(end - 1)
            owner = ida_funcs.get_func(nxt)
            if not owner or owner.start_ea != owner_ea:
                break
            end = nxt + idc.get_item_size(nxt)
        return dict(site=hex(site), owner=hex(owner_ea), block=block(start, end - start),
                    instructions=instructions(start, end),
                    scope='局部调用窗口，不能单独证明完整调用者语义')

    functions = [function(ea) for ea in TARGETS]
    target_set = set(TARGETS)
    windows = [call_window(int(ref['site'], 16), int(ref['owner'], 16))
               for item in functions for ref in item['incoming']
               if ref['iscode'] and ref['owner']
               and int(ref['owner'], 16) not in target_set]
    context = []
    for ea in CONTEXT:
        func = ida_funcs.get_func(ea)
        if not func or func.start_ea != ea:
            context.append(dict(va=hex(ea), error='not a function entry'))
            continue
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        context.append(dict(va=hex(ea), name=idc.get_func_name(ea),
                            pseudocode=pseudo, pseudocode_error=error,
                            note='上下文反编译，仅作线索；未导出完整字节'))
    result = dict(schema=1, subject='大厅区域频道配置',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  image_base=hex(base), functions=functions, windows=windows,
                  context=context,
                  scope='IDA 只读导出；目标函数全块和调用现场窗口同当前磁盘 PE 逐字节对照')
    out = HERE / 'lobby_regions_ida_raw.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), disk_sha256=result['disk_sha256'],
                idb_input_sha256=result['idb_input_sha256'],
                function_count=len(functions), window_count=len(windows),
                target_chunks_equal=all(chunk['equal'] for f in functions
                                        for chunk in f['chunks']),
                windows_equal=all(w['block']['equal'] for w in windows))
