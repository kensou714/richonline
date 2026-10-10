"""只读收集三个全局 WORD 和本地回调指针的交叉引用。"""
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
TARGETS = (0xA6779C, 0xA6779E, 0xA677A0, 0xACB864, 0xACB868)


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
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
        return dict(va=hex(ea), end=hex(ea + size), size=size, ida_hex=ida.hex(),
                    disk_hex=disk.hex(), equal=ida == disk,
                    sha256=hashlib.sha256(ida).hexdigest())

    def instruction(ea):
        size = idc.get_item_size(ea)
        assert size > 0 and ida_bytes.is_code(ida_bytes.get_full_flags(ea))
        return dict(va=hex(ea), size=size, hex=ida_bytes.get_bytes(ea, size).hex(),
                    text=idc.generate_disasm_line(ea, 0) or '')

    def window(site, owner):
        start = site
        end = site + idc.get_item_size(site)
        for _ in range(12):
            prev = idc.prev_head(start)
            f = ida_funcs.get_func(prev)
            if not f or f.start_ea != owner:
                break
            start = prev
        for _ in range(12):
            nxt = idc.next_head(end - 1)
            f = ida_funcs.get_func(nxt)
            if not f or f.start_ea != owner:
                break
            end = nxt + idc.get_item_size(nxt)
        rows = [instruction(ea) for ea in idautils.Heads(start, end)
                if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]
        return dict(site=hex(site), owner=hex(owner), block=identity(start, end - start),
                    instructions=rows, scope='仅交叉引用附近局部窗口')

    def undeclared_window(site):
        start = site
        end = site + idc.get_item_size(site)
        for _ in range(12):
            prev = idc.prev_head(start)
            if not ida_bytes.is_code(ida_bytes.get_full_flags(prev)) or ida_funcs.get_func(prev):
                break
            start = prev
        for _ in range(4):
            nxt = idc.next_head(end - 1)
            if not ida_bytes.is_code(ida_bytes.get_full_flags(nxt)) or ida_funcs.get_func(nxt):
                break
            end = nxt + idc.get_item_size(nxt)
        return dict(site=hex(site), owner=None, block=identity(start, end - start),
                    instructions=[instruction(ea) for ea in idautils.Heads(start, end)
                                  if ida_bytes.is_code(ida_bytes.get_full_flags(ea))],
                    scope='无IDA函数owner的局部代码窗口；不计入已声明函数')

    refs = []
    windows = []
    for target in TARGETS:
        for x in idautils.XrefsTo(target, 0):
            f = ida_funcs.get_func(x.frm)
            owner = f.start_ea if f else None
            row = dict(target=hex(target), site=hex(x.frm), owner=hex(owner) if owner else None,
                       iscode=bool(x.iscode), xref_type=int(x.type),
                       site_is_instruction=bool(ida_bytes.is_code(ida_bytes.get_full_flags(x.frm))))
            if row['site_is_instruction']:
                row['instruction'] = instruction(x.frm)
                row['bytes'] = identity(x.frm, row['instruction']['size'])
            refs.append(row)
            if target in TARGETS[3:] and row['site_is_instruction'] and owner is not None:
                windows.append(window(x.frm, owner))
            elif target in TARGETS[3:] and row['site_is_instruction']:
                windows.append(undeclared_window(x.frm))

    globals_ = [dict(target=hex(ea), bytes=identity(ea, 2)) for ea in TARGETS[:3]]
    for ea in TARGETS[3:]:
        globals_.append(dict(target=hex(ea),
                             idb_hex=(ida_bytes.get_bytes(ea, 4) or b'').hex(),
                             disk_status='PE .data 虚拟扩展区；无磁盘原字节'))
    result = dict(schema=4, subject='A6779C..A677A1 + ACB864/ACB868',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  globals=globals_, refs=refs, windows=windows,
                  note='只读IDA交叉引用；引用指令及三个WORD与当前PE比对；回调指针处未落盘。data xref 的 iscode 可为 false，另记 site_is_instruction')
    assert all(row['bytes']['equal'] for row in refs if row['site_is_instruction'])
    assert all(row['block']['equal'] for row in windows)
    assert all(row['bytes']['equal'] for row in globals_[:3])
    HERE.mkdir(parents=True, exist_ok=True)
    path = HERE / 'global_refs_raw.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(path), refs=len(refs), windows=len(windows),
                owners=len({row['owner'] for row in refs if row['owner']}),
                per_target={hex(ea): sum(row['target'] == hex(ea) for row in refs)
                            for ea in TARGETS})
