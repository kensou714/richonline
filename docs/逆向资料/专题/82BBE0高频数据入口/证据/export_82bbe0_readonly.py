"""只读导出82BBE0及调用现场；只写本专题证据文件。"""
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
MAIN = 0x82BBE0
SELECTED = (0x82EDD0, 0x840230, 0x846AB0)


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]
    thunks = {}

    def identity(ea, size):
        mapping = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(mapping) == 1, hex(ea)
        rva, off = mapping[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + size]
        ida = ida_bytes.get_bytes(ea, size)
        assert ida is not None and len(ida) == size, hex(ea)
        return dict(va=hex(ea), end=hex(ea + size), size=size, ida_hex=ida.hex(),
                    disk_hex=disk.hex(), sha256=hashlib.sha256(ida).hexdigest(),
                    equal=ida == disk)

    def resolve(ea, record=True):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9:
            assert ea not in seen, 'E9 cycle ' + hex(ea)
            seen.add(ea)
            target = ea + 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
            if record:
                thunks[hex(ea)] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

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
        ins = [row for start, end in idautils.Chunks(ea)
               for row in instructions(start, end)]
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        return dict(va=hex(ea), name=idc.get_func_name(ea), role=role,
                    chunks=chunks, instructions=ins, pseudocode=pseudo,
                    pseudocode_error=error)

    def window(site, owner):
        start, end = site, site + idc.get_item_size(site)
        for _ in range(16):
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
        return dict(owner=hex(owner), site=hex(site), block=identity(start, end - start),
                    instructions=instructions(start, end),
                    scope='调用前后局部导航，非完整调用者审阅')

    entries = {MAIN}
    for ea in idautils.Functions():
        if ida_bytes.get_byte(ea) == 0xE9 and resolve(ea, False) == MAIN:
            entries.add(ea)
    incoming = []
    for entry in sorted(entries):
        if entry != MAIN:
            resolve(entry)
        for xref in idautils.XrefsTo(entry, 0):
            owner = ida_funcs.get_func(xref.frm)
            incoming.append(dict(site=hex(xref.frm), entry=hex(entry),
                                 owner=hex(owner.start_ea) if owner else None,
                                 xref_type=int(xref.type), iscode=bool(xref.iscode)))
    owners = {int(row['owner'], 16) for row in incoming if row['iscode'] and row['owner']}
    assert set(SELECTED) <= owners, '代表调用者不在当前可见入边中'
    windows = [window(int(row['site'], 16), int(row['owner'], 16))
               for row in incoming if row['iscode'] and row['owner']
               and int(row['owner'], 16) not in entries]
    undeclared = []
    for row in incoming:
        if row['iscode'] and row['owner'] is None:
            site = int(row['site'], 16)
            assert site == 0x82D864, '新未声明入边须重新划定范围'
            start, end = 0x82D820, 0x82D8B9
            assert start <= site < end and ida_funcs.get_func(site) is None
            undeclared.append(dict(site=row['site'], block=identity(start, end - start),
                                   instructions=instructions(start, end),
                                   scope='未声明函数形代码候选；仅完整字节与IDA已识别指令，未计入函数审阅'))
    result = dict(schema=1, subject=hex(MAIN), input=str(ROOT / 'RnClient.exe'),
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  functions=[function(MAIN, 'owned_main')]
                            + [function(ea, 'caller_context') for ea in SELECTED],
                  entries=[hex(ea) for ea in sorted(entries)],
                  thunks=thunks, incoming=incoming, windows=windows,
                  undeclared=undeclared,
                  selected_callers=[hex(ea) for ea in SELECTED],
                  note='IDB仅用于取证；完整块与当前PE磁盘字节逐块比对；未修改EXE或IDB')
    assert all(block['equal'] for f in result['functions'] for block in f['chunks'])
    assert all(row['block']['equal'] for row in windows)
    assert all(row['block']['equal'] for row in undeclared)
    assert all(row['equal'] for row in thunks.values())
    HERE.mkdir(parents=True, exist_ok=True)
    path = HERE / '82bbe0_raw.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(path), entries=len(entries), incoming=len(incoming),
                windows=len(windows), undeclared=len(undeclared),
                functions=len(result['functions']),
                disk_sha256=result['disk_sha256'])
