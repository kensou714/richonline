"""只读采集宽度定位与相关字段入口；不修改 EXE、资源或 IDB。"""
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
MAIN = 0x90CE80
SEEDS = [MAIN, 0x924FC0, 0x8E1620, 0x8E1800, 0x8E0A00, 0x8E0AA0,
         0x90D120, 0x90D310, 0x8F4B10, 0x8F5300, 0x90BFF0, 0x8FA130]


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    optional = struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, pe + 24 + optional + 40 * n + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]
    thunks = {}

    def identity(ea, size):
        candidates = [(rva, off) for _, rva, raw, off in sections
                      if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(candidates) == 1
        rva, off = candidates[0]
        pos = off + ea - base - rva
        disk = image[pos:pos + size]
        raw = ida_bytes.get_bytes(ea, size)
        assert raw is not None and len(raw) == size
        return dict(va=hex(ea), size=size, end=hex(ea + size), ida_hex=raw.hex(),
                    disk_hex=disk.hex(), sha256=hashlib.sha256(raw).hexdigest(), equal=raw == disk)

    def resolve(ea, record=True):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9:
            assert ea not in seen
            seen.add(ea)
            target = ea + 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
            if record:
                thunks[ea] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

    def instructions(start, end):
        rows = []
        for ea in idautils.Heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                size = idc.get_item_size(ea)
                rows.append(dict(va=hex(ea), size=size, hex=ida_bytes.get_bytes(ea, size).hex(),
                                 text=idc.generate_disasm_line(ea, 0) or ''))
        return rows

    def function(ea):
        owner = ida_funcs.get_func(ea)
        assert owner and owner.start_ea == ea
        chunks, assembly, calls, indirect = [], [], [], []
        for start, end in idautils.Chunks(ea):
            chunks.append(identity(start, end - start))
            assembly.extend(instructions(start, end))
            for site in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(site)):
                    continue
                if idc.print_insn_mnem(site) not in ('call', 'jmp'):
                    continue
                if idc.get_operand_type(site, 0) in (idc.o_near, idc.o_far):
                    target = idc.get_operand_value(site, 0)
                    calls.append(dict(site=hex(site), target=hex(target), resolved=hex(resolve(target))))
                else:
                    indirect.append(dict(site=hex(site), text=idc.generate_disasm_line(site, 0) or ''))
        try:
            pseudocode, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        refs = []
        for x in idautils.XrefsTo(ea, 0):
            caller = ida_funcs.get_func(x.frm)
            refs.append(dict(site=hex(x.frm), type=int(x.type), iscode=bool(x.iscode),
                             caller=hex(caller.start_ea) if caller else None))
        return dict(va=hex(ea), name=idc.get_func_name(ea), chunks=chunks,
                    instructions=assembly, calls=calls, indirect=indirect, references=refs,
                    pseudocode=pseudocode, pseudocode_error=error)

    entries = {MAIN}
    for ea in idautils.Functions():
        if ida_bytes.get_byte(ea) == 0xE9 and resolve(ea, False) == MAIN:
            entries.add(ea)
    incoming = []
    for entry in sorted(entries):
        if entry != MAIN:
            resolve(entry)
        for x in idautils.XrefsTo(entry, 0):
            owner = ida_funcs.get_func(x.frm)
            caller = owner.start_ea if owner else None
            if caller in entries - {MAIN}:
                continue
            incoming.append(dict(site=hex(x.frm), entry=hex(entry), type=int(x.type),
                                 iscode=bool(x.iscode), caller=hex(caller) if caller else None))
    navigation = []
    for row in incoming:
        if not row['iscode'] or not row['caller']:
            continue
        site = int(row['site'], 16)
        start, end = site, site + idc.get_item_size(site)
        for _ in range(24):
            previous = idc.prev_head(start)
            owner = ida_funcs.get_func(previous)
            if not owner or hex(owner.start_ea) != row['caller']:
                break
            start = previous
        for _ in range(12):
            following = idc.next_head(end - 1)
            owner = ida_funcs.get_func(following)
            if not owner or hex(owner.start_ea) != row['caller']:
                break
            end = following + idc.get_item_size(following)
        navigation.append(dict(incoming=row, window=identity(start, end - start),
                               instructions=instructions(start, end), scope='调用参数局部窗口，非整个owner语义恢复'))
    functions = [function(ea) for ea in SEEDS]
    result = dict(schema=1, date='2026-10-10', input=str(ROOT / 'RnClient.exe'),
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  main=hex(MAIN), entries=[hex(ea) for ea in sorted(entries)],
                  functions=functions, incoming=incoming, caller_navigation=navigation,
                  thunks=[thunks[ea] for ea in sorted(thunks)],
                  scope='显式选定12入口；调用者局部导航；已有生命周期和列表函数优先复用，不作全排版引擎声明')
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / 'width_position.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                            encoding='utf-8', newline='\n')
    return dict(path=str(HERE / 'width_position.json'), functions=len(functions),
                thunks=len(thunks), incoming=len(incoming), navigation=len(navigation),
                all_equal=all(c['equal'] for f in functions for c in f['chunks'])
                and all(t['equal'] for t in thunks.values()) and all(n['window']['equal'] for n in navigation))
