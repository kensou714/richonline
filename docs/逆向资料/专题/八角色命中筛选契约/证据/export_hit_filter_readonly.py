"""只读导出八角色命中筛选及一层依赖，仅写本专题原证。"""
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
MAIN = 0x64FF10
KNOWN = [0x63F4A0, 0x63EF50, 0x63EF80, 0x63EFB0, 0x7C0C00, 0x63F470, 0x7F7400,
         0x63E0E0, 0x63E000, 0x63E990]


def export(db, selected_callers=()):
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
        assert ida is not None and len(ida) == size
        return dict(va=hex(ea), size=size, ida_hex=ida.hex(), disk_hex=disk.hex(),
                    sha256=hashlib.sha256(ida).hexdigest(), equal=ida == disk)

    def resolve(ea, record=True):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9:
            assert ea not in seen, 'E9 cycle ' + hex(ea)
            seen.add(ea)
            target = ea + 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
            if record:
                thunks[ea] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

    def near_calls(ea):
        rows = []
        for start, end in idautils.Chunks(ea):
            for site in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(site)):
                    continue
                if idc.print_insn_mnem(site) in ('call', 'jmp') and idc.get_operand_type(site, 0) in (idc.o_near, idc.o_far):
                    target = idc.get_operand_value(site, 0)
                    rows.append(dict(site=hex(site), target=hex(target), resolved=hex(resolve(target)),
                                     name=idc.get_name(target)))
        return rows

    entries = {MAIN}
    for ea in idautils.Functions():
        if ida_bytes.get_byte(ea) == 0xE9 and resolve(ea, False) == MAIN:
            entries.add(ea)
    incoming, callers = [], set()
    for entry in sorted(entries):
        if entry != MAIN:
            resolve(entry)
        for xref in idautils.XrefsTo(entry, 0):
            owner = ida_funcs.get_func(xref.frm)
            caller = owner.start_ea if owner else None
            if caller in entries:
                continue
            incoming.append(dict(site=hex(xref.frm), entry=hex(entry), type=int(xref.type),
                                 iscode=bool(xref.iscode), caller=hex(caller) if caller else None))
            if xref.iscode and caller is not None:
                callers.add(caller)
    main_calls = near_calls(MAIN)
    dependencies = set(KNOWN)
    for call in main_calls:
        f = ida_funcs.get_func(int(call['resolved'], 16))
        if f and f.start_ea == int(call['resolved'], 16) and f.start_ea != MAIN:
            dependencies.add(f.start_ea)
    assert len(dependencies) <= 24, '依赖数量异常，先人工确定范围'
    selected_callers = set(selected_callers)
    assert selected_callers <= callers, '指定的调用者不在当前可见入边中'
    assert len(selected_callers) <= 6, '完整调用者导出限六个，需保持有限专题'

    def navigation(row):
        site = int(row['site'], 16)
        start, end = site, site + idc.get_item_size(site)
        # 局部窗口只用来选择进一步审阅的owner，不冒充完整函数块。
        for _ in range(32):
            previous = idc.prev_head(start)
            owner = ida_funcs.get_func(previous)
            if not owner or hex(owner.start_ea) != row['caller']:
                break
            start = previous
        for _ in range(10):
            following = idc.next_head(end - 1)
            owner = ida_funcs.get_func(following)
            if not owner or hex(owner.start_ea) != row['caller']:
                break
            end = following + idc.get_item_size(following)
        instructions = []
        for ea in idautils.Heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                size = idc.get_item_size(ea)
                instructions.append(dict(va=hex(ea), size=size, hex=ida_bytes.get_bytes(ea, size).hex(),
                                         text=idc.generate_disasm_line(ea, 0) or ''))
        return dict(incoming=row, window=identity(start, end - start), instructions=instructions,
                    scope='局部调用参数导航，非完整函数审阅')

    def function(ea, role):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks, instructions, indirect = [], [], []
        for start, end in idautils.Chunks(ea):
            chunks.append(dict(identity(start, end - start), end=hex(end)))
            for site in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(site)):
                    continue
                size = idc.get_item_size(site)
                instructions.append(dict(va=hex(site), size=size, hex=ida_bytes.get_bytes(site, size).hex(),
                                         text=idc.generate_disasm_line(site, 0) or ''))
                if idc.print_insn_mnem(site) in ('call', 'jmp') and idc.get_operand_type(site, 0) not in (idc.o_near, idc.o_far):
                    indirect.append(dict(site=hex(site), text=idc.generate_disasm_line(site, 0) or ''))
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        return dict(va=hex(ea), name=idc.get_func_name(ea), role=role, chunks=chunks,
                    instructions=instructions, calls=near_calls(ea), indirect=indirect,
                    pseudocode=pseudo, pseudocode_error=error)

    functions = [function(MAIN, 'owned_main')]
    functions += [function(ea, 'dependency_pending_review') for ea in sorted(dependencies)]
    contexts = [function(ea, 'caller_context_only') for ea in sorted(selected_callers - {MAIN} - dependencies)]
    navigation_rows = [navigation(row) for row in incoming if row['iscode'] and row['caller']]
    result = dict(schema=1, date='2026-10-10', input=str(ROOT / 'RnClient.exe'),
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  scope=dict(main=hex(MAIN), dependencies=[hex(x) for x in sorted(dependencies)],
                             entries=[hex(x) for x in sorted(entries)],
                             selected_callers=[hex(x) for x in sorted(selected_callers)],
                             policy='一层直接依赖、全部可见入边局部导航与至多六个明确选择的完整调用者；已有状态函数只复用'),
                  functions=functions, contexts=contexts, incoming=incoming,
                  caller_navigation=navigation_rows,
                  thunks=[thunks[ea] for ea in sorted(thunks)],
                  limitation='静态可见xref不能证明覆盖全部间接调用者；不修改EXE/资源/IDB')
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / 'hit_filter.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                        encoding='utf-8', newline='\n')
    return dict(path=str(HERE / 'hit_filter.json'), functions=len(functions), contexts=len(contexts),
                incoming=incoming, dependencies=result['scope']['dependencies'],
                all_equal=all(c['equal'] for f in functions + contexts for c in f['chunks'])
                          and all(t['equal'] for t in result['thunks']))
