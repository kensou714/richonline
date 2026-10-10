"""只读导出6FA控件外层明确入口；8E底层由并行专题负责。仅写本专题JSON。"""
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
MAIN = 0x6FA8E0


def export(db, selected_functions=(), selected_sites=()):
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
        content = image[off + ea - base - rva:off + ea - base - rva + size]
        ida = ida_bytes.get_bytes(ea, size)
        assert ida is not None and len(ida) == size
        return dict(va=hex(ea), size=size, ida_hex=ida.hex(), disk_hex=content.hex(),
                    sha256=hashlib.sha256(ida).hexdigest(), equal=ida == content)

    def resolve(ea, record=True):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9:
            assert ea not in seen, hex(ea)
            seen.add(ea)
            target = ea + 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
            if record:
                thunks[ea] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

    def near_calls(ea):
        calls = []
        for start, end in idautils.Chunks(ea):
            for site in idautils.Heads(start, end):
                if (ida_bytes.is_code(ida_bytes.get_full_flags(site))
                        and idc.print_insn_mnem(site) in ('call', 'jmp')
                        and idc.get_operand_type(site, 0) in (idc.o_near, idc.o_far)):
                    target = idc.get_operand_value(site, 0)
                    calls.append(dict(site=hex(site), target=hex(target), resolved=hex(resolve(target))))
        return calls

    def instructions(start, end):
        rows = []
        for site in idautils.Heads(start, end):
            if ida_bytes.is_code(ida_bytes.get_full_flags(site)):
                size = idc.get_item_size(site)
                rows.append(dict(va=hex(site), size=size, hex=ida_bytes.get_bytes(site, size).hex(),
                                 text=idc.generate_disasm_line(site, 0) or ''))
        return rows

    def function(ea):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks, ins = [], []
        for start, end in idautils.Chunks(ea):
            chunks.append(dict(identity(start, end - start), end=hex(end)))
            ins.extend(instructions(start, end))
        try:
            pseudo, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudo, error = [], str(exc)
        return dict(va=hex(ea), name=idc.get_func_name(ea), chunks=chunks, instructions=ins,
                    calls=near_calls(ea), pseudocode=pseudo, pseudocode_error=error)

    owned = {MAIN}
    owned.update(selected_functions)
    assert len(owned) <= 20, '超过有限专题范围，先人工拆分'
    aliases = {MAIN: {MAIN}}
    for ea in idautils.Functions():
        if ida_bytes.get_byte(ea) == 0xE9:
            real = resolve(ea, False)
            if real in aliases:
                aliases[real].add(ea)
    incoming = []
    for real, entries in sorted(aliases.items()):
        for entry in sorted(entries):
            if entry != real:
                resolve(entry)
            for xref in idautils.XrefsTo(entry, 0):
                owner = ida_funcs.get_func(xref.frm)
                caller = owner.start_ea if owner else None
                if caller in entries:
                    continue
                incoming.append(dict(site=hex(xref.frm), entry=hex(entry), resolved=hex(real),
                                     caller=hex(caller) if caller else None,
                                     iscode=bool(xref.iscode), type=int(xref.type)))
    assert len(selected_sites) <= 8
    by_site = {int(row['site'], 16): row for row in incoming if row['iscode'] and row['caller']}
    assert set(selected_sites) <= set(by_site), '只能选择当前可见代码入边'
    # 首轮只预览主入口最多8个调用窗口；全入边表保留，窗口不冒充完整函数。
    sites = list(selected_sites) if selected_sites else sorted(
        site for site, row in by_site.items() if row['resolved'] == hex(MAIN))[:8]
    navigation = []
    for site in sites:
        row = by_site[site]
        start, end = site, site + idc.get_item_size(site)
        for _ in range(24):
            previous = idc.prev_head(start)
            f = ida_funcs.get_func(previous)
            if not f or hex(f.start_ea) != row['caller']:
                break
            start = previous
        for _ in range(8):
            following = idc.next_head(end - 1)
            f = ida_funcs.get_func(following)
            if not f or hex(f.start_ea) != row['caller']:
                break
            end = following + idc.get_item_size(following)
        navigation.append(dict(incoming=row, window=identity(start, end - start),
                               instructions=instructions(start, end),
                               scope='局部调用参数导航，非完整函数审阅'))
    functions = [function(ea) for ea in sorted(owned)]
    neighbors = [dict(va=hex(ea), name=idc.get_func_name(ea))
                 for ea in idautils.Functions(0x6F9800, 0x6FB000)]
    result = dict(schema=1, input=str(ROOT / 'RnClient.exe'),
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  scope=dict(main=hex(MAIN),
                             selected_functions=[hex(x) for x in selected_functions],
                             policy='6FA控件外层及明确选择的补证；最多20函数/8窗口；8E底层由图像状态专题负责'),
                  functions=functions, incoming=incoming, caller_navigation=navigation,
                  neighbors_navigation_only=neighbors,
                  thunks=[thunks[ea] for ea in sorted(thunks)],
                  limitation='目录名为种子暂存名，不预设消息类别；局部字节一致不证明整个IDB身份相同')
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / 'wrapper.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                     encoding='utf-8', newline='\n')
    return dict(path=str(HERE / 'wrapper.json'), functions=[f['va'] for f in functions],
                incoming=incoming, neighbors=neighbors,
                all_equal=all(c['equal'] for f in functions for c in f['chunks'])
                and all(t['equal'] for t in result['thunks'])
                and all(n['window']['equal'] for n in navigation))
