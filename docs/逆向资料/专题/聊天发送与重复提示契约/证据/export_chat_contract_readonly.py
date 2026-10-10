# -*- coding: utf-8 -*-
"""只读发现导出；不改 IDB/EXE，仅写本专题 chat_contract_discovery.json。"""
import hashlib
import json
import pathlib
import struct

import ida_bytes
import ida_funcs
import ida_nalt
import idautils
import idc

ROOT = pathlib.Path(r"F:\大富翁online\Richonline")
OUT = ROOT / "docs/逆向资料/专题/聊天发送与重复提示契约/证据"
SEED = 0x64A520
GLOBALS = [0xA76E68, 0xA76E6C, 0xA76E70, 0xA76F80, 0xA77090, 0xA772A0, 0xA772A8]
EXTRA_CONTEXTS = [0x64A430, 0x64A820, 0x64C400, 0x932CD0, 0x932FC0,
                  0x934100, 0x9341D0, 0x934220]
EXTRA_ENTRIES = [0x60BAB7, 0x60634B, 0x607FE3, 0x920535]


def export(db):
    image = (ROOT / "RnClient.exe").read_bytes()
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[pe:pe + 4] == b"PE\0\0"
    optional = pe + 24
    assert struct.unpack_from("<H", image, optional)[0] == 0x10B
    base = struct.unpack_from("<I", image, optional + 28)[0]
    sections = []
    count = struct.unpack_from("<H", image, pe + 6)[0]
    table = optional + struct.unpack_from("<H", image, pe + 20)[0]
    for index in range(count):
        _, rva, raw_size, raw = struct.unpack_from("<IIII", image, table + 40 * index + 8)
        sections.append((rva, raw_size, raw))

    def identity(ea, size):
        ida = ida_bytes.get_bytes(ea, size)
        assert ida is not None and len(ida) == size
        disk = None
        for rva, raw_size, raw in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= raw_size:
                disk = image[raw + relative:raw + relative + size]
                break
        return {"va": hex(ea), "size": size, "ida_hex": ida.hex(),
                "disk_hex": disk.hex() if disk is not None else None,
                "sha256": hashlib.sha256(ida).hexdigest(),
                "equal": ida == disk if disk is not None else None,
                "disk_mapped": disk is not None}

    thunks = {}

    def resolve(ea):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9 and ea not in seen:
            seen.add(ea)
            target = ea + 5 + struct.unpack("<i", ida_bytes.get_bytes(ea + 1, 4))[0]
            thunks[ea] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

    def instruction(ea):
        size = idc.get_item_size(ea)
        return {"va": hex(ea), "size": size,
                "hex": ida_bytes.get_bytes(ea, size).hex(),
                "text": idc.generate_disasm_line(ea, 0) or ""}

    def function(ea, category):
        assert ida_funcs.get_func(ea).start_ea == ea
        chunks, instructions, calls = [], [], []
        for start, end in idautils.Chunks(ea):
            chunks.append(dict(identity(start, end - start), end=hex(end)))
            for site in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(site)):
                    continue
                instructions.append(instruction(site))
                if idc.print_insn_mnem(site) in ("call", "jmp") and idc.get_operand_type(site, 0) in (idc.o_near, idc.o_far):
                    target = idc.get_operand_value(site, 0)
                    calls.append({"site": hex(site), "target": hex(target),
                                  "resolved": hex(resolve(target)), "name": idc.get_name(target)})
        try:
            pseudocode, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        return {"va": hex(ea), "name": idc.get_func_name(ea), "category": category,
                "chunks": chunks, "instructions": instructions, "calls": calls,
                "pseudocode": pseudocode, "pseudocode_error": error}

    seed = function(SEED, "candidate_seed_not_yet_reviewed")
    # 仅导出种子的直接调用依赖；不递归扩大调用图，也不把这些函数计为已审成果。
    dependencies = set()
    for ea in EXTRA_CONTEXTS + [resolve(entry) for entry in EXTRA_ENTRIES]:
        owner = ida_funcs.get_func(ea)
        assert owner is not None
        dependencies.add(owner.start_ea)
    for call in seed["calls"]:
        ea = int(call["resolved"], 16)
        owner = ida_funcs.get_func(ea)
        if owner and owner.start_ea == ea and ea != SEED:
            dependencies.add(ea)
    functions = [seed] + [function(ea, "direct_dependency_context_not_yet_reviewed")
                          for ea in sorted(dependencies)]

    def window(site):
        owner = ida_funcs.get_func(site)
        if not owner:
            return {"site": hex(site), "caller": None, "instructions": []}
        heads = [ea for start, end in idautils.Chunks(owner.start_ea)
                 for ea in idautils.Heads(start, end)
                 if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]
        if site not in heads:
            return {"site": hex(site), "caller": hex(owner.start_ea), "instructions": []}
        position = heads.index(site)
        return {"site": hex(site), "caller": hex(owner.start_ea),
                "instructions": [instruction(ea) for ea in heads[max(0, position - 8):position + 7]]}

    aliases = {SEED}
    for ea in idautils.Functions():
        if ida_bytes.get_byte(ea) == 0xE9:
            # 不在此阶段导出全库跳板，resolve 只用于命中种子的别名。
            target, seen = ea, set()
            while ida_bytes.get_byte(target) == 0xE9 and target not in seen:
                seen.add(target)
                target += 5 + struct.unpack("<i", ida_bytes.get_bytes(target + 1, 4))[0]
            if target == SEED:
                aliases.add(ea)
                resolve(ea)
    incoming = []
    for alias in sorted(aliases):
        for site in idautils.CodeRefsTo(alias, False):
            incoming.append(dict(window(site), entry=hex(alias)))

    globals_rows = []
    for ea in GLOBALS:
        xrefs = [dict(window(xref.frm), kind=int(xref.type)) for xref in idautils.XrefsTo(ea)]
        globals_rows.append({"va": hex(ea), "name": idc.get_name(ea),
                             "ida_item_size": idc.get_item_size(ea),
                             "next_item_head": hex(idc.next_head(ea)),
                             "snapshot": identity(ea, 32), "xrefs": xrefs,
                             "policy": "IDA item_size/邻接名称不等于真实缓冲容量；窗口不是调用方完整语义"})
    # 只记录本题实际消费的固定数据，不从符号注释推断字符串内容。
    static_data = [identity(ea, size) for ea, size in
                   [(0xA229B0, 3), (0xA229B4, 3), (0xA67308, 4), (0xA67341, 1),
                    (0xA2F048, 5)]]
    prefix_target = struct.unpack("<I", ida_bytes.get_bytes(0xA67308, 4))[0]
    static_data.append(dict(identity(prefix_target, 5), role="prefix_target"))
    route_tables = [identity(0x64A807, 16), identity(0x82A3BD, 28)]
    result = {"schema": 1, "input": str(ROOT / "RnClient.exe"),
              "disk_sha256": hashlib.sha256(image).hexdigest(),
              "idb_input_sha256": ida_nalt.retrieve_input_file_sha256().hex(),
              "seed": hex(SEED), "functions": functions,
              "thunks": [thunks[ea] for ea in sorted(thunks)],
              "incoming": incoming, "globals": globals_rows,
              "static_data": static_data,
              "route_tables": route_tables,
              "scope": "只读发现证据；直接依赖和窗口均未自动升级为函数审阅或传输层新成果"}
    OUT.mkdir(parents=True, exist_ok=True)
    destination = OUT / "chat_contract_discovery.json"
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"path": str(destination), "functions": len(functions), "incoming": len(incoming),
            "thunks": len(thunks), "globals_xrefs": sum(len(row["xrefs"]) for row in globals_rows),
            "code_all_equal": all(chunk["equal"] for function in functions for chunk in function["chunks"])
                              and all(row["equal"] for row in thunks.values())}


print(export(db))
