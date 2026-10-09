# -*- coding: utf-8 -*-
"""只读 IDA 导出；仅在本专题证据目录写 JSON，不修改数据库或客户端。"""
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
OUT = ROOT / "docs/逆向资料/专题/音频容器与对象池/证据"
HELPERS = [
    0x8235C0, 0x823680, 0x823780, 0x8237D0, 0x8237F0, 0x8238B0,
    0x8239B0, 0x823A00, 0x823A20, 0x823AE0, 0x823BE0, 0x823C20,
    0x823C40, 0x823C90, 0x823D50, 0x823E50, 0x823EA0, 0x823EC0,
    0x823EF0, 0x823FB0, 0x8240B0, 0x824310, 0x824350, 0x824450,
    0x824470, 0x8244A0, 0x8244F0, 0x826C50, 0x826D10, 0x826E10,
    0x826E60, 0x826E80, 0x826F40, 0x827040, 0x827090, 0x8270B0,
    0x827170, 0x827270, 0x8272C0, 0x8272E0, 0x827310, 0x8273D0,
    0x8274D0, 0x827520, 0x827540,
]
DTORS = [0x69BCB0, 0x69BD40, 0x69BDC0, 0x69BE50, 0x69BED0,
         0x69BF30, 0x69BF90, 0x69BFF0, 0x69B7D0, 0x69B860,
         0x69B8F0, 0x69B980, 0x69B9E0, 0x69BA40]
COPY = [0x9213A0]
CTORS = [0x69B770, 0x69B800, 0x69B890, 0x69B920, 0x69BC50,
         0x69BCE0, 0x69BD70, 0x69BDF0, 0x69BE80]
TABLES = [(0x921404, 12), (0x921480, 32), (0x9214EC, 16),
          (0x921590, 12), (0x92161C, 32), (0x921688, 16)]


def export(db):
    image = (ROOT / "RnClient.exe").read_bytes()
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[pe:pe + 4] == b"PE\0\0"
    optional = pe + 24
    assert struct.unpack_from("<H", image, optional)[0] == 0x10B
    base = struct.unpack_from("<I", image, optional + 28)[0]
    sections = []
    n = struct.unpack_from("<H", image, pe + 6)[0]
    table = optional + struct.unpack_from("<H", image, pe + 20)[0]
    for i in range(n):
        p = table + 40 * i
        virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", image, p + 8)
        sections.append((rva, raw_size, raw))

    def disk_bytes(ea, size):
        for rva, raw_size, raw in sections:
            offset = ea - base - rva
            if 0 <= offset and offset + size <= raw_size:
                return image[raw + offset:raw + offset + size]
        raise ValueError("地址无完整磁盘映射: " + hex(ea))

    def identity(ea, size):
        ida = ida_bytes.get_bytes(ea, size)
        disk = disk_bytes(ea, size)
        return {"va": hex(ea), "size": size, "ida_hex": ida.hex(),
                "disk_hex": disk.hex(), "sha256": hashlib.sha256(ida).hexdigest(),
                "equal": ida == disk}

    thunk_rows = {}

    def resolve(ea):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9 and ea not in seen:
            seen.add(ea)
            target = ea + 5 + struct.unpack("<i", ida_bytes.get_bytes(ea + 1, 4))[0]
            thunk_rows[ea] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

    addresses = HELPERS + DTORS + CTORS + COPY
    incoming = {f: [] for f in addresses}
    aliases = {f: {f} for f in addresses}
    for f in idautils.Functions():
        if ida_bytes.get_byte(f) == 0xE9:
            target = resolve(f)
            if target in aliases:
                aliases[target].add(f)
    # 只保留本专题实际引用的跳板，避免全库扫描污染证据范围。
    thunk_rows.clear()
    callers = set()
    for f, entries in aliases.items():
        for entry in sorted(entries):
            if entry != f:
                resolve(entry)
            for site in idautils.CodeRefsTo(entry, False):
                owner = ida_funcs.get_func(site)
                if not owner or owner.start_ea in entries:
                    continue
                if f in COPY and owner.start_ea not in HELPERS:
                    continue
                incoming[f].append({"site": hex(site), "caller": hex(owner.start_ea),
                                    "entry": hex(entry)})
                if owner.start_ea not in addresses and f not in COPY:
                    callers.add(owner.start_ea)

    def function(ea, category):
        chunks = []
        instructions = []
        calls = []
        for start, end in idautils.Chunks(ea):
            chunks.append(dict(identity(start, end - start), end=hex(end)))
            for h in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(h)):
                    continue
                size = idc.get_item_size(h)
                instructions.append({"va": hex(h), "size": size,
                                     "hex": ida_bytes.get_bytes(h, size).hex(),
                                     "text": idc.generate_disasm_line(h, 0) or ""})
                if idc.print_insn_mnem(h) in ("call", "jmp") and idc.get_operand_type(h, 0) in (idc.o_near, idc.o_far):
                    target = idc.get_operand_value(h, 0)
                    calls.append({"site": hex(h), "target": hex(target),
                                  "resolved": hex(resolve(target)), "name": idc.get_name(target)})
        try:
            pseudocode = db.pseudocode.get_text(ea)
            error = None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        return {"va": hex(ea), "name": idc.get_func_name(ea), "category": category,
                "chunks": chunks, "instructions": instructions, "calls": calls,
                "incoming": sorted(incoming.get(ea, []), key=lambda x: int(x["site"], 16)),
                "pseudocode": pseudocode, "pseudocode_error": error}

    functions = [function(f, "container_helper") for f in HELPERS]
    functions += [function(f, "destructor_helper") for f in DTORS]
    functions += [function(f, "constructor_helper") for f in CTORS]
    functions += [function(f, "copy_support") for f in COPY]
    contexts = [function(f, "existing_audio_context") for f in sorted(callers)]
    tables = []
    for ea, size in TABLES:
        row = identity(ea, size)
        row["targets"] = [hex(idc.get_wide_dword(ea + i)) for i in range(0, size, 4)]
        tables.append(row)
    result = {
        "schema": 1, "date": "2026-10-10", "input": str(ROOT / "RnClient.exe"),
        "disk_sha256": hashlib.sha256(image).hexdigest(),
        "idb_input_sha256": ida_nalt.retrieve_input_file_sha256().hex(),
        "scope": {"helpers": [hex(f) for f in HELPERS], "destructors": [hex(f) for f in DTORS],
                  "constructors": [hex(f) for f in CTORS],
                  "copy_support": [hex(f) for f in COPY],
                  "context_policy": "复用上层音频函数，仅为 this 偏移、元素类型和释放责任提供上下文，不计新增语义成果"},
        "functions": functions, "contexts": contexts,
        "thunks": [thunk_rows[f] for f in sorted(thunk_rows)], "copy_tables": tables,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    destination = OUT / "audio_containers.json"
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"path": str(destination), "functions": len(functions), "contexts": len(contexts),
            "chunks": sum(len(f["chunks"]) for f in functions),
            "instructions": sum(len(f["instructions"]) for f in functions),
            "bytes": sum(c["size"] for f in functions for c in f["chunks"]),
            "all_equal": all(c["equal"] for f in functions + contexts for c in f["chunks"])
                         and all(c["equal"] for c in result["thunks"] + tables)}


export(db)
