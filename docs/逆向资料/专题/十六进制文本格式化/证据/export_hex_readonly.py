# -*- coding: utf-8 -*-
"""只读 IDA 导出；唯一写入为本专题 evidence JSON，不改 IDB 或 EXE。"""
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
OUT = ROOT / "docs/逆向资料/专题/十六进制文本格式化/证据/hex_raw.json"
ENTRIES = [0x8E0380, 0x92BBD0, 0x92BAD0, 0x8E67C0, 0x8F1000, 0x8F9490,
           0x901F30, 0x905420, 0x909330, 0x90AAA0, 0x90E060]


def export(db):
    image = (ROOT / "RnClient.exe").read_bytes()
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[pe:pe + 4] == b"PE\0\0"
    optional = pe + 24
    assert struct.unpack_from("<H", image, optional)[0] == 0x10B
    base = struct.unpack_from("<I", image, optional + 28)[0]
    table = optional + struct.unpack_from("<H", image, pe + 20)[0]
    sections = []
    for i in range(struct.unpack_from("<H", image, pe + 6)[0]):
        _, rva, raw_size, raw = struct.unpack_from("<IIII", image, table + i * 40 + 8)
        sections.append((rva, raw_size, raw))

    def identity(ea, size):
        data = ida_bytes.get_bytes(ea, size)
        assert data is not None and len(data) == size
        disk = None
        for rva, raw_size, raw in sections:
            offset = ea - base - rva
            if 0 <= offset and offset + size <= raw_size:
                disk = image[raw + offset:raw + offset + size]
                break
        return {"va": hex(ea), "size": size, "ida_hex": data.hex(),
                "disk_hex": disk.hex() if disk is not None else None,
                "equal": data == disk if disk is not None else None,
                "sha256": hashlib.sha256(data).hexdigest()}

    bridges = {}

    def resolve(ea):
        seen = set()
        while ida_bytes.get_byte(ea) == 0xE9 and ea not in seen:
            seen.add(ea)
            target = ea + 5 + struct.unpack("<i", ida_bytes.get_bytes(ea + 1, 4))[0]
            bridges[ea] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea

    def instruction(ea):
        size = idc.get_item_size(ea)
        return {"va": hex(ea), "size": size, "hex": ida_bytes.get_bytes(ea, size).hex(),
                "text": idc.generate_disasm_line(ea, 0) or ""}

    strings = {}

    def function(ea):
        owner = ida_funcs.get_func(ea)
        assert owner is not None and owner.start_ea == ea
        chunks, instructions, data_items, calls, references = [], [], [], [], []
        for start, end in idautils.Chunks(ea):
            chunks.append(dict(identity(start, end - start), end=hex(end)))
            for site in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(site)):
                    data_items.append(instruction(site))
                    continue
                instructions.append(instruction(site))
                mnemonic = idc.print_insn_mnem(site)
                if mnemonic in ("call", "jmp"):
                    target = idc.get_operand_value(site, 0)
                    operand_type = idc.get_operand_type(site, 0)
                    direct = operand_type in (idc.o_near, idc.o_far)
                    calls.append({"site": hex(site), "kind": mnemonic, "direct": direct,
                                  "target": hex(target), "resolved": hex(resolve(target)) if direct else None,
                                  "target_name": idc.get_name(target), "operand_type": operand_type})
                for target in idautils.DataRefsFrom(site):
                    references.append({"site": hex(site), "target": hex(target), "name": idc.get_name(target)})
                    if ida_bytes.is_strlit(ida_bytes.get_full_flags(target)) and target not in strings:
                        size = idc.get_item_size(target)
                        if 0 < size <= 512:
                            strings[target] = identity(target, size)
        try:
            pseudocode, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        return {"va": hex(ea), "name": idc.get_func_name(ea), "chunks": chunks,
                "instructions": instructions, "non_code_items": data_items,
                "calls": calls, "data_refs": references,
                "pseudocode": pseudocode, "pseudocode_error": error}

    functions = [function(ea) for ea in ENTRIES]
    incoming = []
    for entry in (0x8E0380, 0x600248):
        resolve(entry)
        for site in idautils.CodeRefsTo(entry, False):
            owner = ida_funcs.get_func(site)
            incoming.append({"site": hex(site), "entry": hex(entry),
                             "owner": hex(owner.start_ea) if owner else None,
                             "instruction": instruction(site)})

    global_info = {"va": "0xacc3d8", "ida_item_size": idc.get_item_size(0xACC3D8),
                   "next_head": hex(idc.next_head(0xACC3D8)),
                   "snapshot": identity(0xACC3D8, 32), "references": []}
    for ea in range(0xACC3D8, 0xACC3D8 + 32):
        for ref in idautils.XrefsTo(ea):
            owner = ida_funcs.get_func(ref.frm)
            global_info["references"].append({"target": hex(ea), "site": hex(ref.frm),
                                              "type": int(ref.type),
                                              "owner": hex(owner.start_ea) if owner else None,
                                              "instruction": instruction(ref.frm)})
    result = {"schema": 1, "input": str(ROOT / "RnClient.exe"),
              "disk_sha256": hashlib.sha256(image).hexdigest(),
              "idb_input_sha256": ida_nalt.retrieve_input_file_sha256().hex(),
              "scope": "种子和两个CRT主体候选、8个保存调用方局部候选；导出不等于已审",
              "functions": functions, "thunks": [bridges[ea] for ea in sorted(bridges)],
              "incoming": incoming, "global": global_info,
              "strings": [strings[ea] for ea in sorted(strings)]}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"path": str(OUT), "functions": len(functions), "incoming": len(incoming),
            "thunks": len(bridges), "strings": len(strings),
            "code_equal": all(c["equal"] for f in functions for c in f["chunks"])}


print(export(db))
