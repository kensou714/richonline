"""实时只读复核高扇入专题；audit(db) 不写文件或 IDB。"""

import hashlib
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_nalt
import idautils


HERE = Path(__file__).resolve().parent
TARGETS = (0x91F7E0, 0x9CA953, 0x9DB4B6, 0x85BB10)
FUNCTIONS = TARGETS + (0x85C710, 0x85EA60, 0x85FEA0, 0x860000, 0x85F190, 0x860370)
ALIASES = (0x601CD3, 0x612367, 0x608A4C, 0x60C87C)


def audit(db):
    raw = json.loads((HERE / "highfanout_raw.json").read_text(encoding="utf-8"))
    group = json.loads((HERE / "85bb_group_raw.json").read_text(encoding="utf-8"))
    aliases = json.loads((HERE / "highfanout_aliases.json").read_text(encoding="utf-8"))
    saved = {int(f["va"], 16): f for f in
             [t["function"] for t in raw["targets"]] + group["functions"]}
    assert ida_nalt.retrieve_input_file_sha256().hex() == raw["idb_input_sha256"]
    byte_differences = []
    for ea in FUNCTIONS:
        function = ida_funcs.get_func(ea)
        assert function and function.start_ea == ea
        current_chunks = list(idautils.Chunks(ea))
        expected_chunks = saved[ea]["chunks"]
        assert len(current_chunks) == len(expected_chunks)
        for (start, end), expected in zip(current_chunks, expected_chunks):
            assert start == int(expected["va"], 16)
            current = ida_bytes.get_bytes(start, end - start)
            if current is None or current.hex() != expected["ida_hex"]:
                byte_differences.append(hex(start))
    totals = []
    for target, alias, original in zip(TARGETS, ALIASES, aliases["targets"]):
        live = []
        for entry in (target, alias):
            for ref in idautils.XrefsTo(entry, 0):
                owner = ida_funcs.get_func(ref.frm)
                live.append((hex(ref.frm), hex(entry),
                             hex(owner.start_ea) if owner else None,
                             int(ref.type), bool(ref.iscode)))
        expected = [(row["site"], row["entry"], row["owner"],
                     row["xref_type"], row["iscode"]) for row in original["incoming"]]
        totals.append(dict(va=hex(target), live=len(live), saved=len(expected),
                           missing=sorted(set(expected) - set(live)),
                           added=sorted(set(live) - set(expected))))
    return dict(status="PASS" if not byte_differences and all(
                    not t["missing"] and not t["added"] for t in totals) else "DIFFERENCE",
                idb_input_sha256=raw["idb_input_sha256"],
                checked_functions=len(FUNCTIONS), byte_differences=byte_differences,
                targets=totals, idb_writes=0)
