"""82BBE0 专题独审：磁盘 PE 与实时 IDA 分别取证。"""

import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
RAW = HERE / "82bbe0_raw.json"
FUNCTIONS = ROOT / "docs/逆向资料/全量分析/functions.json"
EXPECTED_SHA256 = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
START, END, SITE = 0x82D820, 0x82D8B9, 0x82D864


def offline():
    source = json.loads(RAW.read_text(encoding="utf-8"))
    image = (ROOT / "RnClient.exe").read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA256 == source["disk_sha256"]
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[:2] == b"MZ" and image[pe:pe + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", image, pe + 24)[0] == 0x10B
    base = struct.unpack_from("<I", image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from("<H", image, pe + 20)[0]
    sections = [struct.unpack_from("<4I", image, section_table + i * 40 + 8)
                for i in range(struct.unpack_from("<H", image, pe + 6)[0])]

    def at(va, size):
        matches = [offset + va - base - rva for _, rva, raw_size, offset in sections
                   if base + rva <= va and va + size <= base + rva + raw_size]
        assert len(matches) == 1, hex(va)
        return image[matches[0]:matches[0] + size]

    def target(va):
        assert at(va, 1) == b"\xe8" or at(va, 1) == b"\xe9"
        return va + 5 + struct.unpack("<i", at(va + 1, 4))[0]

    assert source["subject"] == "0x82bbe0"
    assert source["entries"] == ["0x60bfda", "0x82bbe0"]
    assert target(0x60BFDA) == 0x82BBE0
    assert [f["va"] for f in source["functions"]] == [
        "0x82bbe0", "0x82edd0", "0x840230", "0x846ab0"]
    for function in source["functions"]:
        for block in function["chunks"]:
            assert at(int(block["va"], 16), block["size"]).hex() == block["ida_hex"]

    assert len(source["incoming"]) == 63
    assert sum(r["entry"] == "0x60bfda" for r in source["incoming"]) == 62
    assert sum(r["entry"] == "0x82bbe0" for r in source["incoming"]) == 1
    unowned = [r for r in source["incoming"] if r["owner"] is None]
    assert len(unowned) == 1 and unowned[0]["site"] == hex(SITE)
    assert unowned[0]["iscode"] is True
    assert len(source["windows"]) == 61
    sites = {r["site"] for r in source["windows"]}
    owners = {r["owner"] for r in source["windows"]}
    assert len(sites) == 61 and len(owners) == 48
    assert {r["site"] for r in source["incoming"]} - sites == {hex(SITE), "0x60bfda"}
    assert all(target(int(site, 16)) == 0x60BFDA for site in sites)

    assert len(source["undeclared"]) == 1
    gap = source["undeclared"][0]
    block = gap["block"]
    assert gap["site"] == hex(SITE)
    assert (int(block["va"], 16), int(block["end"], 16), block["size"]) == (START, END, 153)
    assert at(START, END - START).hex() == block["ida_hex"] == block["disk_hex"]
    assert hashlib.sha256(at(START, END - START)).hexdigest() == block["sha256"]
    assert at(START, 3).hex() == "558bec"
    assert at(END - 3, 3).hex() == "c20400"
    instructions = gap["instructions"]
    assert len(instructions) == 46
    cursor = START
    for row in instructions:
        assert int(row["va"], 16) == cursor
        assert at(cursor, row["size"]).hex() == row["hex"]
        cursor += row["size"]
    assert cursor == END
    assert target(0x82D84A) == 0x601922
    assert target(SITE) == 0x60BFDA
    assert target(0x82D86B) == 0x602D63
    assert at(0x82D890, 2).hex() == "6a14"
    assert at(0x82D892, 6).hex() == "ff1564b8ac00"
    candidate_entry_source = 0x609A05
    candidate_entry_bytes = at(candidate_entry_source, 5)
    assert candidate_entry_bytes[0] == 0xE9
    assert target(candidate_entry_source) == START

    catalog = json.loads(FUNCTIONS.read_text(encoding="utf-8"))
    if isinstance(catalog, dict):
        catalog = catalog["functions"]
    boundaries = [(int(row["va"], 16), int(row["end_va"], 16)) for row in catalog]
    before = max((pair for pair in boundaries if pair[0] < START), key=lambda pair: pair[0])
    after = min((pair for pair in boundaries if pair[0] > START), key=lambda pair: pair[0])
    assert before == (0x82D7D0, 0x82D805)
    assert after == (0x82D8E0, 0x82D965)
    assert not any(a <= START < b or a <= SITE < b for a, b in boundaries)

    result = dict(status="PASS", pe_sha256=digest, declared_complete_functions=4,
                  declared_call_owners=48, owned_windows=61, visible_incoming=63,
                  undeclared_window=[hex(START), hex(END)], undeclared_bytes=153,
                  contiguous_instructions=46, previous_function=[hex(v) for v in before],
                  next_function=[hex(v) for v in after],
                  site_target=hex(target(SITE)), thunk_target=hex(target(0x60BFDA)),
                  candidate_entry_source=hex(candidate_entry_source),
                  candidate_entry_source_bytes=candidate_entry_bytes.hex(),
                  candidate_entry_source_target=hex(target(candidate_entry_source)),
                  limitation="函数目录及入边归属来自 IDA 导出；磁盘独审不能证明运行时可达性")
    (HERE / "independent_offline.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def audit(db):
    """在现有 IDA 会话内调用；仅读取 IDB 并写本专题独审证据。"""
    import ida_bytes
    import ida_funcs
    import idautils
    import idc

    assert ida_funcs.get_func(START) is None
    assert ida_funcs.get_func(SITE) is None
    assert ida_funcs.get_func(END - 1) is None
    assert ida_funcs.get_func(0x82D7D0).start_ea == 0x82D7D0
    assert ida_funcs.get_func(0x82D8E0).start_ea == 0x82D8E0
    assert ida_funcs.get_func(0x82D7D0).end_ea == 0x82D805
    assert ida_funcs.get_func(0x82D8E0).end_ea == 0x82D965
    heads = [ea for ea in idautils.Heads(START, END)
             if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]
    assert len(heads) == 46 and heads[0] == START and heads[-1] == END - 3
    assert all(ida_bytes.get_bytes(ea, idc.get_item_size(ea)) is not None for ea in heads)
    xrefs = [(x.frm, x.to, bool(x.iscode), int(x.type))
             for x in idautils.XrefsTo(0x60BFDA, 0)]
    assert len(xrefs) == 62
    assert sum(frm == SITE and iscode for frm, _, iscode, _ in xrefs) == 1
    owned = [ida_funcs.get_func(frm) for frm, _, iscode, _ in xrefs if iscode and frm != SITE]
    assert len(owned) == 61 and all(owned)
    assert len({f.start_ea for f in owned}) == 48
    entry_xrefs = [(x.frm, x.to, bool(x.iscode), int(x.type),
                   ida_funcs.get_func(x.frm).start_ea if ida_funcs.get_func(x.frm) else None)
                  for x in idautils.XrefsTo(START, 0)]
    assert len(entry_xrefs) == 1 and entry_xrefs[0][0] == 0x609A05
    result = dict(status="PASS", idb_undeclared_start=ida_funcs.get_func(START) is None,
                  idb_undeclared_site=ida_funcs.get_func(SITE) is None,
                  contiguous_code_heads=len(heads), alias_incoming=len(xrefs),
                  owned_incoming=len(owned), owned_callers=len({f.start_ea for f in owned}),
                  candidate_entry_xrefs=[dict(source=hex(a), target=hex(b), iscode=c,
                                              xref_type=d, owner=hex(e) if e else None)
                                         for a, b, c, d, e in entry_xrefs],
                  limitation="仅当前 IDB 声明状态与交叉引用；入边不证明运行时可达")
    (HERE / "independent_ida.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(offline(), ensure_ascii=False))
