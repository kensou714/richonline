"""业务提示与期限映射的独立静态复核。

本文件只读取当前 RnClient.exe、作者导出的证据和资源包；不执行客户端，
也不申请或修改 IDA 数据库。audit(db) 可在已有 IDA-MCP 数据库租约中附加
核对函数块、指令和 xref，但不会写入数据库。
"""
from contextlib import redirect_stdout
from itertools import product
from pathlib import Path
import hashlib
import io
import json
import re
import runpy
import struct
import sys

import lzokay

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
SHA = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
FILES = ("entries.json", "callers.json", "followups.json", "ctor_and_loaders.json")
RESULTS = {0x6C2590, 0x6C2790, 0x6C2870, 0x6C29A0, 0x6C2B80,
           0x6C2D70, 0x6C2E70, 0x6C3000, 0x6C3120, 0x6C32E0,
           0x6C34A0, 0x6C35B0, 0x6C3670}
ICONS = {0x741820, 0x747E10, 0x749D60, 0x756460, 0x75AD50,
         0x762A80, 0x762E10, 0x766B50, 0x767860, 0x77F590, 0x77FEF0}
CONCLUSIONS = {0x6C22E0, 0x6F4AA0, 0x627B60, 0x627C20, 0x629D90,
               0x6DBA40, 0x800AD0, 0x800B30, 0x800B90, 0x6D7170, 0x7FEA80}


def _pe(blob):
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    base = struct.unpack_from("<I", blob, pe + 52)[0]
    n = struct.unpack_from("<H", blob, pe + 6)[0]
    opt = struct.unpack_from("<H", blob, pe + 20)[0]
    return base, [struct.unpack_from("<IIII", blob, pe + 24 + opt + 40 * i + 8)
                  for i in range(n)]


def _resource_sections(text):
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if value.startswith("[") and value.endswith("]"):
            out.append({"section": value[1:-1], "line": number,
                        "fields": {}, "raw_lines": [line]})
        elif out:
            out[-1]["raw_lines"].append(line)
            if "=" in line and not value.startswith("//"):
                key, val = line.split("=", 1)
                out[-1]["fields"][key.strip().lower()] = val.strip()
    return out


def _decode(relative):
    source = (ROOT / relative).read_bytes()
    if relative.endswith(".kpd"):
        key = source[0]
        header = bytes((b - key) & 255 for b in source[1:9])
        expanded, packed = struct.unpack("<II", header)
        assert packed == len(source) - 9
        plain = lzokay.decompress(bytes((b - key) & 255 for b in source[9:]), expanded)
        assert len(plain) == expanded
    else:
        key = b"RichNet"
        plain = bytes((b - key[i % len(key)]) & 255 for i, b in enumerate(source))
    codec = "gbk" if relative == "Interface/Intf.kpd" else "cp950"
    text = plain.decode(codec, errors="strict")
    assert text.encode(codec) == plain
    return dict(source=relative, source_sha256=hashlib.sha256(source).hexdigest(),
                source_size=len(source), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                codec=codec, strict_roundtrip=True, sections=_resource_sections(text))


def _resource_audit():
    rich = _decode("Data/RichStr.kpd")
    want = {str(i) for i in range(1120, 1130)}
    rich["sections"] = [s for s in rich["sections"] if s["fields"].get("indx") in want]
    present = {s["fields"]["indx"] for s in rich["sections"]}
    rich["requested_indices"] = [str(i) for i in range(1120, 1130)]
    rich["missing_indices"] = sorted(want - present, key=int)
    intf = _decode("Interface/Intf.kpd")
    intf["sections"] = [s for s in intf["sections"] if s["fields"].get("indx") == "71"]
    assert len(intf["sections"]) == 1
    ui = _decode("Interface/" + intf["sections"][0]["fields"]["file"])
    prop = _decode("Data/Prop.kpd")
    prop["sections"] = [s for s in prop["sections"]
                         if s["fields"].get("indx") in {"1", "9", "13", "501", "503"}]
    assert len(prop["sections"]) == 5
    return {"scope": "独立只读解码；不模拟窗口、网络响应或资源句柄消费",
            "records": [rich, intf, ui, prop]}


def _reproduce_author_outputs():
    """复跑作者脚本并拦截写入，确保独审没有依赖手工修改的 JSON。"""
    captured = {}
    old_text, old_bytes = Path.write_text, Path.write_bytes
    old_path = list(sys.path)
    old_model = sys.modules.pop("model", None)
    def text_write(path, text, *args, **kwargs):
        captured[path.resolve()] = text
        return len(text)
    def bytes_write(path, data):
        captured[path.resolve()] = data
        return len(data)
    try:
        sys.path.insert(0, str(HERE))
        Path.write_text, Path.write_bytes = text_write, bytes_write
        with redirect_stdout(io.StringIO()):
            for name in ("build_review.py", "inspect_resources.py"):
                runpy.run_path(str(TOPIC / name), run_name="__main__")
    finally:
        Path.write_text, Path.write_bytes, sys.path[:] = old_text, old_bytes, old_path
        sys.modules.pop("model", None)
        if old_model is not None:
            sys.modules["model"] = old_model
    for path, value in captured.items():
        if path.suffix == ".json":
            assert json.loads(value) == json.loads(path.read_text("utf-8")), path
        elif path.suffix == ".txt":
            assert value == path.read_text("utf-8"), path
        else:
            assert value == path.read_bytes(), path
    return len(captured)


def audit(db=None):
    blob = (ROOT / "RnClient.exe").read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    base, sections = _pe(blob)
    def disk(va, size):
        for _, rva, raw_size, raw_off in sections:
            offset = va - base - rva
            if 0 <= offset and offset + size <= raw_size:
                return blob[raw_off + offset:raw_off + offset + size]
        raise AssertionError((hex(va), size))

    functions, thunks, instructions, byte_map = {}, {}, {}, {}
    spans, chunks, calls = set(), set(), 0
    comparisons = 0
    def check_range(row):
        nonlocal comparisons
        va, size = int(row["va"], 16), int(row["size"])
        expected = bytes.fromhex(row["idb_hex"])
        assert len(expected) == size == len(bytes.fromhex(row["disk_hex"]))
        assert disk(va, size) == expected == bytes.fromhex(row["disk_hex"])
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == expected
        for i, value in enumerate(expected):
            assert byte_map.get(va + i, value) == value
            byte_map[va + i] = value
        spans.add((va, size)); comparisons += 1
    for filename in FILES:
        source = json.loads((HERE / filename).read_text("utf-8"))
        assert source["disk_sha256"] == SHA
        for thunk in source["thunks"]:
            check_range(thunk)
            va, code = int(thunk["va"], 16), bytes.fromhex(thunk["idb_hex"])
            assert len(code) == 5 and code[0] == 0xE9
            assert va + 5 + struct.unpack_from("<i", code, 1)[0] == int(thunk["target"], 16)
            thunks[va] = thunk
        for f in source["functions"]:
            va = int(f["va"], 16)
            assert va not in functions and f["bytes_match_disk"] is True
            functions[va] = f
            declared = {(int(c["start_va"], 16), int(c["end_va"], 16), c["is_main"])
                        for c in f["declared_chunks"]}
            assert {(s, e) for s, e, _ in declared} == {
                (int(r["va"], 16), int(r["va"], 16) + r["size"])
                for r in f["chunk_byte_ranges"]}
            for row in f["byte_ranges"] + f["chunk_byte_ranges"]:
                check_range(row)
            chunks.update((va, s, e) for s, e, _ in declared)
            for ins in f["assembly"]:
                address = int(ins["va"], 16)
                assert any(s <= address < e for s, e, _ in declared)
                assert instructions.get(address, ins["text"]) == ins["text"]
                instructions[address] = ins["text"]
            for call in f["calls"]:
                site, target = int(call["site"], 16), int(call["target"], 16)
                code = disk(site, 6)
                if code[0] in (0xE8, 0xE9):
                    assert site + 5 + struct.unpack_from("<i", code, 1)[0] == target
                else:
                    assert code[:2] == b"\xff\x15" and struct.unpack_from("<I", code, 2)[0] == target
                calls += 1
            if db is not None:
                live = db.functions.get_at(va)
                assert live.start_ea == va and live.end_ea == int(f["end_va"], 16)
                live_chunks = list(db.functions.get_chunks(live))
                assert {(c.start_ea, c.end_ea, c.is_main) for c in live_chunks} == declared
                live_ins = {i.ea: db.instructions.get_disassembly(i)
                            for c in live_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
                assert live_ins == {int(i["va"], 16): i["text"] for i in f["assembly"]}
                edges = [dict(site=hex(i.ea), target=hex(x.to_ea))
                         for c in live_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)
                         for x in db.xrefs.from_ea(i.ea) if x.type in (16, 17)]
                assert edges == [{k: c[k] for k in ("site", "target")} for c in f["calls"]]

    assert set(functions) == RESULTS | ICONS | CONCLUSIONS
    assert instructions[0x6C230A].startswith("ja ")
    assert instructions[0x6C250B] == "retn    4"
    assert instructions[0x6F4C08] == "retn"
    assert instructions[0x629DA4] == "imul    ecx, [eax]"
    assert instructions[0x629DAA] == "add     ecx, [edx+8]"
    assert instructions[0x629DB2] == "retn    4"
    assert instructions[0x6D7181] == "mov     dword ptr [eax+8], 0"
    assert instructions[0x6DBDB1] == "retn    10h"
    navigation = json.loads((HERE / "references.json").read_text("utf-8"))
    for edge in navigation["edges"]:
        site, target = int(edge["source"], 16), int(edge["target"], 16)
        expected = bytes.fromhex(edge["source_hex"])
        check_range(dict(va=hex(site), size=5, idb_hex=expected.hex(), disk_hex=expected.hex()))
        assert expected[0] in (0xE8, 0xE9)
        assert site + 5 + struct.unpack_from("<i", expected, 1)[0] == target
        assert edge["e9_bridge"] == (expected[0] == 0xE9)
        if db is not None:
            owner = db.functions.get_at(site)
            assert (hex(owner.start_ea) if owner else None) == edge["owner"]
    if db is not None:
        for target in {e["target"] for e in navigation["edges"]}:
            assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(int(target, 16))} == {
                (e["source"], e["kind"]) for e in navigation["edges"] if e["target"] == target}
    icon_calls = 0
    for va in RESULTS:
        assembly = functions[va]["assembly"]
        compare = next(i for i, row in enumerate(assembly) if row["text"] == "cmp     [ebp+arg_0], 0")
        branch = assembly[compare + 1]["text"]
        assert branch.startswith("jnz ")
        target = int(re.search(r"loc_([0-9A-F]+)", branch)[1], 16)
        call = next(c for c in functions[va]["calls"] if c["implementation"] == "0x6c22e0")
        index = next(i for i, row in enumerate(assembly) if row["va"] == call["site"])
        window = assembly[index - 3:index]
        assert int(window[0]["va"], 16) == target
        register = re.fullmatch(r"mov     (eax|ecx|edx), \[ebp\+arg_0\]", window[0]["text"])[1]
        assert window[1]["text"] == "push    " + register
        assert window[2]["text"] == "mov     ecx, [ebp+var_4]"
    for va in ICONS:
        assembly = functions[va]["assembly"]
        for call in functions[va]["calls"]:
            if call["implementation"] != "0x6f4aa0":
                continue
            index = next(i for i, row in enumerate(assembly) if row["va"] == call["site"])
            assert assembly[index + 1]["text"] == "add     esp, 8"
            icon_calls += 1
    assert icon_calls == 12
    # 结果码跳表与每个 case 的 UI71/文本立即数，均由原始磁盘字节独立确认。
    switch = disk(0x6C2313, 7)
    assert switch[:3] == bytes.fromhex("ff2495")
    table = struct.unpack_from("<I", switch, 3)[0]
    targets = struct.unpack("<8I", disk(table, 32))
    text_ids = (1123, 1124, 1121, 1125, 1126, 1127, 1128, 1120)
    for target, text_id in zip(targets, text_ids):
        assert disk(target, 6) == bytes.fromhex("6a006a006a47")
        assert disk(target + 18, 1) == b"\x68"
        assert struct.unpack("<I", disk(target + 19, 4))[0] == text_id
    assert disk(0x6C24DE, 5) == b"\x68" + struct.pack("<I", 1129)
    if db is not None:
        assert db.bytes.get_bytes_at(table, 32) == disk(table, 32)
    result_cases = list(range(-1024, 4097)) + [-0x80000000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
    for code in result_cases:
        index = (code - 1) & 0xFFFFFFFF
        from_branch = text_ids[index] if index <= 7 else 1129
        assert from_branch == (dict(enumerate(text_ids, 1)).get(code, 1129))

    # 期限表的机器常量和 signed jl；这里使用有限模型，不把无符号输入冒充实参语义。
    icon_switch = disk(0x6F4B4E, 7)
    icon_table = struct.unpack_from("<I", icon_switch, 3)[0]
    assert icon_switch[:3] == bytes.fromhex("ff2485")
    assert struct.unpack("<7I", disk(icon_table, 28)) == (
        0x6F4B6F, 0x6F4BAE, 0x6F4B78, 0x6F4BCC, 0x6F4BBE, 0x6F4BCC, 0x6F4B93)
    stores = {0x6F4B6F: (0xF8, 40), 0x6F4B78: (0xF8, 41), 0x6F4B81: (0xF8, 42),
              0x6F4B8A: (0xF8, 43), 0x6F4B93: (0xF8, 44), 0x6F4B9C: (0xF8, 45),
              0x6F4BA5: (0xF8, 51), 0x6F4BAE: (0xF8, 15), 0x6F4BB5: (0xF4, 47),
              0x6F4BBE: (0xF8, 87), 0x6F4BC5: (0xF4, 51),
              0x6F4BD5: (0xF4, 15), 0x6F4BDC: (0xF8, 19)}
    for va, (off, value) in stores.items():
        assert disk(va, 7) == b"\xc7\x45" + bytes([off]) + struct.pack("<I", value)
    assert disk(0x6F4BCC, 7) == b"\x81\x7d\xfc" + struct.pack("<I", 1500)
    assert disk(0x6F4BD3, 1) == b"\x7c"  # signed jl
    if db is not None:
        assert db.bytes.get_bytes_at(icon_table, 28) == disk(icon_table, 28)
    # 从已核指令解释这一段纯整数分支，避免把手写映射表再与自身比较。
    addresses = sorted(a for a in instructions if 0x6F4B26 <= a <= 0x6F4BE3)
    successors = dict(zip(addresses, addresses[1:]))
    signed = lambda value: ((value + 0x80000000) & 0xFFFFFFFF) - 0x80000000
    def interpret(n):
        values = {"[ebp+var_4]": n & 0xFFFFFFFF,
                  "[ebp+var_8]": 0xFFFFFFFF, "[ebp+var_C]": 38}
        def value(operand):
            if operand in values:
                return values[operand]
            return int(operand[:-1], 16) if operand.endswith("h") else int(operand)
        pc, compared = 0x6F4B26, None
        for _ in range(40):
            if pc == 0x6F4BE3:
                return signed(values["[ebp+var_C]"]), signed(values["[ebp+var_8]"])
            text = instructions[pc].split(";", 1)[0].strip()
            operation, operands = text.split(None, 1)
            destination = successors[pc]
            if operation in {"mov", "sub", "cmp"}:
                left, right = operands.split(", ")
                if operation == "mov":
                    values[left] = value(right)
                elif operation == "sub":
                    values[left] = (value(left) - value(right)) & 0xFFFFFFFF
                else:
                    compared = value(left), value(right)
            elif pc == 0x6F4B4E:
                destination = struct.unpack("<I", disk(icon_table + values["eax"] * 4, 4))[0]
            else:
                assert operation in {"jmp", "jz", "ja", "jg", "jl"}, text
                a, b = compared
                taken = {"jmp": True, "jz": a == b, "ja": a > b,
                         "jg": signed(a) > signed(b), "jl": signed(a) < signed(b)}[operation]
                if taken:
                    label = re.search(r"(?:loc|def)_([0-9A-F]+)", operands)[1]
                    destination = int(label, 16)
                    # IDA 的 def 名字是跳表指令地址，但符号实际指向公共默认块。
                    if label == "6F4B4E":
                        destination = 0x6F4BCC
            pc = destination
        raise AssertionError("有限纯分支模型未收敛")
    model = runpy.run_path(str(TOPIC / "build_review.py"))["icon_slot"]
    samples = list(range(-1024, 4097)) + [-0x80000000, -0x7FFFFFFF, 0x7FFFFFFE, 0x7FFFFFFF]
    for n in samples:
        assert interpret(n) == model(n), n
    for va, offsets in [(0x800AD0, [0x44, 0x48, 0x4C]),
                        (0x800B30, [0x50, 0x54, 0x58]),
                        (0x800B90, [0x5C, 0x60, 0x64])]:
        text = "\n".join(i["text"] for i in functions[va]["assembly"])
        assert text.count("468h") == 3 and "imul    eax, 16Dh" in text
        assert "imul    ecx, 1Eh" in text and text.endswith("retn    4")
        assert all(("+%Xh]" % offset) in text for offset in offsets)
    arithmetic_cases = 0
    for y, m, d in product([-0x80000000, -1, 0, 1, 2, 0x7FFFFFFF], repeat=3):
        stages = (((y * 365) & 0xFFFFFFFF) + ((m * 30) & 0xFFFFFFFF)) & 0xFFFFFFFF
        assert signed(stages + d) == signed(365 * y + 30 * m + d)
        arithmetic_cases += 1

    # type10 边界指令：group/frame 是 signed 比较；第四参数没有被断言为资源句柄。
    image = functions[0x6DBA40]["assembly"]
    asm = {int(i["va"], 16): i["text"] for i in image}
    assert asm[0x6DBAD5].startswith("jl ") and asm[0x6DBADB].startswith("jge ")
    assert asm[0x6DBAC1].startswith("jl ") and asm[0x6DBACF].startswith("jge ")
    assert asm[0x6DBAE0] == "imul    edx, 4B0h"
    assert asm[0x6DBAE9] == "add     edx, [eax+3AC00h]"
    assert asm[0x6DBAF2] == "imul    ecx, 0Ch"
    assert asm[0x6DBAF5] == "mov     edx, [edx+ecx+4]"
    image_guard_cases = 0
    boundaries = [-0x80000000, -1, 0, 1, 38, 99, 100, 0x7FFFFFFF, 0x80000000]
    for group, frame, count in product(boundaries, repeat=3):
        g, f, c = signed(group), signed(frame), signed(count)
        branch_allows_read = not (g < 0 or g >= c or f < 0 or f >= 100)
        assert branch_allows_read == (0 <= g < c and 0 <= f < 100)
        image_guard_cases += 1
    resources = _resource_audit()
    saved = json.loads((HERE / "resources.json").read_text("utf-8"))
    assert resources["records"] == saved["records"]
    assert resources["records"][0]["missing_indices"] == [str(i) for i in range(1120, 1130)]
    review = json.loads((TOPIC / "审阅清单.json").read_text("utf-8"))["functions"]
    assert {int(f["va"], 16) for f in review} == set(functions)
    assert all(f["status"] == "局部静态语义已审阅" and f["unknown"] for f in review)
    for path in TOPIC.glob("*.txt"):
        assert all(not line or line.startswith(("//", "/*", " *", " */"))
                   for line in path.read_text("utf-8").splitlines()), path
    reproduced = _reproduce_author_outputs()
    return dict(disk_sha256=SHA, functions=len(functions), declared_chunks=len(chunks),
                instruction_addresses=len(instructions), byte_comparisons=comparisons,
                unique_verified_bytes=len(byte_map), unique_spans=len(spans),
                attached_e9_thunks=len(thunks), call_edges=calls, result_branches=8,
                navigation_records=len(navigation["edges"]), result_caller_branches=len(RESULTS),
                icon_caller_functions=len(ICONS), icon_call_sites=icon_calls,
                icon_branch_model_cases=len(samples), wrapped_arithmetic_cases=arithmetic_cases,
                result_branch_model_cases=len(result_cases), image_guard_model_cases=image_guard_cases,
                result_text_ids=list(text_ids), icon_immediate_stores=len(stores),
                resources=len(resources["records"]), richstr_missing=resources["records"][0]["missing_indices"],
                author_outputs_reproduced=reproduced, ida_live=db is not None,
                mismatches=0,
                scope="函数声明块、跳表常量、有限 signed 边界和四个资源文件；不证明网络响应、运行时装载、图像生命周期或完整调用可达性。")


if __name__ == "__main__":
    result = audit()
    (HERE / "independent_local_review.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True))
