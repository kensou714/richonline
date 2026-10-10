"""只读核验颜色专题；不修改EXE、资源、IDB或保存的证据。"""
import hashlib
import importlib.util
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
SOURCES = {"color_functions.json": 5, "color_narrow.json": 3}
OWNERS = {"0x8e4ff0": 22, "0x8ee7b0": 12, "0x8f8080": 12,
          "0x900cd0": 1, "0x901d30": 1, "0x904480": 4,
          "0x90a8f0": 1, "0x90d9b0": 8}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    blob = (ROOT / "RnClient.exe").read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED, "EXE版本改变，须重新提取证据"
    assert blob[:2] == b"MZ"
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    assert blob[pe:pe+4] == b"PE\0\0"
    count = struct.unpack_from("<H", blob, pe+6)[0]
    optional = struct.unpack_from("<H", blob, pe+20)[0]
    assert struct.unpack_from("<H", blob, pe+24)[0] == 0x10B, "本专题针对PE32"
    base = struct.unpack_from("<I", blob, pe+52)[0]
    sections = [struct.unpack_from("<IIII", blob, pe+24+optional+40*i+8) for i in range(count)]

    def disk(ea, size):
        assert size > 0
        for virtual, rva, raw_size, raw_offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= raw_size:
                offset = raw_offset+relative
                assert offset+size <= len(blob), "PE节超出文件"
                return blob[offset:offset+size]
        raise AssertionError(f"没有磁盘映射：{ea:#x}+{size}")

    audited, instruction_ranges, tails, thunks = set(), set(), set(), {}

    def relative_target(row, opcode):
        raw = bytes.fromhex(row["disk_hex"])
        assert len(raw) == 5 and raw[0] == opcode, row["va"]
        return hex(int(row["va"], 16)+5+int.from_bytes(raw[1:], "little", signed=True))

    def check(row):
        ea, size = int(row["va"], 16), row["size"]
        actual = disk(ea, size)
        assert actual.hex() == row["disk_hex"] == row["idb_hex"], row["va"]
        assert row["matching"] and len(actual) == size
        audited.add((ea, ea+size))
        if "target" in row:
            target = relative_target(row, 0xE9)
            assert target == row["target"], (row["va"], "跳板目标")
            assert row["va"] not in thunks or thunks[row["va"]] == target
            thunks[row["va"]] = target

    functions, sources, assembly = {}, {}, {}
    for filename, expected_count in SOURCES.items():
        data = read_json(HERE / "证据" / filename)
        assert data["disk_sha256"] == EXPECTED and len(data["functions"]) == expected_count
        for function in data["functions"]:
            va = function["va"]
            assert va not in functions, "一个函数应只有一条主证据"
            functions[va], sources[va] = function, ["证据/"+filename]
            assert function["bytes_match_disk"] and function["assembly"]
            if va == "0x92bedd":
                assert not function["pseudocode"] and function["decompile_error"]
            else:
                assert function["pseudocode"]
            declared = {(int(c["start_va"], 16), int(c["end_va"], 16)) for c in function["declared_chunks"]}
            saved = {(int(r["va"], 16), int(r["va"], 16)+r["size"]) for r in function["chunk_byte_ranges"]}
            assert declared == saved, (va, "声明块必须完整保存")
            assert any(c["is_main"] and c["start_va"] == va for c in function["declared_chunks"])
            covered = []
            for row in function["byte_ranges"]:
                check(row)
                span = (int(row["va"], 16), int(row["va"], 16)+row["size"])
                assert any(a <= span[0] < span[1] <= b for a, b in declared)
                covered.append(span)
                instruction_ranges.add(span)
            for row in function["chunk_byte_ranges"]:
                check(row)
            local = {}
            for instruction in function["assembly"]:
                address = int(instruction["va"], 16)
                assert any(a <= address < b for a, b in covered)
                assert instruction["va"] not in local
                local[instruction["va"]] = instruction["text"]
            assembly[va] = local
            tails.update((va, c["start_va"], c["end_va"]) for c in function["declared_chunks"] if not c["is_main"])
        for row in data["thunks"]:
            check(row)
    assert set(functions) == {"0x8e0450", "0x8e1c40", "0x924720", "0x92be08",
                              "0x92be80", "0x92bedd", "0x93ebc0", "0x93ebd9"}
    assert tails == {("0x92bedd", "0x60e9e2", "0x60e9e7"),
                     ("0x92bedd", "0x93ffce", "0x93ffdb")}
    for owner, function in functions.items():
        for call in function["calls"]:
            assert call["site"] in assembly[owner]
            raw = disk(int(call["site"], 16), 6)
            if raw[0] == 0xE8:
                actual_target = hex(int(call["site"], 16)+5+int.from_bytes(raw[1:5], "little", signed=True))
            elif owner == "0x8e0450" and call["site"] in {"0x8e0465", "0x8e0487"}:
                assert raw[:2] == b"\xff\xd6", "lstrlenA通过ESI调用"
                load = disk(0x8E045E, 6)
                assert load[:2] == b"\x8b\x35"
                actual_target = hex(struct.unpack_from("<I", load, 2)[0])
            else:
                assert raw[:2] == b"\xff\x15", (owner, call["site"], "未支持调用编码")
                actual_target = hex(struct.unpack_from("<I", raw, 2)[0])
            assert actual_target == call["target"], (owner, call["site"], "调用操作数")
            current, seen = call["target"], set()
            for bridge in call["thunks"]:
                assert bridge == current and bridge not in seen
                seen.add(bridge)
                current = thunks[bridge]
            assert current == call["implementation"], (owner, call["site"], "调用链")

    data = read_json(HERE / "证据/color_data.json")
    assert data["disk_sha256"] == EXPECTED
    constants = {r["va"]: r for r in data["ranges"]}
    assert set(constants) == {"0xa305a0", "0x60f464", "0x610b6b"}
    for row in data["ranges"]:
        check(row)
    assert struct.unpack("<d", bytes.fromhex(constants["0xa305a0"]["disk_hex"]))[0] == 16.0
    assert thunks["0x60f464"] == "0x93ebc0" and thunks["0x610b6b"] == "0x8e1c40"
    assert data["runtime_flag"]["va"] == "0xad0e80" and "disk_hex" not in data["runtime_flag"]
    assert disk(0x8E1C40, 22).hex() == "8b4424088b5424048b4c240c8d0480894cc220c20c00"
    guards = {"0x8e0495": "b809000000", "0x8e049b": "2bc6",
              "0x8e0517": "0fafc1", "0x8e051a": "03f8"}
    for site, opcode in guards.items():
        assert site in assembly["0x8e0450"]
        assert disk(int(site, 16), len(opcode)//2).hex() == opcode, site
    expected_math = {"0x8e04b8": "0x92be80", "0x8e04bd": "0x92be08",
                     "0x8e04de": "0x92be80", "0x8e04e3": "0x92be08",
                     "0x8e0507": "0x92be80", "0x8e050c": "0x92be08",
                     "0x8e0537": "0x924720", "0x8e053f": "0x92be08"}
    math_calls = {c["site"]: c["implementation"] for c in functions["0x8e0450"]["calls"]}
    assert all(math_calls[site] == target for site, target in expected_math.items())

    calls = read_json(HERE / "证据/color_calls.json")
    assert calls["disk_sha256"] == EXPECTED
    check(calls["entry"])
    assert relative_target(calls["entry"], 0xE9) == "0x8e0450"
    assert len(calls["references"]) == 62 and len(calls["sites"]) == 61
    sites = {s["site"]: s for s in calls["sites"]}
    assert len(sites) == 61 and Counter(s["owner_va"] for s in sites.values()) == OWNERS
    assert {o["va"] for o in calls["owners"]} == set(OWNERS)
    assert all(o["pseudocode"] and o["scope"] for o in calls["owners"])
    assert {(r["source_va"], r["target_va"], r["kind"]) for r in calls["references"]} == (
        {(site, "0x60c9a3", 17) for site in sites} | {("0x60c9a3", "0x8e0450", 19)})
    strings, contexts = {}, {}
    assert len(calls["strings"]) == 53
    for row in calls["strings"]:
        check(row)
        raw = bytes.fromhex(row["disk_hex"])
        assert raw[-1] == 0 and b"\0" not in raw[:-1]
        assert raw[:-1].decode("ascii") == row["text"] and row["va"] not in strings
        strings[row["va"]] = row["text"]
    string_references = set()
    for site, saved in sites.items():
        rows = saved["context"]
        assert len({r["va"] for r in rows}) == len(rows)
        local = {r["va"]: r for r in rows}
        assert site in local and relative_target(local[site], 0xE8) == "0x60c9a3"
        for row in rows:
            check(row)
            assert row["va"] not in contexts or contexts[row["va"]] == row
            contexts[row["va"]] = row
            for ref in row["data_refs"]:
                assert strings[ref["target_va"]] == ref["text"]
                raw = bytes.fromhex(row["disk_hex"])
                assert len(raw) == 5 and raw[0] == 0x68
                assert hex(struct.unpack_from("<I", raw, 1)[0]) == ref["target_va"]
                string_references.add((row["va"], ref["target_va"]))

    reviews = read_json(HERE / "调用点审阅清单.json")["sites"]
    assert len(reviews) == 61 and {r["site"] for r in reviews} == set(sites)
    shared = {r["site"] for r in reviews if r.get("shared_tail")}
    assert shared == {"0x8e5223", "0x8e5330"}
    style_count, direct_count = 0, 0
    for review in reviews:
        site = review["site"]
        assert review["owner"] == sites[site]["owner_va"]
        assert review["status"] == "调用点局部已审阅"
        assert all(review[f] for f in ["scope", "conclusion", "unknown"])
        assert review["evidence"] == ["证据/color_calls.json"]
        rows = sites[site]["context"]
        index = next(i for i, row in enumerate(rows) if row["va"] == site)
        before, after = rows[:index], rows[index+1:]
        preceding = [ref["text"] for row in before for ref in row["data_refs"]]
        if site not in shared:
            assert preceding[-1] == review["key"], (site, "取值属性")
        else:
            assert preceding[-1] in review["key"].split(" | ")
        if "presence_key" in review:
            assert review["presence_key"] in preceding
        if review["kind"] == "direct":
            direct_count += 1
            # MOV r/m32,EAX；只接受无SIB的disp8/disp32控件字段写入。
            store = next(r for r in after[:3] if r["text"].startswith("mov") and r["text"].endswith(", eax"))
            raw = bytes.fromhex(store["disk_hex"])
            assert raw[0] == 0x89 and (raw[1] >> 3) & 7 == 0 and raw[1] & 7 != 4
            mode = raw[1] >> 6
            assert mode in {1, 2}
            offset = int.from_bytes(raw[2:], "little", signed=True)
            assert offset == review["offset"], (site, "字段位移")
        else:
            assert review["kind"] == "style"
            style_count += 1
            setter_index = next(i for i, r in enumerate(after) if r["text"].startswith("call"))
            assert relative_target(after[setter_index], 0xE8) == "0x610b6b"
            pushes = [bytes.fromhex(r["disk_hex"]) for r in after[:setter_index] if r["text"].startswith("push")]
            assert len(pushes) == 3 and pushes[0] == b"\x50"
            assert pushes[1] == bytes([0x6A, review["state"]])
            assert len(pushes[2]) == 1 and 0x50 <= pushes[2][0] <= 0x57
            assert review["offset"] == review["base_offset"]+40*review["state"]+32
    # 每组持久寄存器的基址LEA已在首调用上下文保存；后续同组复用该寄存器。
    bases = {"0x8e53ae": 164, "0x8eeb3a": 576, "0x8ef4c8": 752,
             "0x8efe54": 928, "0x8f8213": 596, "0x9047c9": 576}
    for site, offset in bases.items():
        raw = bytes.fromhex(contexts[site]["disk_hex"])
        assert raw[0] == 0x8D and raw[1] >> 6 == 2 and raw[1] & 7 != 4
        assert struct.unpack_from("<i", raw, 2)[0] == offset
    groups = {"0x8e4ff0": [164]*8, "0x8ee7b0": [576]*4+[752]*4+[928]*4,
              "0x8f8080": [596]*4, "0x904480": [576]*4}
    for owner, offsets in groups.items():
        group = sorted((r for r in reviews if r["owner"] == owner and r["kind"] == "style"),
                       key=lambda r: int(r["site"], 16))
        assert [r["base_offset"] for r in group] == offsets
    for source, target in [("0x8e51ae", "0x8e521d"), ("0x8e52bb", "0x8e532a")]:
        raw = bytes.fromhex(contexts[source]["disk_hex"])
        assert len(raw) == 2 and raw[0] == 0xEB
        assert hex(int(source, 16)+2+int.from_bytes(raw[1:], "little", signed=True)) == target

    function_reviews = read_json(HERE / "函数审阅清单.json")["functions"]
    assert len(function_reviews) == 8 and {r["va"] for r in function_reviews} == set(functions)
    assert Counter(r["status"] for r in function_reviews) == {"主体已审阅": 5, "局部已审阅": 3}
    for row in function_reviews:
        assert all(row[f] for f in ["scope", "conclusion", "unknown"])
        assert row["evidence"] == sources[row["va"]]
    documents = sorted(HERE.glob("0[0-4]_*.txt"))
    assert len(documents) == 5
    for path in documents:
        assert all(line.startswith("//") for line in path.read_text(encoding="utf-8").splitlines()), path

    model = load_module("color_model", HERE / "颜色模型.py")
    model_result = model.verify_model()
    resource = load_module("color_resources", HERE / "证据/提取资源.py")
    samples = read_json(HERE / "证据/resource_samples.json")["records"]
    assert len(samples) == 3 and [r["source"] for r in samples] == resource.SELECTED
    colors = 0
    for saved in samples:
        raw = (ROOT / saved["source"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == saved["source_sha256"] and len(raw) == saved["source_bytes"]
        assert saved["key_ascii"] == "RichNet" and saved["transform"] == "(cipher[i]-key[i%7])&255"
        plain = resource.decode(raw)
        assert hashlib.sha256(plain).hexdigest() == saved["decoded_sha256"] and len(plain) == saved["decoded_bytes"]
        assert resource.colors(plain) == saved["colors"]
        for row in saved["colors"]:
            assert re.fullmatch(r"0x[0-9a-fA-F]{8}", row["value"])
            assert model.parse_hex(row["value"]) == int(row["value"], 16)
        colors += len(saved["colors"])
    assert colors == 2767 and model_result["position_cases"] == 67056
    union = []
    for lo, hi in sorted(audited):
        if union and lo <= union[-1][1]:
            union[-1][1] = max(union[-1][1], hi)
        else:
            union.append([lo, hi])
    print(json.dumps({"结果": "通过", "函数": len(functions), "函数指令范围": len(instruction_ranges),
        "非连续尾块": len(tails), "唯一跳板": len(thunks), "调用点": len(sites),
        "直接字段调用": direct_count, "四态setter调用": style_count, "属性字符串": len(strings),
        "字符串引用": len(string_references), "正文": len(documents), "资源": len(samples),
        "资源颜色项": colors, "有限域位置场景": model_result["position_cases"],
        "唯一局部范围": len(audited), "去重字节数": sum(b-a for a, b in union)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
