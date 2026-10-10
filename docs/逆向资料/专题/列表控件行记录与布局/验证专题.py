"""只读复核列表行布局专题；不改 EXE、资源、IDB 或保存证据。"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
SOURCES = {"list_functions.json": 21, "list_dependencies.json": 15, "list_lifecycle.json": 6}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    blob = (ROOT / "RnClient.exe").read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED, "EXE版本改变，须重新导出证据"
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

    def check(row):
        ea, size = int(row["va"], 16), row["size"]
        actual = disk(ea, size)
        assert actual.hex() == row["disk_hex"] == row["idb_hex"], row["va"]
        assert row["matching"] and len(actual) == size
        audited.add((ea, ea+size))
        if "target" in row:
            assert size == 5 and actual[0] == 0xE9
            target = hex(ea+5+int.from_bytes(actual[1:], "little", signed=True))
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
            functions[va] = function
            sources[va] = ["证据/"+filename]
            assert function["bytes_match_disk"] and function["pseudocode"] and function["assembly"]
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
            local_assembly = {}
            for instruction in function["assembly"]:
                address = int(instruction["va"], 16)
                assert any(a <= address < b for a, b in covered)
                assert instruction["va"] not in local_assembly
                local_assembly[instruction["va"]] = instruction["text"]
            assembly[va] = local_assembly
            tails.update((va, c["start_va"], c["end_va"]) for c in function["declared_chunks"] if not c["is_main"])
        for row in data["thunks"]:
            check(row)

    for owner, function in functions.items():
        for call in function["calls"]:
            assert call["site"] in assembly[owner]
            current, seen = call["target"], set()
            for bridge in call["thunks"]:
                assert bridge == current and bridge not in seen
                seen.add(bridge)
                current = thunks[bridge]
            assert current == call["implementation"], (owner, call["site"], "调用链目标")

    data = read_json(HERE / "证据/list_data.json")
    assert data["disk_sha256"] == EXPECTED
    check(data["vtable"])
    assert data["vtable"]["va"] == "0xa307d4" and data["vtable"]["size"] == 272
    for row in data["thunk_ranges"]:
        check(row)
    targets = {0: "0x8e39d0", 232: "0x8f7d40", 244: "0x8f4690", 252: "0x8f42d0"}
    assert len(data["slots"]) == len(targets)
    assert {s["offset"] for s in data["slots"]} == set(targets)
    table = bytes.fromhex(data["vtable"]["disk_hex"])
    for slot in data["slots"]:
        entry = hex(struct.unpack_from("<I", table, slot["offset"])[0])
        assert entry == slot["entry"]
        current = entry
        seen = set()
        for bridge in slot["thunks"]:
            assert bridge == current and bridge not in seen
            seen.add(bridge)
            current = thunks[bridge]
        assert current == slot["implementation"] == targets[slot["offset"]]

    strings = {}
    assert len(data["strings"]) == 51 and len(data["references"]) == 101
    for row in data["strings"]:
        check(row)
        raw = bytes.fromhex(row["disk_hex"])
        assert raw[-1] == 0 and b"\0" not in raw[:-1]
        assert raw[:-1].decode("ascii") == row["text"]
        assert row["va"] not in strings
        strings[row["va"]] = row["text"]
    references = {}
    for row in data["references"]:
        owner, site, target = row["function_va"], row["instruction_va"], row["target_va"]
        assert owner == "0x8f8080" and site in assembly[owner]
        assert strings[target] == row["text"] and site not in references
        raw = disk(int(site, 16), 5)
        assert raw[0] == 0x68 and hex(struct.unpack_from("<I", raw, 1)[0]) == target
        assert assembly[owner][site].startswith("push")
        references[site] = row["text"]
    colors = {
        "0x8f8cce": "NorFontBColor", "0x8f8ced": "NorFontColor",
        "0x8f8d10": "DownFontBColor", "0x8f8d2e": "DownFontColor",
        "0x8f8d51": "InFontBColor", "0x8f8d70": "InFontColor",
        "0x8f8d92": "DisFontBColor", "0x8f8db1": "DisFontColor",
    }
    assert all(references[site] == text for site, text in colors.items())

    # 关键边界直接比对磁盘操作码，同时要求所在指令已在函数证据中保存。
    guards = {
        "0x8f4050": {"0x8f405c": "7d"},
        "0x8f4c20": {"0x8f4c30": "0f8d"},
        "0x8f4ba0": {"0x8f4be4": "f7f9", "0x8f4bf9": "f7f9"},
        "0x8f3fd0": {"0x8f4014": "7d", "0x8f4016": "85c0", "0x8f4018": "7c"},
    }
    for owner, sites in guards.items():
        for site, opcode in sites.items():
            assert site in assembly[owner]
            assert disk(int(site, 16), len(opcode)//2).hex() == opcode, site

    reviews = read_json(HERE / "函数审阅清单.json")["functions"]
    assert len(functions) == len(reviews) == 42 and {r["va"] for r in reviews} == set(functions)
    for row in reviews:
        assert row["status"] in {"主体已审阅", "局部已审阅"}
        assert all(row[field] for field in ["scope", "conclusion", "unknown"])
        assert row["evidence"] == sources[row["va"]]
    documents = sorted(HERE.glob("0[0-4]_*.txt"))
    assert len(documents) == 5
    for path in documents:
        assert all(line.startswith("//") for line in path.read_text(encoding="utf-8").splitlines()), path

    # 完整块、指令段和数据段可能重叠；统计按地址合并后再求字节数。
    union = []
    for lo, hi in sorted(audited):
        if union and lo <= union[-1][1]:
            union[-1][1] = max(union[-1][1], hi)
        else:
            union.append([lo, hi])
    print(json.dumps({"结果": "通过", "函数": len(functions), "函数指令范围": len(instruction_ranges),
        "异常尾块": len(tails), "唯一跳板": len(thunks), "虚表槽": len(data["slots"]),
        "属性字符串": len(strings), "字符串引用": len(references), "正文": len(documents),
        "唯一局部范围": len(audited), "去重字节数": sum(b-a for a, b in union)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
