"""只读复核大厅玩家记录专题；不会改动EXE、IDA数据库或资源。"""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

import lzokay

# 动态载入解析器时不生成缓存，保证专题校验只读运行。
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    blob = (ROOT / "RnClient.exe").read_bytes()
    assert sha(blob) == EXPECTED, "EXE版本改变，需重新核对证据"
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    count = struct.unpack_from("<H", blob, pe+6)[0]
    optional = struct.unpack_from("<H", blob, pe+20)[0]
    base = struct.unpack_from("<I", blob, pe+52)[0]
    sections = [struct.unpack_from("<IIII", blob, pe+24+optional+40*i+8) for i in range(count)]

    def disk(ea, size):
        for virtual, rva, raw_size, raw_offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= raw_size:
                return blob[raw_offset+relative:raw_offset+relative+size]
        raise AssertionError(f"没有磁盘映射：{ea:#x}+{size}")

    audited_ranges = set()

    def check(row):
        ea, size = int(row["va"], 16), row["size"]
        actual = disk(ea, size)
        assert actual.hex() == row["disk_hex"] == row["idb_hex"], row["va"]
        assert row["matching"] and len(actual) == size
        audited_ranges.add((ea, ea+size))
        if "target" in row:
            assert actual[0] == 0xE9 and size == 5
            assert ea+5+int.from_bytes(actual[1:], "little", signed=True) == int(row["target"], 16)

    functions, sources, thunks, tails, instruction_ranges, rtc_calls = {}, {}, set(), set(), set(), set()
    for source in sorted((HERE / "证据").glob("*.json")):
        data = read_json(source)
        if "functions" not in data:
            continue
        assert data["disk_sha256"] == EXPECTED
        for function in data["functions"]:
            va = function["va"]
            assert va not in functions, "同一函数应只有一个主证据条目"
            functions[va] = function
            sources[va] = ["证据/"+source.name]
            assert function["bytes_match_disk"] and function["pseudocode"]
            declared = {(int(c["start_va"], 16), int(c["end_va"], 16)) for c in function["declared_chunks"]}
            saved = {(int(r["va"], 16), int(r["va"], 16)+r["size"]) for r in function["chunk_byte_ranges"]}
            assert declared == saved, (va, "声明块未完整保存")
            covered = []
            for row in function["byte_ranges"]:
                check(row)
                span = (int(row["va"], 16), int(row["va"], 16)+row["size"])
                assert any(a <= span[0] < span[1] <= b for a, b in declared)
                covered.append(span)
                instruction_ranges.add(span)
            for row in function["chunk_byte_ranges"]:
                check(row)
            for instruction in function["assembly"]:
                assert any(a <= int(instruction["va"], 16) < b for a, b in covered)
            for chunk in function["declared_chunks"]:
                if not chunk["is_main"]:
                    tails.add((va, chunk["start_va"], chunk["end_va"]))
            rtc_calls.update((va, c["site"]) for c in function["calls"] if c["implementation"] == "0x91f700")
        for row in data["thunks"]:
            check(row)
            thunks.add(row["va"])

    data = read_json(HERE / "证据/data_ranges.json")
    assert data["disk_sha256"] == EXPECTED
    for row in data["ranges"]:
        check(row)
    selected = {
        "0x828fb6": {52: "0x829986", 53: "0x8299d3"},
        "0x82b0ca": {0: "0x82b0d1", 3: "0x82b145", 43: "0x82b6b5", 45: "0x82b715"},
        "0x6be354": {2: "0x6be37d", 5: "0x6be39f", 8: "0x6be3c1", 20: "0x6be47c", 63: "0x6be647", 64: "0x6be658"},
    }
    assert {s["site"] for s in data["switches"]} == set(selected)
    for switch in data["switches"]:
        jumps = disk(int(switch["jumps"], 16), switch["jump_count"]*switch["jump_size"])
        assert switch["jump_size"] == 4 and switch["index_base"] == 0
        values = disk(int(switch["values"], 16), switch["ncases"]*switch["value_size"]) if int(switch["values"], 16) else None
        mapping = {}
        for case in switch["cases"]:
            for number in case["values"]:
                assert 0 <= number < switch["ncases"]
                index = int.from_bytes(values[number*switch["value_size"]:(number+1)*switch["value_size"]], "little") if values is not None else number
                assert index < switch["jump_count"]
                target = hex(struct.unpack_from("<I", jumps, index*4)[0])
                assert target == case["target"]
                mapping[number] = target
        assert all(mapping.get(n) == target for n, target in selected[switch["site"]].items())

    rtc = read_json(HERE / "证据/rtc_ranges.json")
    assert rtc["disk_sha256"] == EXPECTED
    assert {(f["function_va"], f["call_va"]) for f in rtc["frames"]} == rtc_calls
    names = {r["va"]: r for r in rtc["name_ranges"]}
    local_count, local_map = 0, {}
    for frame in rtc["frames"]:
        for row in (frame["frame"], frame["variables"]):
            check(row)
        count, pointer = struct.unpack("<iI", bytes.fromhex(frame["frame"]["disk_hex"]))
        assert count == frame["local_count"] == len(frame["locals"])
        assert pointer == int(frame["variables"]["va"], 16)
        load = disk(int(frame["pointer_load_va"], 16), 6)
        assert load[:2] == b"\x8d\x15" and int.from_bytes(load[2:], "little") == int(frame["frame"]["va"], 16)
        local_count += count
        for index, local in enumerate(frame["locals"]):
            offset, size, name = struct.unpack_from("<iII", bytes.fromhex(frame["variables"]["disk_hex"]), index*12)
            assert (offset, size, name) == (local["ebp_offset"], local["size"], int(local["name_va"], 16))
            text = bytes.fromhex(names[local["name_va"]]["disk_hex"])
            assert text[-1] == 0 and text[:-1].decode("ascii") == local["name"]
            local_map[(frame["function_va"], local["name"])] = size
    for row in names.values():
        check(row)
    assert local_map[("0x6a32a0", "xData")] == local_map[("0x6a3390", "xData")] == 12
    assert local_map[("0x6ab0d0", "rName")] == 33 and local_map[("0x6ae5a0", "szTmp")] == 128

    # 引用同目录只读资源解析函数，避免验证器使用另一种记录切分规则。
    spec = importlib.util.spec_from_file_location("topic_resource_extract", HERE / "证据/提取资源.py")
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    resources = read_json(HERE / "证据/resource_samples.json")["records"]
    for record in resources:
        packed = (ROOT / record["source"]).read_bytes()
        assert sha(packed) == record["source_sha256"] and len(packed) == record["source_bytes"]
        key = packed[0]
        expanded_size, packed_size = struct.unpack("<II", bytes((b-key) & 255 for b in packed[1:9]))
        assert key == record["key"] and expanded_size == record["expanded_bytes"]
        assert packed_size == record["packed_bytes"] == len(packed)-9
        plain = lzokay.decompress(bytes((b-key) & 255 for b in packed[9:]), expanded_size)
        assert plain == (HERE / "证据" / record["decoded_file"]).read_bytes()
        assert sha(plain) == record["decoded_sha256"]
        text = plain.decode(record["codec"], errors="strict")
        assert text.encode(record["codec"]) == plain and record["strict_roundtrip"]
        requested = set(record["requested_indices"])
        actual = [s for s in parser.sections(text) if s["fields"].get("indx", "").isdigit() and int(s["fields"]["indx"]) in requested]
        assert actual == record["sections"]
        assert sorted(requested - {int(s["fields"]["indx"]) for s in actual}) == record["missing_indices"]
    prop = next(r for r in resources if r["source"] == "Data/Prop.kpd")
    assert prop["requested_indices"] == prop["missing_indices"] == [535, 540]
    strings = next(r for r in resources if r["source"] == "Data/RichStr.kpd")
    assert len(strings["sections"]) == 5 and not strings["missing_indices"]

    reviews = read_json(HERE / "函数审阅清单.json")["functions"]
    assert len(functions) == len(reviews) == 50 and {r["va"] for r in reviews} == set(functions)
    for row in reviews:
        assert all(row[field] for field in ["status", "scope", "conclusion", "unknown"])
        assert row["evidence"] == sources[row["va"]]
    documents = sorted(HERE.glob("0[0-5]_*.txt"))
    assert len(documents) == 6
    for path in documents:
        assert all(line.startswith("//") for line in path.read_text(encoding="utf-8").splitlines())

    # 合并重叠字节后计数，避免指令范围、声明块、RTC表重复计入。
    union = []
    for lo, hi in sorted(audited_ranges):
        if union and lo <= union[-1][1]:
            union[-1][1] = max(union[-1][1], hi)
        else:
            union.append([lo, hi])
    assert len(rtc["frames"]) == 17 and local_count == 38
    print(json.dumps({"结果": "通过", "函数": len(functions), "函数指令范围": len(instruction_ranges),
        "异常尾块": len(tails), "唯一跳板": len(thunks), "分派数据范围": len(data["ranges"]),
        "RTC函数": len(rtc["frames"]), "RTC局部项": local_count,
        "RTC原证范围": 2*len(rtc["frames"])+len(names), "资源文件": len(resources),
        "唯一局部范围": len(audited_ranges), "去重字节数": sum(b-a for a, b in union)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
