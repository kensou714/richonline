"""只读复核专题：PE局部范围、尾块、数据表、资源原文和逐函数覆盖。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    blob = (ROOT / "RnClient.exe").read_bytes()
    assert sha(blob) == EXPECTED, "当前EXE指纹已变化，需重新评估局部证据"
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    count = struct.unpack_from("<H", blob, pe+6)[0]
    optional = struct.unpack_from("<H", blob, pe+20)[0]
    base = struct.unpack_from("<I", blob, pe+52)[0]
    sections = [struct.unpack_from("<IIII", blob, pe+24+optional+40*i+8)
                for i in range(count)]

    def disk(ea, size):
        for virtual, rva, raw_size, raw_offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= raw_size:
                return blob[raw_offset+relative:raw_offset+relative+size]
        raise AssertionError(f"无PE原始映射：{ea:#x}")

    def check(row):
        actual = disk(int(row["va"], 16), row["size"])
        assert actual.hex() == row["disk_hex"] == row["idb_hex"], row["va"]
        assert row["matching"], row["va"]
        if "target" in row:
            assert actual[0] == 0xE9 and len(actual) == 5
            target = int(row["va"], 16)+5+int.from_bytes(actual[1:], "little", signed=True)
            assert target == int(row["target"], 16)

    unique, function_ranges, thunks, tails = set(), set(), set(), set()
    rtc_calls = set()
    evidence = {}
    for source in sorted((HERE / "证据").glob("*.json")):
        data = json.loads(source.read_text(encoding="utf-8"))
        if "functions" not in data:
            continue
        assert data["disk_sha256"] == EXPECTED
        for function in data["functions"]:
            unique.add(function["va"])
            evidence.setdefault(function["va"], []).append("证据/"+source.name)
            assert function["bytes_match_disk"] and function["pseudocode"]
            rtc_calls.update((function["va"], c["site"]) for c in function["calls"]
                             if c["implementation"] == "0x91f700")
            covered = []
            for row in function["byte_ranges"]:
                check(row)
                function_ranges.add((row["va"], row["size"]))
                covered.append((int(row["va"], 16), int(row["va"], 16)+row["size"]))
            for chunk in function["declared_chunks"]:
                lo, hi = int(chunk["start_va"], 16), int(chunk["end_va"], 16)
                instructions = [i for i in function["assembly"] if lo <= int(i["va"], 16) < hi]
                assert instructions, (function["va"], chunk)
                for instruction in instructions:
                    assert any(a <= int(instruction["va"], 16) < b for a, b in covered)
                if not chunk["is_main"]:
                    tails.add((function["va"], chunk["start_va"], chunk["end_va"]))
        for row in data["thunks"]:
            check(row)
            thunks.add(row["va"])
    data_ranges = json.loads((HERE / "证据/data_ranges.json").read_text(encoding="utf-8"))
    for row in data_ranges["ranges"]:
        check(row)
    rtc = json.loads((HERE / "证据/rtc_ranges.json").read_text(encoding="utf-8"))
    assert rtc["disk_sha256"] == EXPECTED
    assert {(f["function_va"], f["call_va"]) for f in rtc["frames"]} == rtc_calls
    names = {r["va"]: r for r in rtc["name_ranges"]}
    rtc_ranges, rtc_locals = 0, 0
    for frame in rtc["frames"]:
        assert frame["local_count"] == len(frame["locals"])
        for row in (frame["frame"], frame["variables"]):
            check(row)
            rtc_ranges += 1
        count, pointer = struct.unpack("<iI", bytes.fromhex(frame["frame"]["disk_hex"]))
        assert count == frame["local_count"] and pointer == int(frame["variables"]["va"], 16)
        load = disk(int(frame["pointer_load_va"], 16), 6)
        assert load[:2] == b"\x8d\x15" and int.from_bytes(load[2:], "little") == int(frame["frame"]["va"], 16)
        rtc_locals += frame["local_count"]
        for index, local in enumerate(frame["locals"]):
            assert local["size"] > 0 and local["ebp_offset"] < 0
            offset, size, name = struct.unpack_from("<iII", bytes.fromhex(frame["variables"]["disk_hex"]), index*12)
            assert (offset, size, name) == (local["ebp_offset"], local["size"], int(local["name_va"], 16))
            raw_name = bytes.fromhex(names[local["name_va"]]["disk_hex"])
            assert raw_name[-1] == 0 and raw_name[:-1].decode("ascii") == local["name"]
    for row in rtc["name_ranges"]:
        check(row)
        rtc_ranges += 1
    assert len(rtc["frames"]) == 19 and rtc_locals == 169
    samples = json.loads((HERE / "证据/resource_samples.json").read_text(encoding="utf-8"))
    for record in samples["records"]:
        raw = (ROOT / record["source"]).read_bytes()
        assert sha(raw) == record["source_sha256"] and len(raw) == record["source_bytes"]
        key = raw[0]
        expanded, packed = struct.unpack("<II", bytes((b-key) & 255 for b in raw[1:9]))
        assert key == record["key"] and expanded == record["expanded_bytes"]
        assert packed == record["packed_bytes"] == len(raw)-9
        plain = lzokay.decompress(bytes((b-key) & 255 for b in raw[9:]), expanded)
        assert plain == (HERE / "证据" / record["decoded_file"]).read_bytes()
        assert sha(plain) == record["decoded_sha256"]
        text = plain.decode(record["codec"], errors="strict")
        assert text.encode(record["codec"]) == plain and record["strict_roundtrip"]
        lines = text.splitlines()
        for section in record["sections"]:
            start = section["line"]-1
            assert lines[start:start+len(section["raw_lines"])] == section["raw_lines"]
    values = next(r for r in samples["records"] if r["source"] == "Data/GValue.kpd")
    assert values["sections"][0]["fields"] == {"indx": "30", "value": "2"}
    reviews = json.loads((HERE / "函数审阅清单.json").read_text(encoding="utf-8"))["functions"]
    assert len(reviews) == len(unique) and {r["va"] for r in reviews} == unique
    for row in reviews:
        assert row["status"] and row["conclusion"] and row["unknown"]
        assert sorted(row["evidence"]) == sorted(evidence[row["va"]])
    for path in HERE.glob("0[0-5]_*.txt"):
        assert all(line.startswith("//") for line in path.read_text(encoding="utf-8").splitlines())
    print(json.dumps({"结果": "通过", "唯一函数": len(unique), "函数指令范围": len(function_ranges),
        "异常尾块": len(tails), "唯一跳板": len(thunks), "数据范围": len(data_ranges["ranges"]),
        "RTC函数": len(rtc["frames"]), "RTC局部项": rtc_locals, "RTC原证范围": rtc_ranges,
        "资源文件": len(samples["records"]), "当前冬眠计数": 2}, ensure_ascii=False))


if __name__ == "__main__":
    main()
