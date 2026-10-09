"""只读复核登录与大厅第三批证据；本脚本不依赖 IDA，也不运行客户端。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOPIC = ROOT.parent
CLIENT = TOPIC.parents[3] / "RnClient.exe"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    meta = load(ROOT / "版本核验.json")
    data = CLIENT.read_bytes()
    assert digest(data) == meta["disk_sha256"], "磁盘客户端版本已改变"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 52)[0]
    sections = [struct.unpack_from("<IIII", data, pe + 24 + optional_size + i * 40 + 8)
                for i in range(count)]

    def read_va(address, length):
        rva = address - base
        for _, start, raw_size, raw_offset in sections:
            if start <= rva and rva + length <= start + raw_size:
                offset = raw_offset + rva - start
                return data[offset:offset + length]
        raise AssertionError(f"区间不在单个 PE 原始节内：{address:#x}")

    for entry in meta["files"]:
        content = (ROOT / entry["path"]).read_bytes()
        assert digest(content) == entry["sha256"], entry["path"]
        json.loads(content.decode("utf-8"))
    for entry in meta["functions"] + meta["unrecognized_ranges"]:
        raw = read_va(int(entry["va"], 16), entry["byte_count"])
        assert digest(raw) == entry["disk_sha256"] == entry["idb_sha256"], entry["va"]
        assert entry["matches_disk"]
    links = load(ROOT / "links_and_tables.json")
    for entry in links["tables"] + links["thunks"] + links["关键指令"]:
        raw = bytes.fromhex(entry["bytes"])
        assert read_va(int(entry["va"], 16), len(raw)) == raw, entry["va"]
        assert entry["matches_disk"]

    ledger = load(ROOT / "函数审阅清单.json")
    ranges = load(ROOT / "未声明范围审阅清单.json")
    assert {x["地址"] for x in ledger} == {x["va"] for x in meta["functions"]}
    assert {x["范围起点"] for x in ranges} == {x["va"] for x in meta["unrecognized_ranges"]}
    for entry in ledger + ranges:
        address = entry.get("地址", entry.get("范围起点"))
        assert entry["状态"] and entry["结论"] and entry["未知项"]
        for name in [entry["证据路径"]] + entry["交叉证据"]:
            records = load(TOPIC / name)
            source = next(x for x in records if x["va"] == address)
            assert source["end_va"] == entry["结束地址"] and source["assembly"]
            if "地址" in entry:
                assert source["pseudocode"]
            else:
                raw = bytes.fromhex(source["bytes"])
                assert read_va(int(address, 16), len(raw)) == raw
    for path in TOPIC.glob("*.txt"):
        in_block = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            value = line.strip()
            if not value:
                continue
            if value.startswith("/*"):
                in_block = True
            assert in_block or value.startswith("//"), (path.name, number)
            if "*/" in value:
                in_block = False
        assert not in_block, path.name
    print(f"PASS: {len(ledger)} 个函数区间、{len(ranges)} 个未声明范围、证据哈希、跳板/虚表及中文注释格式")
    print(json.dumps(dict(Counter(x["状态"] for x in ledger)), ensure_ascii=False))


if __name__ == "__main__":
    main()
