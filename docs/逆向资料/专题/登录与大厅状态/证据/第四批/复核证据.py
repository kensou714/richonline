"""只读核验第四批函数块、ABI证据和文档格式；不需要 IDA。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOPIC = ROOT.parent.parent


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    meta = load(ROOT / "版本核验.json")
    data = (TOPIC.parents[3] / "RnClient.exe").read_bytes()
    assert sha(data) == meta["disk_sha256"], "客户端版本已改变"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 52)[0]
    sections = [struct.unpack_from("<IIII", data, pe + 24 + opt_size + i * 40 + 8)
                for i in range(count)]

    def read(address, size):
        rva = int(address, 16) - base
        for _, start, raw_size, raw_offset in sections:
            if start <= rva and rva + size <= start + raw_size:
                offset = raw_offset + rva - start
                return data[offset:offset + size]
        raise AssertionError(f"区间不在原始 PE 节内：{address}")

    for item in meta["files"]:
        raw = (ROOT / item["path"]).read_bytes()
        assert sha(raw) == item["sha256"], item["path"]
        json.loads(raw.decode("utf-8"))
    for item in meta["functions"]:
        for block in [item] + item["chunks"]:
            raw = read(block["va"], block["byte_count"])
            assert sha(raw) == block["disk_sha256"] == block["idb_sha256"], block["va"]
            assert block["matches_disk"]
    links = load(ROOT / "links_abi_and_tables.json")
    for item in links["thunks"] + links["tables"] + links["instructions"]:
        raw = bytes.fromhex(item["bytes"])
        assert read(item["va"], len(raw)) == raw and item["matches_disk"], item["va"]
    ledger = load(ROOT / "函数审阅清单.json")
    assert len(ledger) == len({x["地址"] for x in ledger})
    assert {x["地址"] for x in ledger} == {x["va"] for x in meta["functions"]}
    for item in ledger:
        assert item["结论"] and item["未知项"]
        for name in [item["证据路径"]] + item["交叉证据"]:
            evidence = next(x for x in load(TOPIC / name) if x["va"] == item["地址"])
            assert evidence["end_va"] == item["结束地址"]
            assert evidence["assembly"] and evidence["pseudocode"]
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
    print(f"PASS: {len(ledger)} 个函数、{sum(len(x['chunks']) for x in meta['functions'])} 个函数块")
    print(json.dumps(dict(Counter(x["状态"] for x in ledger)), ensure_ascii=False))


if __name__ == "__main__":
    main()
