"""离线核验第二批证据、文档和当前PE字节；不修改二进制或已有证据。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOPIC = ROOT.parent.parent
CLIENT = TOPIC.parents[3] / "RnClient.exe"
data = CLIENT.read_bytes()
meta = json.loads((ROOT / "版本与逐函数核验.json").read_text(encoding="utf-8"))
assert hashlib.sha256(data).hexdigest() == meta["disk_sha256"]
pe = struct.unpack_from("<I", data, 0x3C)[0]
count = struct.unpack_from("<H", data, pe + 6)[0]
optional_size = struct.unpack_from("<H", data, pe + 20)[0]
base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
sections = []
for i in range(count):
    offset = pe + 24 + optional_size + i * 40
    virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
    sections.append((rva, raw_size, raw_offset))

def read_va(address, length):
    rva = address - base
    for start, raw_size, raw_offset in sections:
        if start <= rva and rva + length <= start + raw_size:
            start_offset = raw_offset + rva - start
            return data[start_offset:start_offset + length]
    raise AssertionError(f"范围不在单个PE原始节内: {address:#x}")

for evidence in meta["files"]:
    content = (ROOT / evidence["path"]).read_bytes()
    assert hashlib.sha256(content).hexdigest() == evidence["sha256"]
    json.loads(content.decode("utf-8"))
for entry in meta["functions"]:
    address = int(entry["va"], 16)
    raw = read_va(address, entry["byte_count"])
    assert hashlib.sha256(raw).hexdigest() == entry["disk_sha256"] == entry["idb_sha256"]
    assert entry["matches_disk"]
links = json.loads((ROOT / "links_and_tables.json").read_text(encoding="utf-8"))
for row in links["tables"] + links["thunks"]:
    expected = bytes.fromhex(row["bytes"])
    assert read_va(int(row["va"], 16), len(expected)) == expected
    assert row["matches_disk"]
ledger = json.loads((ROOT / "函数审阅清单.json").read_text(encoding="utf-8"))
assert {entry["va"] for entry in meta["functions"]} == {entry["地址"] for entry in ledger}
for entry in ledger:
    assert entry["结论"] and entry["未知项"]
    path = TOPIC / entry["证据路径"]
    entries = json.loads(path.read_text(encoding="utf-8"))
    function = next(row for row in entries if row["va"] == entry["地址"])
    assert function["pseudocode"] and function["assembly"]
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
    assert not in_block
print("PASS: 105 function ranges, tables/thunks, evidence hashes, UTF-8/comment format")
print(json.dumps(dict(Counter(row["状态"] for row in ledger)), ensure_ascii=True))
