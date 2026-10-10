"""Independent local-byte audit of the lobby region parser evidence."""

import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
raw = json.loads((HERE / "lobby_regions_ida_raw.json").read_text(encoding="utf-8"))
image = (ROOT / "RnClient.exe").read_bytes()


def require(condition, label):
    if not condition:
        raise AssertionError(label)


require(raw["schema"] == 1, "evidence schema")
disk_hash = hashlib.sha256(image).hexdigest()
require(disk_hash == raw["disk_sha256"], "disk SHA-256")
require(disk_hash != raw["idb_input_sha256"], "IDB input must be treated as a different file")
pe = struct.unpack_from("<I", image, 0x3C)[0]
require(image[:2] == b"MZ" and image[pe:pe + 4] == b"PE\0\0", "PE header")
require(struct.unpack_from("<H", image, pe + 24)[0] == 0x10B, "PE32 optional header")
base = struct.unpack_from("<I", image, pe + 52)[0]
require(base == int(raw["image_base"], 16) == 0x400000, "image base")
section_table = pe + 24 + struct.unpack_from("<H", image, pe + 20)[0]
sections = [struct.unpack_from("<4I", image, section_table + i * 40 + 8)
            for i in range(struct.unpack_from("<H", image, pe + 6)[0])]


def disk_bytes(va, size):
    matches = [(rva, offset, raw_size) for _, rva, raw_size, offset in sections
               if base + rva <= va and va + size <= base + rva + raw_size]
    require(len(matches) == 1, f"unique raw section for {va:#x}")
    rva, offset, _ = matches[0]
    start = offset + va - base - rva
    result = image[start:start + size]
    require(len(result) == size, f"complete disk read at {va:#x}")
    return result


def check_block(block):
    start, end = int(block["va"], 16), int(block["end_va"], 16)
    require(end - start == block["size"], f"block range {start:#x}")
    data = disk_bytes(start, block["size"])
    require(data.hex() == block["disk_hex"] == block["idb_hex"],
            f"IDB/disk bytes at {start:#x}")
    digest = hashlib.sha256(data).hexdigest()
    require(digest == block["disk_sha256"] == block["idb_sha256"],
            f"block SHA-256 at {start:#x}")
    return start, end


expected = [(0x69EEE0, 0x60ABDA), (0x69F750, 0x5FFE60),
            (0x6A0130, 0x60617F)]
require(len(raw["functions"]) == len(raw["windows"]) == len(expected),
        "target and window count")
instruction_count = 0
chunk_count = 0
for function, window, (target, site) in zip(raw["functions"], raw["windows"], expected):
    require(int(function["va"], 16) == target, f"target order {target:#x}")
    require(function["pseudocode_error"] is None, f"pseudocode error {target:#x}")
    chunks = sorted(check_block(block) for block in function["chunks"])
    chunk_count += len(chunks)
    require(chunks[0] == (target, int(function["end_va"], 16)),
            f"main function range {target:#x}")
    rows = sorted(function["instructions"], key=lambda row: int(row["va"], 16))
    previous_count = instruction_count
    for start, end in chunks:
        cursor = start
        for row in rows:
            ea = int(row["va"], 16)
            if not start <= ea < end:
                continue
            require(ea == cursor and row["size"] > 0,
                    f"instruction gap/overlap at {cursor:#x}")
            require(disk_bytes(ea, row["size"]).hex() == row["hex"],
                    f"instruction bytes at {ea:#x}")
            cursor += row["size"]
            instruction_count += 1
        require(cursor == end, f"uncovered function bytes at {cursor:#x}")
    require(instruction_count - previous_count == len(rows),
            f"unexpected instruction outside chunks at {target:#x}")
    require(int(window["site"], 16) == site, f"jump site {site:#x}")
    require(window["owner"] == window["site"], f"jump owner {site:#x}")
    require(check_block(window["block"]) == (site, site + 5),
            f"jump window range {site:#x}")
    encoded = disk_bytes(site, 5)
    require(encoded[0] == 0xE9, f"E9 opcode at {site:#x}")
    destination = site + 5 + struct.unpack_from("<i", encoded, 1)[0]
    require(destination == target, f"E9 target at {site:#x}")
    require(len(window["instructions"]) == 1 and
            window["instructions"][0]["hex"] == encoded.hex() and
            window["instructions"][0]["code_refs"] == [hex(target)],
            f"jump instruction at {site:#x}")
    require(function["incoming"] == [dict(site=hex(site), owner=hex(site),
                                          iscode=True, type=19)],
            f"IDA direct incoming list at {target:#x}")

result = {
    "status": "PASS",
    "disk_sha256": disk_hash,
    "idb_input_sha256": raw["idb_input_sha256"],
    "same_complete_file": False,
    "functions": len(expected),
    "function_chunks": chunk_count,
    "covered_instructions": instruction_count,
    "e9_targets": [f"{target:#x}" for target, _ in expected],
    "scope": "Disk/IDB local bytes, complete exported instruction ranges, and E9 targets; no helper or runtime semantics",
}
print(json.dumps(result, ensure_ascii=False, indent=2))
