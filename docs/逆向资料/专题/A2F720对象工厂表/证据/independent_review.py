"""Independently compare the A2F720 evidence with the current PE image."""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
image = (ROOT / "RnClient.exe").read_bytes()
raw = json.loads((HERE / "a2f720_raw.json").read_text(encoding="utf-8"))
chain = json.loads((HERE / "constructor_chain.json").read_text(encoding="utf-8"))
prior = json.loads((ROOT / "docs/逆向资料/专题/82BBE0高频数据入口/证据/table_provenance.json").read_text(encoding="utf-8"))
sha = hashlib.sha256(image).hexdigest()
assert sha == raw["disk_sha256"] == chain["disk_sha256"] == prior["disk_sha256"]
pe = struct.unpack_from("<I", image, 0x3C)[0]
assert image[:2] == b"MZ" and image[pe:pe + 4] == b"PE\x00\x00"
assert struct.unpack_from("<H", image, pe + 24)[0] == 0x10B
base = struct.unpack_from("<I", image, pe + 52)[0]
section_start = pe + 24 + struct.unpack_from("<H", image, pe + 20)[0]
sections = [struct.unpack_from("<4I", image, section_start + i * 40 + 8)
            for i in range(struct.unpack_from("<H", image, pe + 6)[0])]


def disk(va, size):
    matches = [(rva, offset) for _, rva, raw_size, offset in sections
               if base + rva <= va and va + size <= base + rva + raw_size]
    assert len(matches) == 1, hex(va)
    rva, offset = matches[0]
    start = offset + va - base - rva
    return image[start:start + size]


def check_block(block):
    va, size = int(block["va"], 16), block["size"]
    assert int(block["end_va"], 16) == va + size
    assert disk(va, size).hex() == block["ida_hex"] == block["disk_hex"]
    return {"va": block["va"], "size": size}


blocks = []
functions = []
for function in (raw["function"], raw["adjacent_function"], chain["function"]):
    for block in function["chunks"]:
        blocks.append(check_block(block))
    instructions = sorted(function["instructions"], key=lambda row: int(row["va"], 16))
    for block in function["chunks"]:
        contained = [row for row in instructions
                     if int(block["va"], 16) <= int(row["va"], 16) < int(block["end_va"], 16)]
        cursor = int(block["va"], 16)
        for row in contained:
            assert int(row["va"], 16) == cursor
            assert disk(cursor, row["size"]).hex() == row["hex"]
            cursor += row["size"]
        assert cursor == int(block["end_va"], 16)
    functions.append({"va": function["va"], "instruction_count": len(instructions)})

blocks.extend(check_block(block) for block in
              (raw["table"]["block"], raw["alias"]["block"],
               raw["factory_alias"]["block"], chain["alias"]["block"]))
slots = [struct.unpack("<I", disk(0xA2F720 + 4 * i, 4))[0] for i in range(32)]
assert slots == [int(row["target"], 16) for row in raw["table"]["slots"]]


def rel32_target(va, opcode):
    instruction = disk(va, 5)
    assert instruction[0] == opcode
    return va + 5 + struct.unpack_from("<i", instruction, 1)[0]


assert rel32_target(0x8561A6, 0xE8) == 0x60810F
assert rel32_target(0x60810F, 0xE9) == 0x8563C0
assert disk(0x8563E6, 6) == bytes.fromhex("c70038f7a200")
assert disk(0x8561AE, 6) == bytes.fromhex("c7002cf7a200")
assert disk(0x8560BE, 6) == bytes.fromhex("c70020f7a200")
assert rel32_target(0x60ECC6, 0xE9) == 0x8553F0
assert rel32_target(0x60EFB4, 0xE9) == 0x856090
assert disk(0x855428, 5) == bytes.fromhex("68d0000000")
assert disk(0x82CB20, 6) == bytes.fromhex("c70050f0a200")
assert all(check_block(block) for function in prior["functions"]
           for block in function["chunks"])

result = {
    "status": "PASS",
    "disk_sha256": sha,
    "functions": functions,
    "checked_local_blocks": blocks,
    "window_dwords": 32,
    "head_six_dwords": [hex(value) for value in slots[:6]],
    "call_8561a6": "0x60810f",
    "jump_60810f": "0x8563c0",
    "first_write_8563e6": "[this+0] = 0xa2f738",
    "later_write_8561ae": "[this+0] = 0xa2f72c",
    "jump_60ecc6": "0x8553f0",
    "jump_60efb4": "0x856090",
    "prior_function_blocks_checked": sum(len(f["chunks"]) for f in prior["functions"]),
    "boundary": "Disk bytes establish static call/write order, not runtime dispatch or class inheritance."
}
(HERE / "independent_validation.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, ensure_ascii=False))
