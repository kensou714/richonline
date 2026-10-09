"""Collect NEW possession lifecycle and combat instruction evidence."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import capstone
import pefile

BASELINE_SHA256 = "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77"
WINDOWS = {
    "strength_setter": (0x7FAE80, 0x180),
    "strength_positive": (0x7016B0, 0x30),
    "multiplier_read": (0x7016E0, 0x30),
    "strength_clear": (0x7FDBA0, 0x30),
    "detach": (0x7F7D50, 0x60),
    "attach": (0x7F7DB0, 0x80),
    "detach_positive_thunk": (0x61283A, 5),
    "detach_clear_thunk": (0x6048B6, 5),
    "attach_helper_thunk": (0x6037AE, 5),
    "attach_helper": (0x63E210, 0x30),
    "damage": (0x7CE420, 0x600),
    "attack_display": (0x6F4E70, 0x1E0),
    "defense_display": (0x6F5050, 0x1E0),
}


def collect(root):
    original = root / "RnClient.before-graphics-threading.exe"
    current = root / "RnClient.exe"
    original_bytes = original.read_bytes()
    current_bytes = current.read_bytes()
    baseline_hash = hashlib.sha256(original_bytes).hexdigest()
    if baseline_hash != BASELINE_SHA256:
        raise ValueError("NEW baseline hash mismatch")
    baseline_pe = pefile.PE(data=original_bytes, fast_load=True)
    current_pe = pefile.PE(data=current_bytes, fast_load=True)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    windows = {}
    for name, (address, size) in WINDOWS.items():
        before = baseline_pe.get_data(address - baseline_pe.OPTIONAL_HEADER.ImageBase, size)
        after = current_pe.get_data(address - current_pe.OPTIONAL_HEADER.ImageBase, size)
        windows[name] = {
            "address": hex(address), "size": size,
            "sha256": hashlib.sha256(before).hexdigest(),
            "current_identical": before == after,
            "instructions": [f"{i.address:08x} {i.mnemonic} {i.op_str}" for i in decoder.disasm(before, address)],
        }
    constants = {}
    for address in (0xA2A2B0, 0xA23394, 0xA23388):
        constants[hex(address)] = struct.unpack("<f", baseline_pe.get_data(
            address - baseline_pe.OPTIONAL_HEADER.ImageBase, 4))[0]
    return {
        "baseline": str(original), "baseline_sha256": baseline_hash,
        "current_sha256": hashlib.sha256(current_bytes).hexdigest(),
        "note": "Fixed instruction windows; some include adjacent functions. Addresses refer to NEW baseline.",
        "float_constants": constants, "windows": windows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    evidence = collect(args.root)
    args.output.write_text(json.dumps(evidence, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"baseline_sha256": evidence["baseline_sha256"],
                      "windows": len(evidence["windows"]), "output": str(args.output)}))
