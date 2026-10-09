"""只读解包本专题资源；保存原始字节、严格编码往返与记录行号。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SELECTED = {
    "Data/Prop.kpd": {506, 1071},
    "Data/RichStr.kpd": {131, 264, 359},
    "Data/GValue.kpd": {30},
    "Interface/Intf.kpd": {4, 9, 45},
}


def sections(text):
    rows, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("[") and line.strip().endswith("]"):
            current = {"section": line.strip()[1:-1], "line": number,
                       "raw_lines": [line], "fields": {}}
            rows.append(current)
        elif current is not None:
            current["raw_lines"].append(line)
            if "=" in line and not line.strip().startswith("//"):
                key, value = line.split("=", 1)
                current["fields"][key.strip()] = value.strip()
    return rows


def main():
    records = []
    for relative, indices in SELECTED.items():
        raw = (ROOT / relative).read_bytes()
        key = raw[0]
        unpacked, packed = struct.unpack("<II", bytes((b-key) & 255 for b in raw[1:9]))
        assert 0 < unpacked <= 64*1024*1024 and packed == len(raw)-9
        plain = lzokay.decompress(bytes((b-key) & 255 for b in raw[9:]), unpacked)
        codec = "cp936" if relative.startswith("Interface/") or relative.endswith(("Anim.kpd", "GValue.kpd")) else "cp950"
        decoded = plain.decode(codec, errors="strict")
        assert decoded.encode(codec) == plain and len(plain) == unpacked
        selected = [row for row in sections(decoded)
                    if row["fields"].get("indx", "").isdigit()
                    and int(row["fields"]["indx"]) in indices]
        output = Path(relative).stem + ".decoded.bin"
        (HERE / output).write_bytes(plain)
        records.append({"source": relative, "source_sha256": hashlib.sha256(raw).hexdigest(),
                        "source_bytes": len(raw), "key": key, "expanded_bytes": unpacked,
                        "packed_bytes": packed, "codec": codec, "strict_roundtrip": True,
                        "decoded_sha256": hashlib.sha256(plain).hexdigest(),
                        "decoded_file": output, "sections": selected})
    (HERE / "resource_samples.json").write_text(json.dumps({"records": records},
        ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({r["source"]: len(r["sections"]) for r in records}, ensure_ascii=False))


if __name__ == "__main__":
    main()
