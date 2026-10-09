"""只读提取 4090 系列使用的文本、新闻与界面配置，保留原始行及来源指纹。"""

import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SELECTED_TEXT = {22, 24, 28, 71, 154, 245, 264, 293, 295, 296, 297, 319, 320, 359}


def sections(text):
    result = []
    current = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = {"section": stripped[1:-1], "line": number, "raw_lines": [line], "fields": {}}
            result.append(current)
        elif current is not None:
            current["raw_lines"].append(line)
            if "=" in line and not stripped.startswith("//"):
                key, value = line.split("=", 1)
                current["fields"][key.strip()] = value.strip()
    return result


def main():
    records = []
    for relative in ["Data/RichStr.kpd", "Data/BwNews.kpd", "Data/KoNews.kpd", "Interface/Intf.kpd"]:
        raw = (ROOT / relative).read_bytes()
        key = raw[0]
        expanded, packed = struct.unpack("<II", bytes((byte - key) & 255 for byte in raw[1:9]))
        assert 0 < expanded <= 64 * 1024 * 1024
        assert packed == len(raw) - 9
        plain = lzokay.decompress(bytes((byte - key) & 255 for byte in raw[9:]), expanded)
        assert len(plain) == expanded
        codec = "cp936" if relative.startswith("Interface/") else "cp950"
        decoded = plain.decode(codec, errors="strict")
        assert decoded.encode(codec) == plain
        parsed = sections(decoded)
        if relative.endswith("RichStr.kpd"):
            selected = [row for row in parsed if row["fields"].get("indx", "").isdigit()
                        and int(row["fields"]["indx"]) in SELECTED_TEXT]
        elif relative.endswith("Intf.kpd"):
            selected = [row for row in parsed if row["fields"].get("indx") in {"0", "4", "9", "12", "30", "32", "35"}]
        else:
            selected = []
            for number, line in enumerate(decoded.splitlines(), 1):
                if not line.strip():
                    continue
                columns = line.split("\t")
                assert len(columns) == 10
                selected.append({"line": number, "raw_line": line, "columns": columns,
                                 "map_name": columns[0], "type": int(columns[1]),
                                 "animation_name": columns[8], "text_template": columns[9]})
        output = Path(relative).stem + ".decoded.bin"
        (HERE / output).write_bytes(plain)
        records.append({"source": relative, "source_sha256": hashlib.sha256(raw).hexdigest(),
                        "source_bytes": len(raw), "key": key, "expanded_bytes": expanded,
                        "packed_bytes": packed, "decoded_sha256": hashlib.sha256(plain).hexdigest(),
                        "decoded_file": output, "codec": codec, "strict_roundtrip": True,
                        "sections": selected})
    (HERE / "resource_samples.json").write_text(json.dumps({
        "scope": "当前 Richonline 资源只读解包，未执行客户端；原始繁体文本不改写。",
        "records": records,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({row["source"]: len(row["sections"]) for row in records}, ensure_ascii=False))


if __name__ == "__main__":
    main()
