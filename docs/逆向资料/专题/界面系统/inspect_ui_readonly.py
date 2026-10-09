"""按 IDA 0x9105D0 的字节变换只读核对当前 .ui 样本，不写回资源。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def inspect(source: Path) -> dict:
    raw = source.read_bytes()
    key = b"RichNet"
    plain = bytes((value - key[index % len(key)]) & 0xFF
                  for index, value in enumerate(raw))
    # 这里只读取结构所需的 ASCII 字段；非 ASCII 字节以十六进制显示，避免猜编码。
    def show(value: bytes) -> str:
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            return "hex:" + value.hex()

    sections: list[dict] = []
    current: dict | None = None
    for line_number, raw_line in enumerate(plain.split(b"\n"), 1):
        line = raw_line.replace(b"\t", b"")
        if not line or line.startswith(b";"):
            continue
        if line.startswith(b"[") and line.endswith(b"]"):
            current = {"name": show(line[1:-1]), "line": line_number,
                       "fields": {}, "duplicate_keys": []}
            sections.append(current)
        elif b"=" in line and current is not None:
            key_bytes, value = line.split(b"=", 1)
            field = show(key_bytes)
            if field in current["fields"]:
                current["duplicate_keys"].append(field)
            current["fields"][field] = show(value)

    names = [section["name"] for section in sections]
    controls = []
    missing_parents = []
    for section in sections:
        if section["name"].lower() == "head":
            continue
        fields = section["fields"]
        record = {"section": section["name"], "line": section["line"],
                  **{field: fields[field] for field in
                     ("Type", "ID", "Left", "Top", "Width", "Height", "Parent")
                     if field in fields}}
        controls.append(record)
        parent = fields.get("Parent")
        if parent is not None and parent.lower() != "null" and parent not in names:
            missing_parents.append({"section": section["name"], "parent": parent})
    head = next((section["fields"].get("head") for section in sections
                 if section["name"].lower() == "head"), None)
    return {"file": source.name, "size": len(raw), "source_sha256": sha256(raw),
            "decoded_sha256": sha256(plain), "trailing_lf": plain.endswith(b"\n"),
            "contains_cr": b"\r" in plain, "head": head,
            "head_target_exists": head in names, "section_count": len(sections),
            "control_count": len(controls), "missing_parents": missing_parents,
            "duplicate_sections": sorted({name for name in names if names.count(name) > 1}),
            "duplicate_keys": [{"section": section["name"], "keys": section["duplicate_keys"]}
                               for section in sections if section["duplicate_keys"]],
            "controls": controls}


def main() -> None:
    destination = Path(__file__).resolve().parent
    client_root = destination.parents[3]
    samples = [inspect(path) for path in sorted((client_root / "Interface").glob("*.ui"))]
    payload = {"scope": "当前客户端 Interface/*.ui；结构观察不是完整客户端解析器模拟",
               "binary_sha256": sha256((client_root / "RnClient.exe").read_bytes()),
               "key_ascii": "RichNet", "transform": "(cipher[i] - key[i % 7]) & 255",
               "sample_count": len(samples), "files": samples}
    target = destination / "ui_resource_inventory.json"
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(target), "sample_count": len(samples),
                      "head_failures": [s["file"] for s in samples if not s["head_target_exists"]],
                      "parent_failures": [s["file"] for s in samples if s["missing_parents"]],
                      "duplicates": [s["file"] for s in samples if s["duplicate_sections"] or s["duplicate_keys"]]},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
