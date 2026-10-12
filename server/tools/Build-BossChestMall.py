"""生成 BOSS 宝箱物品的金豆商城资源；仅写入新的输出目录。

需要 Python 和 lzokay。原资源为 CP950，编辑以字节为单位保留其他字段。
价格政策：已有金豆价格优先；否则取原商城同子类商品，优先同名，
再按最接近的点券价选择。无有效点券价时取同类金豆价的中位商品。
新增金豆售价同时采用参照商品的金豆购买期限，避免将空期限误作永久。
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import re
import struct
import zipfile

import lzokay


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unpack(data: bytes) -> bytes:
    require(len(data) >= 9, "KPD header missing")
    payload = bytes((value - data[0]) % 256 for value in data[1:])
    size, compressed = struct.unpack_from("<II", payload)
    require(0 < size <= 4 * 1024 * 1024 and compressed == len(payload) - 8, "KPD size invalid")
    plain = lzokay.decompress(payload[8:], size)
    require(len(plain) == size, "KPD unpack size mismatch")
    return plain


def pack(plain: bytes, key: int) -> bytes:
    compressed = lzokay.compress(plain)
    payload = struct.pack("<II", len(plain), len(compressed)) + compressed
    result = bytes([key]) + bytes((value + key) % 256 for value in payload)
    require(unpack(result) == plain, "KPD roundtrip mismatch")
    return result


def sections(plain: bytes) -> list[tuple[str, dict[str, bytes], int, int]]:
    matches = list(re.finditer(rb"(?m)^\[([^\]\r\n]+)\][ \t]*\r?$", plain))
    result = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(plain)
        fields: dict[str, bytes] = {}
        for raw in plain[match.end():end].splitlines():
            line = raw.strip()
            if not line or line.startswith((b"//", b";", b"#")):
                continue
            require(b"=" in line, "Resource field invalid")
            key, value = line.split(b"=", 1)
            name = key.strip().decode("ascii")
            require(name not in fields, "Duplicate resource field")
            fields[name] = value.strip()
        result.append((match[1].decode("ascii"), fields, match.start(), end))
    require(bool(result), "Resource has no sections")
    return result


def amount(fields: dict[str, bytes], key: str) -> float:
    value = float(fields.get(key, b"0"))
    require(math.isfinite(value) and value >= 0, "Invalid resource price")
    return value


def group(fields: dict[str, bytes]) -> str:
    kind, subtype = fields["type"], fields["chType"].decode("ascii")
    if kind == b"AVATAR" and subtype in {"AVATAR_BS", "AVATAR_BJ", "AVATAR_TX", "AVATAR_FS", "AVATAR_QC", "AVATAR_CW", "AVATAR_ZJ"}:
        return "A_" + subtype[7:] + "_R"
    if kind == b"CARD" and subtype in {"CARD_GL", "CARD_CQ"}:
        return "C_" + subtype[5:] + "_R"
    if kind == b"FUNC":
        return "F_R"
    raise ValueError("Unsupported mall category")


def build(client: Path, output: Path) -> dict:
    require(not output.exists(), "Output already exists; choose a new directory")
    names = ("Prop.kpd", "SellProp.kpd", "BossWar.kpd", "BossWar_v.kpd")
    packed = {name: (client / "Data" / name).read_bytes() for name in names}
    plain = {name: unpack(data) for name, data in packed.items()}
    prop_sections = sections(plain["Prop.kpd"])
    products = {int(f["indx"]): f for kind, f, _, _ in prop_sections if kind == "PROP"}
    require(len(products) == len(prop_sections), "Prop IDs or sections invalid")
    sale_sections = sections(plain["SellProp.kpd"])
    offers = {(g, int(f["prop"])) for g, f, _, _ in sale_sections}
    sources: dict[int, set[str]] = {}
    skills = set()
    for name in names[2:]:
        for _, fields, _, _ in sections(plain[name]):
            drops = [(key, value) for key, value in fields.items() if re.fullmatch(r"dropBox\d+", key)]
            require(len(drops) == int(fields.get("dropBoxNum", b"0")), "Boss drop count mismatch")
            for key, value in drops:
                kind, item, weight = value.decode("ascii").split(",")
                require(int(weight) > 0, "Nonpositive boss drop weight")
                if kind in ("Active", "NotAct"):
                    require(int(item) in products, "Boss item missing from Prop")
                    sources.setdefault(int(item), set()).add(name + ":" + fields["mapName"].decode("ascii") + ":" + key)
                else:
                    require(kind in {"Yan", "Pao", "Chang", "Zhong", "Kong", "Mi", "Ba", "Shan", "Zhao", "Shou"}, "Unknown boss drop kind")
                    skills.add((kind, int(item)))
    require(bool(sources), "No boss item drops")
    changes: dict[int, dict[str, bytes]] = {}
    rows = []
    additions = []
    for item in sorted(sources):
        fields = products[item]
        require(fields.get("enable", b"false").split(b",")[0] == b"true", "Disabled reward item needs explicit policy")
        category = group(fields)
        original_price = amount(fields, "priceLR")
        donor_id = item
        updates = {"saleLR": b"true"}
        if original_price == 0:
            candidates = [(i, f) for i, f in products.items() if
                          f["type"] == fields["type"] and f["chType"] == fields["chType"] and
                          f.get("enable", b"false").split(b",")[0] == b"true" and
                          f.get("saleLR") == b"true" and amount(f, "priceLR") > 0 and (category, i) in offers]
            require(bool(candidates), "No listed gold peer for item " + str(item))
            point_price = amount(fields, "priceLJ")
            same_name = [(i, f) for i, f in candidates if f["name"] == fields["name"]]
            if same_name:
                candidates = same_name
            if 0 < point_price < 9999:
                donor_id, donor = min(candidates, key=lambda pair: (abs(amount(pair[1], "priceLJ") - point_price), pair[0]))
            else:
                candidates.sort(key=lambda pair: (amount(pair[1], "priceLR"), pair[0]))
                donor_id, donor = candidates[(len(candidates) - 1) // 2]
            updates.update({"priceLR": donor["priceLR"], **{key: donor.get(key, b"0") for key in ("yearR", "monthR", "dayR")}})
        updates = {key: value for key, value in updates.items() if fields.get(key) != value}
        changes[item] = updates
        final = {**fields, **updates}
        if (category, item) not in offers:
            additions.append(f"[{category}]\r\nprop = {item}\r\n".encode("ascii"))
        rows.append({"id": item, "name": fields["name"].decode("cp950"), "group": category,
                     "price": amount(final, "priceLR"), "term": {key: int(final.get(key, b"0")) for key in ("yearR", "monthR", "dayR")},
                     "pricing": "original_gold" if original_price > 0 else "listed_peer", "peer": donor_id,
                     "changed_fields": sorted(updates), "added_offer": (category, item) not in offers,
                     "sources": sorted(sources[item])})
    edited = plain["Prop.kpd"]
    for _, fields, start, end in reversed(prop_sections):
        updates = changes.get(int(fields["indx"]), {})
        block = edited[start:end]
        for key, value in updates.items():
            pattern = rb"(?m)^([ \t]*" + key.encode("ascii") + rb"[ \t]*=[ \t]*)[^\r\n]*"
            if key in fields:
                block, count = re.subn(pattern, lambda m: m[1] + value, block)
                require(count == 1, "Field replacement count mismatch")
            else:
                block = block.rstrip(b"\r\n") + b"\r\n" + key.encode("ascii") + b" = " + value + b"\r\n\r\n"
        edited = edited[:start] + block + edited[end:]
    new_sale = plain["SellProp.kpd"] + b"\r\n" + b"\r\n".join(additions)
    check_props = {int(f["indx"]): f for _, f, _, _ in sections(edited)}
    require(check_props == {i: {**f, **changes.get(i, {})} for i, f in products.items()}, "Unexpected Prop edit")
    check_sale = sections(new_sale)
    require([(g, f) for g, f, _, _ in check_sale[:len(sale_sections)]] == [(g, f) for g, f, _, _ in sale_sections], "Existing offers changed")
    for row in rows:
        require(sum(g == row["group"] and int(f["prop"]) == row["id"] for g, f, _, _ in check_sale) == 1, "Missing or duplicate gold offer")
        require(check_props[row["id"]]["saleLR"] == b"true" and row["price"] > 0, "Unpurchasable reward")
    resources = {"Prop.kpd": pack(edited, packed["Prop.kpd"][0]),
                 "SellProp.kpd": pack(new_sale, packed["SellProp.kpd"][0])}
    report = {"source_sha256": {name: digest(data) for name, data in packed.items()},
              "output_sha256": {name: digest(data) for name, data in resources.items()},
              "items": len(rows), "added_offers": len(additions), "skill_reward_levels_not_items": len(skills), "products": rows}
    (output / "Data").mkdir(parents=True)
    for name, data in resources.items():
        (output / "Data" / name).write_bytes(data)
    purpose = {"Prop.kpd": "宝箱物品的金豆售卖开关、价格和购买期限", "SellProp.kpd": f"新增{len(additions)}种宝箱物品的金豆商城分类引用"}
    changed = [{"path": "Data/" + name, "purpose": purpose[name],
                "before_sha256": digest(packed[name]), "after_sha256": digest(data),
                "before_bytes": len(packed[name]), "after_bytes": len(data)} for name, data in resources.items()]
    (output / "changed-files.json").write_text(json.dumps(changed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    listing = "客户端修改文件清单（路径相对于客户端根目录）\n\n"
    for entry in changed:
        listing += (f"{entry['path']}：{entry['purpose']}\n"
                    f"原版 SHA256：{entry['before_sha256']}（{entry['before_bytes']}字节）\n"
                    f"新版 SHA256：{entry['after_sha256']}（{entry['after_bytes']}字节）\n\n")
    (output / "changed-files.txt").write_text(listing, encoding="utf-8-sig")
    (output / "catalog.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    table = io.StringIO(newline="")
    writer = csv.writer(table)
    writer.writerow(["道具编号", "名称", "商城分类", "金豆价格", "年", "月", "天", "参照商品编号", "定价依据"])
    for row in rows:
        writer.writerow([row["id"], row["name"], row["group"], row["price"], *row["term"].values(), row["peer"], row["pricing"]])
    (output / "catalog.csv").write_text(table.getvalue(), encoding="utf-8-sig")
    note = "BOSS宝箱金豆商城补丁\n退出客户端，备份原Data/Prop.kpd和Data/SellProp.kpd，将本包Data目录覆盖到客户端根目录，然后重新启动。\n服务端必须使用同一套商城资源。未修改EXE、装备属性或BOSS奖池。\n新增售价及期限见catalog.csv；神迹技能等级奖励不是商城道具，不转换为其他物品。\n"
    (output / "README.txt").write_text(note, encoding="utf-8-sig")
    with zipfile.ZipFile(output / "BossChest-Mall-Client.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(output.rglob("*")):
            if path.is_file() and path.suffix != ".zip":
                archive.write(path, path.relative_to(output).as_posix())
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "client-patches" /
                        (datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-boss-mall"))
    args = parser.parse_args()
    result = build(args.client_root.resolve(), args.output.resolve())
    print(json.dumps({key: value for key, value in result.items() if key != "products"}, ensure_ascii=True))
