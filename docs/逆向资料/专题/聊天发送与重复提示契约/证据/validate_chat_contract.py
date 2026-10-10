# -*- coding: utf-8 -*-
"""只读 PE 回证；有限模型为文档例子的算术核验，不等同实机验证。"""
import collections
import hashlib
import itertools
import json
import pathlib
import struct
import sys

DIRECTORY = pathlib.Path(__file__).resolve().parent
EXPECTED_SHA256 = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"


def validate():
    evidence = json.loads((DIRECTORY / "chat_contract_discovery.json").read_text(encoding="utf-8"))
    review = json.loads((DIRECTORY.parent / "函数审阅清单.json").read_text(encoding="utf-8"))
    image = pathlib.Path(evidence["input"]).read_bytes()
    errors, checks = [], collections.Counter()

    def require(condition, label):
        checks["assertions"] += 1
        if not condition:
            errors.append(label)

    require(image[:2] == b"MZ", "MZ")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    require(image[pe:pe + 4] == b"PE\0\0", "PE")
    optional = pe + 24
    require(struct.unpack_from("<H", image, optional)[0] == 0x10B, "PE32")
    base = struct.unpack_from("<I", image, optional + 28)[0]
    table = optional + struct.unpack_from("<H", image, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from("<H", image, pe + 6)[0]):
        _, rva, size, raw = struct.unpack_from("<IIII", image, table + 40 * index + 8)
        require(raw + size <= len(image), "节raw越界")
        sections.append((rva, size, raw))

    def disk(address, size):
        for rva, raw_size, raw in sections:
            offset = address - base - rva
            if 0 <= offset and offset + size <= raw_size:
                return image[raw + offset:raw + offset + size]
        return None

    require(hashlib.sha256(image).hexdigest() == evidence["disk_sha256"] == EXPECTED_SHA256, "当前EXE指纹")
    require(evidence["idb_input_sha256"] != EXPECTED_SHA256, "不得忽略IDB输入指纹不同")

    def identity(record, kind, allow_unmapped=False):
        address, size = int(record["va"], 16), record["size"]
        content = bytes.fromhex(record["ida_hex"])
        require(len(content) == size, kind + "记录长度")
        require(hashlib.sha256(content).hexdigest() == record["sha256"], kind + "摘要")
        current = disk(address, size)
        if current is None:
            require(allow_unmapped, kind + "未映射代码")
            require(record["disk_hex"] is None and record["equal"] is None and record["disk_mapped"] is False, kind + "未映射标志")
            checks["unmapped_data_records"] += 1
        else:
            require(content == current == bytes.fromhex(record["disk_hex"]), kind + "当前字节不同")
            require(record["equal"] is True and record["disk_mapped"] is True, kind + "映射标志")
        checks[kind + "_records"] += 1
        checks[kind + "_bytes"] += size
        return address, content

    functions = {int(row["va"], 16): row for row in evidence["functions"]}
    require(len(functions) == len(evidence["functions"]) == 36, "函数数量/去重")
    instructions = {}
    for address, function in functions.items():
        chunks = [identity(row, "chunk") for row in function["chunks"]]
        require(any(start == address for start, _ in chunks), "入口chunk")
        for row in function["chunks"]:
            require(int(row["end"], 16) == int(row["va"], 16) + row["size"], "chunk结束")
        heads = set()
        for row in function["instructions"]:
            site, content = int(row["va"], 16), bytes.fromhex(row["hex"])
            require(site not in heads and len(content) == row["size"] > 0, "重复/长度指令")
            heads.add(site)
            owner = [(start, data) for start, data in chunks if start <= site and site + len(content) <= start + len(data)]
            require(len(owner) == 1, "指令chunk归属")
            if owner:
                start, data = owner[0]
                require(data[site - start:site - start + len(content)] == content, "指令与块一致")
            require(disk(site, len(content)) == content, "指令与EXE一致")
            require(site not in instructions, "跨函数重复指令")
            instructions[site] = row
            checks["instructions"] += 1
        for call in function["calls"]:
            site, target = int(call["site"], 16), int(call["target"], 16)
            require(site in heads, "直接转移无指令")
            content = bytes.fromhex(instructions[site]["hex"])
            if len(content) == 5 and content[0] in (0xE8, 0xE9):
                require(site + 5 + struct.unpack("<i", content[1:])[0] == target, "rel32目标")
            elif len(content) == 2 and content[0] == 0xEB:
                require(site + 2 + struct.unpack("<b", content[1:])[0] == target, "rel8目标")
            else:
                require(False, "未知直接call/jmp编码")

    thunks = {}
    for row in evidence["thunks"]:
        address, content = identity(row, "e9")
        require(address not in thunks and len(content) == 5 and content[0] == 0xE9, "E9格式")
        require(address + 5 + struct.unpack("<i", content[1:])[0] == int(row["target"], 16), "E9目标")
        thunks[address] = int(row["target"], 16)
    for function in functions.values():
        for call in function["calls"]:
            target, seen = int(call["target"], 16), set()
            while target in thunks:
                require(target not in seen, "E9循环")
                if target in seen:
                    break
                seen.add(target)
                target = thunks[target]
            require(target == int(call["resolved"], 16), "E9解析闭合")

    def navigation(window):
        for row in window["instructions"]:
            content = bytes.fromhex(row["hex"])
            require(len(content) == row["size"] and disk(int(row["va"], 16), len(content)) == content, "导航窗口字节")
            checks["navigation_instructions"] += 1
        require(not window["instructions"] or any(row["va"] == window["site"] for row in window["instructions"]), "窗口含引用点")

    for window in evidence["incoming"]:
        navigation(window)
    require(len(evidence["incoming"]) == 8, "incoming含别名8")
    require(sum(window["caller"] != "0x6042ee" for window in evidence["incoming"]) == 7, "业务call为7")
    for row in evidence["globals"]:
        identity(row["snapshot"], "global", True)
        for window in row["xrefs"]:
            navigation(window)
    require({row["va"] for row in evidence["globals"]} == {"0xa76e68", "0xa76e6c", "0xa76e70", "0xa76f80", "0xa77090", "0xa772a0", "0xa772a8"}, "全局集合")
    static = evidence.get("static_data", [])
    require(len(static) == 6, "固定数据证据缺失")
    static_map = {int(row["va"], 16): identity(row, "static", True)[1] for row in static}
    require(static_map.get(0xA229B0) == static_map.get(0xA229B4) == b"%d\0", "两个格式串")
    require(static_map.get(0xA67341) == b"\x01", "条件初始化标志文件初值")
    require(static_map.get(0xA2F048) == b"[gm]\0", "分派前缀长度常量")
    if 0xA67308 in static_map:
        target = struct.unpack("<I", static_map[0xA67308])[0]
        require(static_map.get(target) == b"[gm]\0", "前缀指针与目标")
    route_tables = evidence.get("route_tables", [])
    require(len(route_tables) == 2, "路由表证据缺失")
    route_map = {int(row["va"], 16): identity(row, "route_table")[1] for row in route_tables}
    if 0x64A807 in route_map:
        require(struct.unpack("<4I", route_map[0x64A807]) == (0x64A663, 0x64A688, 0x64A6A7, 0x64A688), "mode跳表")
    if 0x82A3BD in route_map:
        require(struct.unpack("<7I", route_map[0x82A3BD]) == (0x829C74, 0x829CB8, 0x829D5F, 0x829D5F, 0x829D5F, 0x829CFC, 0x829D2F), "dispatch跳表")

    # 锚点只核本题语义所依赖的具体指令；全体字节校验在上面单独完成。
    anchors = {
        0x64A561: "0fbe11", 0x64A5AC: "837d0802", 0x64A5B0: "746a",
        0x64A5B2: "b9a872a700", 0x64A610: "c605686ea70001",
        0x64A64F: "837dc803", 0x64A713: "6a01", 0x64A748: "6a01",
        0x64A65C: "ff248d07a86400", 0x829C6D: "ff2495bda38200",
        0x64C188: "69c054010000", 0x64C191: "8d94010ca80200",
        0x64C1B0: "8b914cbd0200", 0x64C1DB: "250f000080", 0x64C1FC: "898a50bd0200",
        0x64C448: "c605686ea70000", 0x81BD43: "7629", 0x81BD53: "7219",
        0x81BD57: "ff15bc3cad00", 0x81BD67: "894204",
        0x922996: "c7400c42000000", 0x922A16: "8b45f8",
        0x932D1D: "83e140", 0x932D28: "83c820", 0x932D31: "83c8ff",
        0x93412D: "83e901", 0x934147: "8802", 0x934182: "c701ffffffff",
    }
    for address, expected in anchors.items():
        require(address in instructions and instructions[address]["hex"] == expected, "语义锚点 " + hex(address))
    call_map = {int(call["site"], 16): int(call["resolved"], 16) for f in functions.values() for call in f["calls"]}
    for site, target in {0x64A625: 0x9204C0, 0x64A761: 0x64C9E0, 0x64A773: 0x64CDC0,
                         0x64A786: 0x9204C0, 0x64A7B6: 0x828F60, 0x64A7C5: 0x64C140,
                         0x64A912: 0x64CDC0, 0x64A94B: 0x64C9E0, 0x64A995: 0x828F60,
                         0x9229BA: 0x932FC0, 0x922A0B: 0x932CD0, 0x93416E: 0x932CD0}.items():
        require(call_map.get(site) == target, "消费调用 " + hex(site))

    rows = review["functions"]
    require({row["va"] for row in rows} == {row["va"] for row in evidence["functions"]}, "审阅清单完整且不扩大")
    expected_counts = {"主体已审阅": 10, "局部已审阅": 5, "既有专题复用": 17, "仅上下文导出": 4}
    require(dict(collections.Counter(row["status"] for row in rows)) == review["counts"] == expected_counts, "逐项分级数量")
    for row in rows:
        require(all(row[key] for key in ("scope", "conclusion", "unknown", "evidence")), "逐项范围缺失")
        require(row["chunk_bytes"] == sum(c["size"] for c in functions[int(row["va"], 16)]["chunks"]), "清单块长度")
    for path in DIRECTORY.parent.glob("*.txt"):
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            require(not line.strip() or line.startswith("//"), "中文文档格式 " + path.name + ":" + str(index))

    model_scenarios = behavioral_models(require)
    result = {"status": "PASS" if not errors else "FAIL", "checks": dict(checks), "errors": errors,
              "behavioral_model_scenarios": model_scenarios,
              "scope": "局部字节回证+有限算术模型；没有实机UI/网络验证，没有审完output其他格式"}
    (DIRECTORY / "validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0 if not errors else 1


def behavioral_models(require):
    cases = 0

    def timer(interval, last, first, second):
        if first <= last or first - last < interval:
            return False, last
        return True, second

    timer_cases = [(0, 0, 0, 1, (False, 0)), (100, 0, 99, 100, (False, 0)),
                   (100, 0, 100, 101, (True, 101)), (100, 0xFFFFFFF0, 32, 33, (False, 0xFFFFFFF0)),
                   (300000, 5, 300005, 300006, (True, 300006))]
    for interval, last, first, second, expected in timer_cases:
        require(timer(interval, last, first, second) == expected, "timer边界")
        cases += 1
    passed, refreshed = timer(300000, 0, 300000, 300001)
    require(passed and timer(300000, refreshed, 300002, 300003) == (False, refreshed), "发送查询先通过影响清理")
    cases += 1
    for mode, muted, long_ok, short_ok, same in itertools.product([0, 1, 2, 3, 4, 0xFFFFFFFF], [False, True], [False, True], [False, True], [False, True]):
        decision = 101 if muted and not long_ok else 100 if mode != 2 and not short_ok and same else None
        if muted and not long_ok:
            require(decision == 101, "外门优先于私聊特例")
        elif mode == 2:
            require(decision is None, "私聊仅免短门")
        elif same and not short_ok:
            require(decision == 100, "相同原文门失败")
        else:
            require(decision is None, "接受候选")
        cases += 1

    def old_snprintf_digit(value):
        text = str(value).encode("ascii")
        output, count, result = bytearray(), 1, 0
        for character in text:
            count -= 1
            if count < 0:
                result = -1
                break
            output.append(character)
            result += 1
        count -= 1
        if count >= 0:
            output.append(0)
        return bytes(output), result

    for value, expected in [(0, (b"0", 1)), (9, (b"9", 1)), (10, (b"1", -1)),
                            (-1, (b"-", -1)), (-2147483648, (b"-", -1)), (2147483647, (b"2", -1))]:
        require(old_snprintf_digit(value) == expected, "旧CRT单字节标签")
        cases += 1
    for mode, language in itertools.product(range(4), range(3)):
        payload = old_snprintf_digit(mode)[0] + old_snprintf_digit(language)[0] + b"abc\0"
        require(len(payload) == len(b"abc") + 3 and payload[-1] == 0 and len(payload[:2]) == 2, "正常标签与长度")
        cases += 1
    for cursor in range(16):
        slot = 0x2A80C + 340 * cursor
        require(slot + 339 < 0x2BD4C and (cursor + 1) % 16 in range(16), "历史正常游标")
        cases += 1
    require(0x2A80C + 16 * 340 == 0x2BD4C, "历史邻接游标")
    require(0xA76E70 + 272 == 0xA76F80 and 0xA77090 + 2 + 526 == 0xA772A0, "越边界NUL地址")
    require(2 + 525 + 1 == 528 and 339 + 1 == 340, "留NUL容量算术")
    require(b"rate\x01".replace(b"\x01", b"%") == b"rate%", "历史逆转义例")
    cases += 4
    return cases


if __name__ == "__main__":
    sys.exit(validate())
