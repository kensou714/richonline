# -*- coding: utf-8 -*-
"""独立离线回证：仅读取 PE 与证据，写本专题 validation.json。"""
import collections
import hashlib
import json
import pathlib
import re
import struct
import sys

DIRECTORY = pathlib.Path(__file__).resolve().parent
EXPECTED_CATEGORIES = {
    "container_helper": 45,
    "constructor_helper": 9,
    "destructor_helper": 14,
    "copy_support": 1,
}


def validate():
    evidence = json.loads((DIRECTORY / "audio_containers.json").read_text(encoding="utf-8"))
    image = pathlib.Path(evidence["input"]).read_bytes()
    errors = []
    checks = collections.Counter()

    def require(condition, label):
        checks["assertions"] += 1
        if not condition:
            errors.append(label)

    require(image[:2] == b"MZ", "目标缺少 MZ 标识")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    require(image[pe:pe + 4] == b"PE\0\0", "目标缺少 PE 标识")
    optional = pe + 24
    require(struct.unpack_from("<H", image, optional)[0] == 0x10B, "目标不是 PE32")
    base = struct.unpack_from("<I", image, optional + 28)[0]
    section_count = struct.unpack_from("<H", image, pe + 6)[0]
    table = optional + struct.unpack_from("<H", image, pe + 20)[0]
    sections = []
    for index in range(section_count):
        offset = table + 40 * index
        _, rva, raw_size, raw = struct.unpack_from("<IIII", image, offset + 8)
        require(raw + raw_size <= len(image), "PE 节 raw 超出文件")
        sections.append((rva, raw_size, raw))
    disk_sha256 = hashlib.sha256(image).hexdigest()
    require(disk_sha256 == evidence["disk_sha256"], "当前 EXE 指纹与导出时不同")

    def disk_bytes(va, size):
        for rva, raw_size, raw in sections:
            offset = va - base - rva
            if 0 <= offset and offset + size <= raw_size:
                return image[raw + offset:raw + offset + size]
        raise ValueError("无完整 PE raw 映射：" + hex(va))

    def byte_record(record, kind):
        va = int(record["va"], 16)
        size = record["size"]
        ida = bytes.fromhex(record["ida_hex"])
        disk = bytes.fromhex(record["disk_hex"])
        current = disk_bytes(va, size)
        require(len(ida) == len(disk) == size, kind + "长度错误：" + hex(va))
        require(ida == disk == current, kind + "字节不同：" + hex(va))
        require(record["equal"] is True, kind + "导出一致标记错误：" + hex(va))
        require(hashlib.sha256(ida).hexdigest() == record["sha256"], kind + "摘要错误：" + hex(va))
        checks[kind + "_records"] += 1
        checks[kind + "_bytes"] += size
        return va, ida

    functions = evidence["functions"]
    contexts = evidence["contexts"]
    categories = collections.Counter(function["category"] for function in functions)
    require(dict(categories) == EXPECTED_CATEGORIES, "主函数类别/数量不符")
    scope = evidence["scope"]
    scoped = scope["helpers"] + scope["constructors"] + scope["destructors"] + scope["copy_support"]
    require(len(scoped) == len(set(scoped)) == 69, "范围集合重复/缺失")
    main_addresses = [function["va"] for function in functions]
    require(len(main_addresses) == len(set(main_addresses)), "主函数重复")
    require(set(scoped) == set(main_addresses), "scope 与 functions 不一致")
    context_addresses = [function["va"] for function in contexts]
    require(len(context_addresses) == len(set(context_addresses)) == 31, "上下文重复/数量不符")
    require(not set(main_addresses) & set(context_addresses), "上下文混入主函数计数")

    function_map = {}
    for function in functions + contexts:
        va = int(function["va"], 16)
        kind = "main_chunk" if function in functions else "context_chunk"
        function_map[va] = function
        chunks = []
        for chunk in function["chunks"]:
            start, data = byte_record(chunk, kind)
            require(int(chunk["end"], 16) == start + len(data), "chunk 结束地址错误")
            require(all(start + len(data) <= old or old + len(content) <= start
                        for old, content in chunks), "同函数 chunks 重叠：" + hex(va))
            chunks.append((start, data))
        require(any(start == va for start, _ in chunks), "函数入口未位于 chunk 起点")
        instruction_map = {}
        for instruction in function["instructions"]:
            site = int(instruction["va"], 16)
            data = bytes.fromhex(instruction["hex"])
            require(site not in instruction_map, "函数内指令重复：" + hex(site))
            instruction_map[site] = instruction
            require(len(data) == instruction["size"] > 0, "指令长度错误：" + hex(site))
            containing = [(start, content) for start, content in chunks
                          if start <= site and site + len(data) <= start + len(content)]
            require(len(containing) == 1, "指令不完全位于单一 chunk：" + hex(site))
            if containing:
                start, content = containing[0]
                require(data == content[site - start:site - start + len(data)], "指令与块字节不同")
            checks["main_instructions" if kind == "main_chunk" else "context_instructions"] += 1
        for call in function["calls"]:
            require(int(call["site"], 16) in instruction_map, "call/jmp 没有指令证据")

    thunks = {}
    for row in evidence["thunks"]:
        va, data = byte_record(row, "e9")
        require(va not in thunks, "E9 记录重复：" + hex(va))
        require(len(data) == 5 and data[0] == 0xE9, "E9 形状错误：" + hex(va))
        if len(data) == 5:
            target = va + 5 + struct.unpack_from("<i", data, 1)[0]
            require(target == int(row["target"], 16), "E9 相对目标错误：" + hex(va))
        thunks[va] = row

    def resolve(va):
        seen = set()
        while va in thunks:
            require(va not in seen, "E9 解析环：" + hex(va))
            if va in seen:
                break
            seen.add(va)
            va = int(thunks[va]["target"], 16)
        require(disk_bytes(va, 1) != b"\xe9", "E9 链导出不完整：" + hex(va))
        return va

    for function in functions + contexts:
        for call in function["calls"]:
            require(resolve(int(call["target"], 16)) == int(call["resolved"], 16),
                    "call/jmp resolved 错误：" + call["site"])
        for incoming in function["incoming"]:
            caller = function_map.get(int(incoming["caller"], 16))
            require(caller is not None, "入边调用方未导出：" + incoming["site"])
            if caller:
                matches = [call for call in caller["calls"] if call["site"] == incoming["site"]]
                require(any(call["target"] == incoming["entry"] and call["resolved"] == function["va"]
                            for call in matches), "入边与调用记录不一致：" + incoming["site"])

    copy = function_map[0x9213A0]
    copy_instructions = {int(instruction["va"], 16) for instruction in copy["instructions"]}
    require(len(evidence["copy_tables"]) == 6, "复制跳表数量错误")
    for row in evidence["copy_tables"]:
        va, data = byte_record(row, "copy_table")
        require(len(data) % 4 == 0, "跳表非 DWORD 对齐长度")
        targets = [struct.unpack_from("<I", data, offset)[0] for offset in range(0, len(data), 4)]
        require(targets == [int(target, 16) for target in row["targets"]], "跳表值错误")
        require(all(target in copy_instructions for target in targets), "跳表目标未命中复制指令")
    require(checks["copy_table_bytes"] == 120, "复制跳表字节总数错误")

    documents = sorted(DIRECTORY.parent.glob("*.txt"))
    required_documents = {
        "00_阅读入口与证据范围.txt",
        "01_字段布局与成员归属.txt",
        "02_操作契约与释放责任.txt",
        "03_逐函数审阅清单.txt",
    }
    require(required_documents <= {path.name for path in documents}, "四份原始中文正文缺失")
    for path in documents:
        lines = path.read_text(encoding="utf-8").splitlines()
        require(all(not line.strip() or line.startswith("//") for line in lines),
                "正文存在非 // 行：" + path.name)
        require(all(not re.match(r"//\s*(?:#{1,6}\s|```|[-*+]\s|\|)", line) for line in lines),
                "正文包含 Markdown 排版：" + path.name)
    review = (DIRECTORY.parent / "03_逐函数审阅清单.txt").read_text(encoding="utf-8")
    listed = [hex(int(va, 16)) for va in re.findall(r"^// (0x[0-9A-Fa-f]+) /", review, re.MULTILINE)]
    require(len(listed) == len(set(listed)) == 69, "逐函数清单地址重复/数量不符")
    require(set(listed) == set(main_addresses), "逐函数清单与证据集合不符")

    report = {
        "status": "PASS" if not errors else "FAIL",
        "scope": "局部机器证据一致性、证据引用、清单覆盖与中文注释格式；非动态游戏验证",
        "disk_sha256": disk_sha256,
        "idb_input_sha256": evidence["idb_input_sha256"],
        "whole_idb_identity_claimed": False,
        "functions": len(functions),
        "categories": dict(categories),
        "contexts": len(contexts),
        "counts": dict(checks),
        "documents": [path.name for path in documents],
        "errors": errors,
    }
    (DIRECTORY / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    result = validate()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result["status"] == "PASS" else 1)
