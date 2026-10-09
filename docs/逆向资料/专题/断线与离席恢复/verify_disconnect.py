"""只读复验离席专题证据，输出核验结果及明确分析边界的函数审阅清单。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path


FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[3]
SOURCES = (
    "ida_disconnect_handlers.json", "ida_disconnect_dependencies.json",
    "ida_disconnect_cleanup.json", "ida_disconnect_resume.json",
    "ida_disconnect_fields.json", "ida_disconnect_end_bridge.json",
)
DOCS = {
    "00": "00_阅读入口与证据范围.txt", "01": "01_等待通知与命令补发.txt",
    "02": "02_离席槽清理与等待恢复.txt", "03": "03_视图恢复与6021边界.txt",
}


def load(name):
    return json.loads((FOLDER / name).read_text(encoding="utf-8"))


def write(name, value):
    (FOLDER / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    binary = (ROOT / "RnClient.exe").read_bytes()
    if binary[:2] != b"MZ":
        raise ValueError("目标不是PE")
    pe = struct.unpack_from("<I", binary, 0x3C)[0]
    if binary[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", binary, pe + 24)[0] != 0x10B:
        raise ValueError("只支持当前PE32")
    count = struct.unpack_from("<H", binary, pe + 6)[0]
    optional_size = struct.unpack_from("<H", binary, pe + 20)[0]
    base = struct.unpack_from("<I", binary, pe + 52)[0]
    sections = []
    for index in range(count):
        offset = pe + 24 + optional_size + index * 40
        _, rva, size, pointer = struct.unpack_from("<IIII", binary, offset + 8)
        sections.append((rva, size, pointer))

    def read_va(va, size):
        relative = int(va, 16) - base
        for rva, length, pointer in sections:
            if rva <= relative and relative + size <= rva + length:
                result = binary[pointer + relative - rva:pointer + relative - rva + size]
                if len(result) == size:
                    return result
        raise ValueError(f"范围未映射到完整磁盘字节：{va}/{size}")

    def check_range(item):
        current = read_va(item["va"], item["size"])
        original = bytes.fromhex(item["idb_hex"])
        saved = bytes.fromhex(item["disk_hex"])
        return {"va": item["va"], "size": item["size"],
                "length_match": len(original) == len(saved) == item["size"],
                "idb_matches_disk": original == current,
                "saved_disk_matches_disk": saved == current,
                "disk_sha256": hashlib.sha256(current).hexdigest()}

    def range_pass(item):
        return item["length_match"] and item["idb_matches_disk"] and item["saved_disk_matches_disk"]

    functions, function_checks, thunk_checks = {}, [], []
    notes = load("disconnect_review_conclusions.json")["functions"]
    disk_hash = hashlib.sha256(binary).hexdigest().upper()
    input_hashes, snapshots = set(), set()
    for name in SOURCES:
        raw = load(name)
        input_hashes.add(raw["idb_baseline_sha256"])
        snapshots.add(raw["disk_sha256"])
        for function in raw["functions"]:
            ea = function["va"]
            regions = [check_range(item) for item in function["byte_ranges"]]
            function_checks.append({"source": name, "va": ea, "ranges": regions,
                                    "match": bool(regions) and all(range_pass(item) for item in regions)})
            if ea in functions:
                if functions[ea]["function"] != function:
                    raise ValueError("同一函数证据冲突：" + ea)
                functions[ea]["sources"].append(name)
            else:
                functions[ea] = {"function": function, "sources": [name]}
        for thunk in raw["thunks"]:
            result = check_range(thunk)
            current = read_va(thunk["va"], thunk["size"])
            target = None
            if len(current) == 5 and current[0] == 0xE9:
                target = hex(int(thunk["va"], 16) + 5 + struct.unpack_from("<i", current, 1)[0])
            result.update(source=name, target=target,
                          target_match=target == thunk["target"],
                          match=range_pass(result) and target == thunk["target"])
            thunk_checks.append(result)
    if set(functions) != set(notes):
        raise ValueError("人工结论和证据函数范围不一致：" + str(set(functions) ^ set(notes)))

    registrations = []
    for entry in load("registration_evidence.json"):
        regions = [check_range(item) for item in entry["ranges"]]
        instruction = read_va(entry["registration_site"], 10)
        jump = read_va(entry["thunk"], 5)
        jump_target = (int(entry["thunk"], 16) + 5 + struct.unpack_from("<i", jump, 1)[0]) if jump[0] == 0xE9 else None
        write_target = struct.unpack_from("<I", instruction, 6)[0] if instruction[:2] == b"\xc7\x05" else None
        registrations.append({"code": entry["code"], "ranges": regions,
                              "write_matches_thunk": write_target == int(entry["thunk"], 16),
                              "jump_matches_bridge": jump_target == int(entry["bridge"], 16),
                              "match": all(range_pass(item) for item in regions)
                              and write_target == int(entry["thunk"], 16)
                              and jump_target == int(entry["bridge"], 16)})

    # 只校验资源文件身份；摘录的解包/索引语义保留原证，不伪称独立重解码。
    resource = load("resource_texts.json")
    resource_hash = hashlib.sha256((ROOT / resource["source"]).read_bytes()).hexdigest()
    resource_check = {"source": resource["source"], "sha256": resource_hash,
                      "match": resource_hash == resource["sha256"], "scope": "文件SHA256复验；未独立重解码"}
    reviews = []
    for ea in sorted(functions, key=lambda value: int(value, 16)):
        status, conclusion, unknown, document = notes[ea]
        document = DOCS[document]
        if not (FOLDER / document).is_file() or not all((status, conclusion, unknown)):
            raise ValueError("缺少正文或明确结论：" + ea)
        item = functions[ea]
        reviews.append({"va": ea, "name": item["function"]["name"], "status": status,
                        "conclusion": conclusion, "unknown": unknown, "document": document,
                        "evidence": [name + "/functions/" + ea for name in item["sources"]]})

    report = {"disk_sha256": disk_hash, "idb_baseline_sha256": sorted(input_hashes),
              "snapshot_disk_sha256": sorted(snapshots), "disk_identity_matches": snapshots == {disk_hash},
              "scope": "静态范围复验；无运行期断线或重连测试；跳板单独计数。",
              "function_count": len(functions), "function_record_count": len(function_checks),
              "function_range_count": sum(len(item["ranges"]) for item in function_checks),
              "thunk_record_count": len(thunk_checks),
              "unique_thunk_count": len({item["va"] for item in thunk_checks}),
              "registration_count": len(registrations), "status_counts": dict(Counter(item["status"] for item in reviews)),
              "functions": function_checks, "thunks": thunk_checks,
              "registrations": registrations, "resource": resource_check}
    report["all_passed"] = report["disk_identity_matches"] and all(
        item["match"] for item in function_checks + thunk_checks + registrations + [resource_check])
    write("核验结果.json", report)
    write("函数审阅清单.json", reviews)
    print(json.dumps({key: report[key] for key in (
        "all_passed", "function_count", "function_record_count", "function_range_count",
        "thunk_record_count", "unique_thunk_count", "registration_count", "status_counts")}, ensure_ascii=True))
    if not report["all_passed"]:
        raise SystemExit("核验失败，详见核验结果.json")


if __name__ == "__main__":
    main()
