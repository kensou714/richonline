"""在当前IDA lease中运行；只读本组函数的RTC表并写出局部原证。"""
import hashlib
import json
import struct
from pathlib import Path

import ida_bytes
import idc

HERE = Path(r"F:\大富翁online\Richonline\docs\逆向资料\专题\本地事件剩余消费者\证据")
blob = (HERE.parents[4] / "RnClient.exe").read_bytes()
fingerprint = hashlib.sha256(blob).hexdigest()
assert fingerprint == "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"
pe = struct.unpack_from("<I", blob, 0x3C)[0]
count = struct.unpack_from("<H", blob, pe + 6)[0]
optional = struct.unpack_from("<H", blob, pe + 20)[0]
base = struct.unpack_from("<I", blob, pe + 52)[0]
sections = [struct.unpack_from("<IIII", blob, pe + 24 + optional + 40*i + 8)
            for i in range(count)]


def disk(ea, size):
    for virtual, rva, raw_size, raw_offset in sections:
        relative = ea - base - rva
        if 0 <= relative and relative + size <= raw_size:
            return blob[raw_offset + relative:raw_offset + relative + size]
    raise AssertionError(f"无PE原始映射：{ea:#x}")


def raw(ea, size, kind):
    actual = disk(ea, size)
    idb = ida_bytes.get_bytes(ea, size)
    assert actual == idb, hex(ea)
    return {"va": hex(ea), "size": size, "kind": kind,
            "disk_hex": actual.hex(), "idb_hex": idb.hex(), "matching": True}


functions = {}
for source in sorted(HERE.glob("*.json")):
    for function in json.loads(source.read_text(encoding="utf-8")).get("functions", []):
        functions[function["va"]] = function
frames, names = [], {}
for va, function in sorted(functions.items()):
    for call in function["calls"]:
        if call["implementation"] != "0x91f700":
            continue
        site = int(call["site"], 16)
        load = idc.prev_head(site)
        assert idc.print_insn_mnem(load) == "lea" and idc.print_operand(load, 0) == "edx"
        frame_va = idc.get_operand_value(load, 1)
        frame = raw(frame_va, 8, "framedesc")
        local_count, variables_va = struct.unpack("<iI", bytes.fromhex(frame["disk_hex"]))
        assert 0 < local_count < 512
        variables = raw(variables_va, 12 * local_count, "vardesc")
        local_items = []
        for index in range(local_count):
            offset, size, name_va = struct.unpack_from(
                "<iII", bytes.fromhex(variables["disk_hex"]), index * 12)
            assert offset < 0 and 0 < size < 4096
            if name_va not in names:
                name_size = 1
                while disk(name_va + name_size - 1, 1) != b"\0":
                    name_size += 1
                    assert name_size < 256
                names[name_va] = raw(name_va, name_size, "variable_name")
            name = bytes.fromhex(names[name_va]["disk_hex"])[:-1].decode("ascii", errors="strict")
            local_items.append({"index": index, "ebp_offset": offset,
                                "size": size, "name_va": hex(name_va), "name": name})
        frames.append({"function_va": va, "call_va": call["site"],
                       "pointer_load_va": hex(load), "local_count": local_count,
                       "frame": frame, "variables": variables, "locals": local_items})
assert frames
output = {"disk_sha256": fingerprint,
          "scope": "已保存函数中所有RTC_CheckStackVars调用；局部尺寸不等同于传输长度",
          "frames": frames, "name_ranges": list(names.values())}
(HERE / "rtc_ranges.json").write_text(
    json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"RTC函数": len(frames), "局部项": sum(f["local_count"] for f in frames), "名称范围": len(names)}, ensure_ascii=False))
