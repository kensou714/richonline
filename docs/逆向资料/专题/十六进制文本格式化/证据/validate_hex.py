# -*- coding: utf-8 -*-
"""只读当前PE核原证，写本题validation.json；模型不是实机测试。"""
import collections
import hashlib
import json
import pathlib
import struct
import sys

from hex_model import run_models

HERE = pathlib.Path(__file__).resolve().parent
SHA = "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2"


def validate():
    raw = json.loads((HERE / "hex_raw.json").read_text(encoding="utf-8"))
    review = json.loads((HERE.parent / "函数审阅清单.json").read_text(encoding="utf-8"))
    save_calls = json.loads((HERE / "save_color_calls.json").read_text(encoding="utf-8"))
    image = pathlib.Path(raw["input"]).read_bytes()
    errors, stats = [], collections.Counter()

    def require(ok, name):
        stats["assertions"] += 1
        if not ok:
            errors.append(name)

    require(hashlib.sha256(image).hexdigest() == raw["disk_sha256"] == SHA, "当前EXE指纹")
    require(raw["idb_input_sha256"] != SHA, "IDB原输入指纹边界")
    require(image[:2] == b"MZ", "MZ")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    require(image[pe:pe+4] == b"PE\0\0", "PE")
    optional = pe + 24
    require(struct.unpack_from("<H", image, optional)[0] == 0x10B, "PE32")
    base = struct.unpack_from("<I", image, optional+28)[0]
    sections = []
    table = optional + struct.unpack_from("<H", image, pe+20)[0]
    for i in range(struct.unpack_from("<H", image, pe+6)[0]):
        _, rva, size, offset = struct.unpack_from("<IIII", image, table+i*40+8)
        require(offset+size <= len(image), "节raw边界")
        sections.append((rva, size, offset))

    def disk(ea, size):
        for rva, length, offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= length:
                return image[offset+relative:offset+relative+size]
        return None

    def cstring(ea):
        result = bytearray()
        for index in range(512):
            b = disk(ea+index,1)
            if b == b"\0":
                return bytes(result)
            if b is None:
                return None
            result.extend(b)
        return None

    # 从当前PE导入表确认寄存器间接调用的IAT名称，不只相信IDA注释。
    imports = {}
    import_rva = struct.unpack_from("<I",image,optional+104)[0]
    for index in range(256):
        descriptor = disk(base+import_rva+index*20,20)
        require(descriptor is not None, "导入描述符可读")
        if descriptor is None or descriptor == bytes(20):
            break
        original,_,_,name_rva,first = struct.unpack("<5I",descriptor)
        dll = cstring(base+name_rva)
        for slot in range(4096):
            record = disk(base+(original or first)+slot*4,4)
            require(record is not None, "导入名称表可读")
            if record is None:
                break
            value = struct.unpack("<I",record)[0]
            if value == 0:
                break
            imports[base+first+slot*4] = (dll, None if value & 0x80000000 else cstring(base+value+2))
    require(imports.get(0xAD3B68) == (b"KERNEL32.dll",b"lstrlenA"), "三次长度读取IAT归属")

    def identity(row, kind, allow_unmapped=False):
        data = bytes.fromhex(row["ida_hex"])
        ea, size = int(row["va"],16), row["size"]
        require(len(data) == size, kind+"记录长度")
        require(hashlib.sha256(data).hexdigest() == row["sha256"], kind+"摘要")
        current = disk(ea,size)
        if current is None:
            require(allow_unmapped and row["disk_hex"] is None and row["equal"] is None, kind+"无raw映射")
            stats["unmapped_records"] += 1
        else:
            require(data == current == bytes.fromhex(row["disk_hex"]), kind+"当前PE字节")
            require(row["equal"] is True, kind+"一致标志")
        stats[kind+"_records"] += 1
        stats[kind+"_bytes"] += size
        return ea, data

    functions = {int(f["va"],16): f for f in raw["functions"]}
    require(len(functions) == len(raw["functions"]) == 11, "11函数不重复")
    instructions = {}
    for ea, f in functions.items():
        chunks = [identity(x,"chunk") for x in f["chunks"]]
        require(any(x == ea for x,_ in chunks), "函数入口块")
        for chunk in f["chunks"]:
            require(int(chunk["end"],16) == int(chunk["va"],16)+chunk["size"], "chunk结束")
        for key in ["instructions","non_code_items"]:
            for row in f[key]:
                address, data = int(row["va"],16), bytes.fromhex(row["hex"])
                require(len(data) == row["size"] and len(data)>0, "item长度")
                require(disk(address,len(data)) == data, "item当前PE字节")
                owners = [(start,b) for start,b in chunks if start<=address and address+len(data)<=start+len(b)]
                require(len(owners) == 1, "item块归属")
                if owners:
                    start,b = owners[0]
                    require(b[address-start:address-start+len(data)] == data, "item块内容")
                if key == "instructions":
                    require(address not in instructions, "跨函数重复指令")
                    instructions[address] = row
                stats[key] += 1
    thunks = {}
    for row in raw["thunks"]:
        ea,b = identity(row,"thunk")
        require(len(b) == 5 and b[0] == 0xE9, "E9格式")
        target = ea+5+struct.unpack("<i",b[1:])[0]
        require(target == int(row["target"],16) and ea not in thunks, "E9目标及唯一")
        thunks[ea] = target
    for f in functions.values():
        for call in f["calls"]:
            ea = int(call["site"],16)
            require(ea in instructions, "call指令归属")
            if not call["direct"]:
                require(call["resolved"] is None, "间接调用不伪装已解析")
                continue
            b = bytes.fromhex(instructions[ea]["hex"])
            target = int(call["target"],16)
            if len(b) == 5 and b[0] in (0xE8,0xE9):
                require(ea+5+struct.unpack("<i",b[1:])[0] == target, "直接rel32")
            elif len(b) == 2 and b[0] == 0xEB:
                require(ea+2+struct.unpack("<b",b[1:])[0] == target, "直接rel8")
            else:
                require(False, "未知直接转移格式")
            seen = set()
            while target in thunks and target not in seen:
                seen.add(target)
                target = thunks[target]
            require(target not in seen and target == int(call["resolved"],16), "E9闭合")
    strings = {int(x["va"],16): identity(x,"string")[1] for x in raw["strings"]}
    require(strings.get(0xA679B0) == b"0x00000000\0", "模板完整11字节")
    identity(raw["global"]["snapshot"],"global",True)
    require(raw["global"]["snapshot"]["va"] == "0xacc3d8", "全局起点")
    for row in raw["global"]["references"]:
        insn = row["instruction"]
        require(instructions.get(int(insn["va"],16)) == insn, "全局引用指令")
    anchors = {
        0x8E0382:"bfb079a600", 0x8E038C:"8b54240c", 0x8E0396:"6a10",
        0x8E039C:"bfd8c3ac00", 0x8E03A1:"68ccc3ac00", 0x8E03A9:"f3a5",
        0x8E03B1:"f3a4", 0x8E03B5:"890dccc3ac00", 0x8E03BB:"890dd0c3ac00",
        0x8E03C1:"66890dd4c3ac00", 0x8E03CD:"8b3d683bad00",
        0x8E03DB:"ffd7", 0x8E03EF:"ffd7", 0x8E03F6:"8bd8", 0x8E03F9:"ffd7",
        0x8E03FB:"bfe2c3ac00", 0x8E0400:"8bcb", 0x8E0402:"2bf8",
        0x8E0409:"f3a5", 0x8E0411:"b8d8c3ac00", 0x8E0416:"f3a4",
        0x92BBD4:"837d100a", 0x92BBDA:"837d0800", 0x92BBDE:"7d09",
        0x92BBE9:"c745fc00000000", 0x92BC08:"8b450c",
        0x92BAE5:"c6012d", 0x92BAF4:"f7d8", 0x92BB04:"f77510",
        0x92BB0F:"f77510", 0x92BB1E:"83c257", 0x92BB34:"83c230",
        0x92BB49:"77b4", 0x92BB4E:"c60200", 0x92BB8C:"72cc",
    }
    for ea,expected in anchors.items():
        require(instructions.get(ea,{}).get("hex") == expected, "语义锚点"+hex(ea))
    incoming = raw["incoming"]
    require(len(incoming) == 46, "入边46含别名")
    business = [x for x in incoming if x["owner"] != "0x600248"]
    require(len(business) == 45 and len({x["owner"] for x in business}) == 8, "45业务call8owner")
    for row in incoming:
        insn = row["instruction"]
        ea,b = int(insn["va"],16), bytes.fromhex(insn["hex"])
        require(disk(ea,len(b)) == b and b[0] in (0xE8,0xE9), "incoming指令")
        require(ea+5+struct.unpack("<i",b[1:])[0] == int(row["entry"],16), "incoming目标")
    require({x["call"] for x in save_calls} == {x["site"] for x in business}, "45call清单闭合")
    # 直接解码字段MOV与键PUSH，避免仅凭反编译字段或反汇编注释判定。
    for row in save_calls:
        f = functions[int(row["owner"],16)]
        seq = f["instructions"]
        i = next(i for i,x in enumerate(seq) if x["va"] == row["call"])
        candidates = []
        for x in seq[max(0,i-5):i]:
            b = bytes.fromhex(x["hex"])
            if b[0] == 0x8B and len(b) in (3,6):
                modrm = b[1]
                if (modrm & 7) in (3,6) and (modrm >> 6) in (1,2):
                    offset = int.from_bytes(b[2:],"little",signed=True)
                    candidates.append((x["va"],offset))
        require(len(candidates) == 1 and candidates[0][1] == row["offset"], "字段MOV偏移"+row["call"])
        key_ea = int(row["key_va"],16)
        key_push = instructions[int(row["key_push"],16)]
        require(bytes.fromhex(key_push["hex"]) == b"\x68"+struct.pack("<I",key_ea), "键PUSH地址")
        require(strings[key_ea] == row["key"].encode("ascii")+b"\0", "键原字节")
        consumer = instructions[int(row["consumer_call"],16)]
        require(consumer["hex"] in ("ff16","ff17"), "ESI/EDI间接消费者")
        consumer_index = next(k for k,x in enumerate(seq) if x["va"] == row["consumer_call"])
        between = seq[i+1:consumer_index]
        require(any(x["hex"] == "50" for x in between), "返回EAX入栈")
        require(not any(x["text"].startswith("call") for x in between), "交接前无另一次调用")
        require(row["callback_slot"] == 96 and any(bytes.fromhex(x["hex"])[0] == 0x8D and x["hex"].endswith("60") for x in seq[max(0,i-4):i]), "回调槽60h")
    require({x["va"] for x in review["functions"]} == {x["va"] for x in raw["functions"]}, "逐函数不扩大不遗漏")
    require(dict(collections.Counter(x["status"] for x in review["functions"])) == review["counts"] == {"主体已审阅":3,"局部已审阅":8}, "分级3主体8局部")
    require(review["reuse"][0]["va"] == "0x8e0450", "反解析复用")
    for row in review["functions"]:
        require(all(row[k] for k in ["scope","conclusion","unknown","evidence"]), "分级范围完整")
        require(row["chunk_bytes"] == sum(x["size"] for x in functions[int(row["va"],16)]["chunks"]), "清单块长度")
    for path in HERE.parent.glob("*.txt"):
        for n,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
            require(not line.strip() or line.startswith("//"), "注释式文档"+path.name+":"+str(n))
    models = run_models(require)
    result = {"status":"FAIL" if errors else "PASS", "checks":dict(stats), "errors":errors,
              "models":models, "scope":"字节/有限模型；没有实机保存或回调深拷贝验证"}
    (HERE / "validation.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(validate())
