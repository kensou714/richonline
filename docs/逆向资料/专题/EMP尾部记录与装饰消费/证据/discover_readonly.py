"""只读定位 EMP 尾部与装饰消费候选；由主任务在批次冻结后执行。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_segment
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
FIELDS = {0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90, 0x94, 0x98,
          0xAC, 0xB0, 0x59C}
SEEDS = (0x7DF010, 0x7E1080, 0x7E1140, 0x7ED0E0)
MEMORY = re.compile(r'\[([^\]]+)\]')
DISPLACEMENT = re.compile(r'\+([0-9A-F]+)h\b', re.I)
REGISTER = re.compile(r'\b(eax|ebx|ecx|edx|esi|edi)\b', re.I)
ALIAS = re.compile(r'^\s*add\s+(eax|ebx|ecx|edx|esi|edi),\s*(59C)h\b', re.I)


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        header = pe + 24 + optional_size + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, header + 12)
        sections.append((image_base + rva, size, offset))

    def audit(ea, size):
        original = ida_bytes.get_bytes(ea, size)
        disk = None
        for start, length, offset in sections:
            relative = ea - start
            if 0 <= relative and relative + size <= length:
                disk = blob[offset + relative:offset + relative + size]
                break
        return dict(va=hex(ea), size=size,
                    idb_hex=original.hex() if original is not None else None,
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=original is not None and original == disk)

    def owner(ea):
        function = ida_funcs.get_func(ea)
        return hex(function.start_ea) if function else None

    def context(ea):
        function = ida_funcs.get_func(ea)
        lower = function.start_ea if function else max(0, ea - 48)
        upper = function.end_ea if function else ea + 49
        left, current = [], ea
        for _ in range(5):
            previous = idc.prev_head(current, lower)
            if previous == idc.BADADDR:
                break
            left.append(previous)
            current = previous
        right, current = [], ea
        for _ in range(6):
            if current >= upper:
                break
            right.append(current)
            following = idc.next_head(current, upper)
            if following == idc.BADADDR:
                break
            current = following
        return [dict(audit(at, idc.get_item_size(at)),
                     text=idc.generate_disasm_line(at, 0) or '')
                for at in list(reversed(left)) + right]

    candidates = []
    scanned = 0
    # 遍历可执行段的已解码代码头，保留未声明函数内的代码；不把数据字节当字段引用。
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(segment_ea)
        if not segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                continue
            scanned += 1
            text = idc.generate_disasm_line(ea, 0) or ''
            hits = []
            for expression in MEMORY.findall(text):
                if not REGISTER.search(expression):
                    continue
                for value in DISPLACEMENT.findall(expression):
                    displacement = int(value, 16)
                    if displacement in FIELDS:
                        hits.append(dict(kind='显式内存偏移候选', displacement=hex(displacement)))
            if ALIAS.search(text):
                hits.append(dict(kind='装饰表地址算术候选', displacement='0x59c'))
            if hits:
                candidates.append(dict(va=hex(ea), owner=owner(ea), text=text,
                                       map_address_neighborhood=0x7DE310 <= ea < 0x7ECB00,
                                       hits=hits, context=context(ea),
                                       status='候选；对象与字段归属未确认'))

    incoming, bridges = [], {}
    for seed in SEEDS:
        pending, visited = [seed], set()
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            for edge in idautils.XrefsTo(target, 0):
                bridge = False
                raw = ida_bytes.get_bytes(edge.frm, 5)
                function = ida_funcs.get_func(edge.frm)
                if (function and function.start_ea == edge.frm and raw and raw[0] == 0xE9
                        and edge.frm + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target):
                    bridge = True
                    bridges[hex(edge.frm)] = dict(audit(edge.frm, 5), target=hex(target))
                    pending.append(edge.frm)
                incoming.append(dict(seed=hex(seed), target=hex(target), site=hex(edge.frm),
                                     kind=int(edge.type), iscode=bool(edge.iscode),
                                     owner=owner(edge.frm), bridge=bridge))
    output = dict(schema=1, disk_sha256=hashlib.sha256(blob).hexdigest(),
                  scope='全可执行段已解码代码头显式非栈寄存器正偏移候选；不证明别名读取穷尽；未解码代码、负偏移、动态偏移、整块复制与间接调用另核',
                  decoded_code_heads_scanned=scanned, candidates=candidates,
                  incoming=incoming, bridges=list(bridges.values()))
    HERE.mkdir(parents=True, exist_ok=True)
    destination = HERE / 'discovery_candidates.json'
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(candidates=len(candidates), incoming=len(incoming), bridges=len(bridges),
                decoded_code_heads_scanned=scanned, output=str(destination))
