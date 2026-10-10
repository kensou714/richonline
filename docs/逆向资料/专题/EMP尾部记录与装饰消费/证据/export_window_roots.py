"""只读保存尾部未声明导航桥及相邻输出表消费者；不创建函数。"""
import importlib.util
import json
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('emp_picker_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, (0x7E1420,), HERE / 'tail_picker_raw.json')
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

    bridges = {}

    def resolve(ea):
        seen = set()
        while ea not in seen and len(seen) < 16:
            raw = ida_bytes.get_bytes(ea, 5)
            if not raw or raw[0] != 0xE9:
                break
            seen.add(ea)
            target = ea + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            bridges[hex(ea)] = dict(audit(ea, 5), target=hex(target))
            ea = target
        return ea

    incoming = []
    for target in (0x601E4F, 0x6074C6):
        resolve(target)
        for edge in idautils.XrefsTo(target, 0):
            owner = ida_funcs.get_func(edge.frm)
            incoming.append(dict(target=hex(target), site=hex(edge.frm), kind=int(edge.type),
                                 owner=hex(owner.start_ea) if owner else None))
    start, end = 0x7E1460, 0x7E14A0
    items, calls = [], []
    for ea in idautils.Heads(start, end):
        iscode = bool(ida_bytes.is_code(ida_bytes.get_full_flags(ea)))
        owner = ida_funcs.get_func(ea)
        items.append(dict(audit(ea, idc.get_item_size(ea)),
                          text=idc.generate_disasm_line(ea, 0) or '', is_code=iscode,
                          declared_owner=hex(owner.start_ea) if owner else None))
        if iscode:
            for edge in idautils.XrefsFrom(ea, 0):
                if edge.type in (16, 17):
                    calls.append(dict(site=hex(ea), target=hex(edge.to),
                                      implementation=hex(resolve(edge.to))))
    window = dict(start_va=hex(start), end_va=hex(end),
                  status='未声明代码导航窗；相邻位置不等于业务归属确认',
                  raw_range=audit(start, end - start), items=items, calls=calls)
    output = dict(bridges=list(bridges.values()), incoming=incoming, windows=[window])
    (HERE / 'window_roots_raw.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(picker=summary, bridges=len(bridges), incoming=incoming, window_items=len(items))
