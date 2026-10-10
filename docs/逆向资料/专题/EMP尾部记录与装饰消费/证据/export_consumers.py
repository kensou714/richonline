"""只读导出装饰消费者与尾部导航窗；窗口不创建函数、不视作函数入口。"""
import hashlib
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
FRESH = (0x7E7530, 0x7ECF40, 0x7ED1E0, 0x7E8240, 0x7E8890)
RECHECK = (0x7E83D0, 0x7E1140)
WINDOWS = ((0x7E10E0, 0x7E1140), (0x7E11A0, 0x7E1420))


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('emp_consumers_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fresh_summary = module.export_group(db, FRESH, HERE / 'consumers_raw.json')
    reuse_summary = module.export_group(db, RECHECK, HERE / 'rechecked_raw.json')
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
        chain = []
        while ea not in chain and len(chain) < 16:
            raw = ida_bytes.get_bytes(ea, 5)
            if not raw or raw[0] != 0xE9:
                break
            chain.append(ea)
            target = ea + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            bridges[hex(ea)] = dict(audit(ea, 5), target=hex(target))
            ea = target
        return ea, chain

    windows = []
    for start, end in WINDOWS:
        items, calls, xrefs = [], [], []
        for ea in idautils.Heads(start, end):
            flags = ida_bytes.get_full_flags(ea)
            size = idc.get_item_size(ea)
            function = ida_funcs.get_func(ea)
            iscode = bool(ida_bytes.is_code(flags))
            items.append(dict(audit(ea, size), text=idc.generate_disasm_line(ea, 0) or '',
                              is_code=iscode,
                              declared_owner=hex(function.start_ea) if function else None))
            for edge in idautils.XrefsTo(ea, 0):
                owner = ida_funcs.get_func(edge.frm)
                xrefs.append(dict(target=hex(ea), site=hex(edge.frm), kind=int(edge.type),
                                  owner=hex(owner.start_ea) if owner else None))
            if iscode:
                for edge in idautils.XrefsFrom(ea, 0):
                    if edge.type not in (16, 17):
                        continue
                    final, chain = resolve(edge.to)
                    calls.append(dict(site=hex(ea), target=hex(edge.to),
                                      implementation=hex(final), thunks=[hex(at) for at in chain]))
        windows.append(dict(start_va=hex(start), end_va=hex(end),
                            status='未声明代码导航窗；起点非函数入口断言',
                            raw_range=audit(start, end - start), items=items,
                            calls=calls, incoming_item_xrefs=xrefs))
    incoming = []
    for seed in FRESH + RECHECK:
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for edge in idautils.XrefsTo(target, 0):
                owner = ida_funcs.get_func(edge.frm)
                raw = ida_bytes.get_bytes(edge.frm, 5)
                bridge = bool(owner and owner.start_ea == edge.frm and raw and raw[0] == 0xE9
                              and edge.frm + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
                incoming.append(dict(seed=hex(seed), target=hex(target), site=hex(edge.frm),
                                     kind=int(edge.type), iscode=bool(edge.iscode),
                                     owner=hex(owner.start_ea) if owner else None, bridge=bridge))
                if bridge:
                    resolve(edge.frm)
                    pending.append(edge.frm)
    sources = [ROOT / 'docs/逆向资料/专题/地图与路径/证据/map_runtime_core.json',
               ROOT / 'docs/逆向资料/专题/地图初始化同步/证据/map_sync_start_ready.json']
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), windows=windows,
                  bridges=list(bridges.values()), incoming=incoming,
                  reused_sources=[dict(path=str(path.relative_to(ROOT)),
                                       sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                                  for path in sources])
    destination = HERE / 'windows_and_incoming.json'
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(fresh=fresh_summary, rechecked=reuse_summary, windows=len(windows),
                window_items=sum(len(row['items']) for row in windows),
                bridges=len(bridges), incoming=len(incoming), path=str(destination))
