"""只读导出 Rank 初始函数与限定 UI 窗口；不创建函数或改动 IDB。"""
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
FUNCTIONS = (0x7559E0, 0x7986C0, 0x799860, 0x79A4B0, 0x79A550,
             0x79A590, 0x79A5F0, 0x79A6B0, 0x753ED0, 0x7997F0)
WINDOWS = ((0x7544C0, 0x754560, 0x754110), (0x754600, 0x754690, 0x754110),
           (0x754940, 0x754A10, 0x754110), (0x7556C0, 0x755790, 0x755290),
           (0x7557D0, 0x755870, 0x755290))
GLOBALS = (0xA859D0, 0xA85A10, 0xA85A14, 0xA84418, 0xA84310)
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError('当前磁盘 EXE 与准备版本不一致')
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional_size + index * 40
        _, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((image_base + rva, raw_size, raw_offset))

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

    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('rank_initial_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, FUNCTIONS, HERE / 'rank_core_raw.json')
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

    windows, data_refs = [], []
    sites = set()
    for start, end, expected_owner in WINDOWS:
        # 原始端点仅为导航范围；落在指令中时按 IDA item 边界扩至完整项。
        actual_start = ida_bytes.get_item_head(start)
        actual_end = ida_bytes.get_item_end(end - 1)
        items, calls = [], []
        for ea in idautils.Heads(actual_start, actual_end):
            function = ida_funcs.get_func(ea)
            iscode = bool(ida_bytes.is_code(ida_bytes.get_full_flags(ea)))
            items.append(dict(audit(ea, idc.get_item_size(ea)),
                              text=idc.generate_disasm_line(ea, 0) or '', is_code=iscode,
                              declared_owner=hex(function.start_ea) if function else None))
            sites.add(ea)
            if iscode:
                for edge in idautils.XrefsFrom(ea, 0):
                    if edge.type in (16, 17):
                        final, chain = resolve(edge.to)
                        calls.append(dict(site=hex(ea), target=hex(edge.to), implementation=hex(final),
                                          thunks=[hex(at) for at in chain]))
        windows.append(dict(requested_start=hex(start), requested_end=hex(end),
                            start_va=hex(actual_start), end_va=hex(actual_end),
                            expected_owner=hex(expected_owner),
                            status='大型UI限定字段窗口，不提升整函数语义覆盖',
                            raw_range=audit(actual_start, actual_end - actual_start),
                            items=items, calls=calls))
    for seed in FUNCTIONS:
        for start, end in idautils.Chunks(seed):
            sites.update(idautils.Heads(start, end))
    for site in sorted(sites):
        for edge in idautils.XrefsFrom(site, 0):
            if edge.iscode:
                continue
            target = edge.to
            string_type = idc.get_str_type(target)
            literal = (ida_bytes.get_strlit_contents(target, -1, string_type)
                       if string_type == 0 else None)
            literal = bytes(literal) if literal is not None else None
            candidate_raw = audit(target, len(literal) + 1) if literal is not None else None
            confirmed = bool(candidate_raw and candidate_raw['matching'] is True and
                             candidate_raw['idb_hex'] == literal.hex() + '00')
            raw = candidate_raw if confirmed else audit(target, 16)
            data_refs.append(dict(site=hex(site), target=hex(target), kind=int(edge.type),
                                  automatic_name=idc.get_name(target), raw=raw,
                                  string_hex=literal.hex() if confirmed else None,
                                  ida_string_candidate_hex=literal.hex() if literal is not None else None,
                                  confirmed_c_string=confirmed,
                                  string_type=string_type,
                                  string_boundary=('实际C字串：原字节等于内容加00且磁盘匹配'
                                                   if confirmed else
                                                   '16字节导航候选；IDA自动字符串解释未通过实际C字串门')))
    global_rows = [dict(audit(ea, 4), automatic_name=idc.get_name(ea),
                        boundary='四字节导航槽；无磁盘映射仍只导航，不证明全局完整大小或类型')
                   for ea in GLOBALS]
    startup = ROOT / 'docs/逆向资料/专题/股票与交易流程/证据/stock_core.json'
    output = dict(disk_sha256=digest, windows=windows, data_refs=data_refs,
                  global_slots=global_rows, bridges=list(bridges.values()),
                  reused_sources=[dict(path=str(startup.relative_to(ROOT)),
                                       sha256=hashlib.sha256(startup.read_bytes()).hexdigest())])
    (HERE / 'rank_navigation_raw.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(core=summary, windows=len(windows), items=sum(len(w['items']) for w in windows),
                bridges=len(bridges), data_refs=len(data_refs), global_slots=len(global_rows))
