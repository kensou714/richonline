"""由主代理串行执行的有限IDA只读导出；消费者仅留调用点窗口。"""
import importlib.util
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x63FB70, 0x63FBE0, 0x63FFB0, 0x6400B0)
CALLSITES = (0x623D9C, 0x6428D4, 0x642913, 0x642C34, 0x643812, 0x6441D3, 0x644B84)


def context(site, before=12, after=18):
    owner = ida_funcs.get_func(site)
    if not owner:
        return None, []
    heads = sorted({ea for start, end in idautils.Chunks(owner.start_ea)
                    for ea in idautils.Heads(start, end)
                    if ida_bytes.is_code(ida_bytes.get_full_flags(ea))})
    if site not in heads:
        return hex(owner.start_ea), []
    index = heads.index(site)
    rows = []
    for ea in heads[max(0, index - before):index + after + 1]:
        size = idc.get_item_size(ea)
        data = ida_bytes.get_bytes(ea, size)
        rows.append(dict(va=hex(ea), size=size, text=idc.generate_disasm_line(ea, 0) or '',
                         hex=data.hex() if data else None))
    return hex(owner.start_ea), rows


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('vehpet_group', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, SEEDS, HERE / 'vehpet_raw.json')
    literals, rejected_literals = [], []
    # 只收四个新函数直接引用的已声明字符串，不读任意指针或扩大数据域。
    for seed in SEEDS:
        for start, end in idautils.Chunks(seed):
            for site in idautils.Heads(start, end):
                for target in idautils.DataRefsFrom(site):
                    kind = idc.get_str_type(target)
                    if kind is None or kind < 0:
                        continue
                    size = idc.get_item_size(target)
                    if not 0 < size <= 512:
                        continue
                    content = ida_bytes.get_strlit_contents(target, -1, kind)
                    raw = ida_bytes.get_bytes(target, size)
                    # 只接受精确声明的ASCII C串；EH/cookie数据的误标不进入键证据。
                    strict = (kind == 0 and idc.get_item_head(target) == target and
                              content is not None and raw == content + b'\0' and
                              bool(content) and all(32 <= value <= 126 for value in content))
                    if not strict:
                        rejected_literals.append(dict(owner=hex(seed), site=hex(site),
                                                      target=hex(target), string_type=kind,
                                                      size=size, reason='未通过精确ASCII C串声明门'))
                        continue
                    literals.append(dict(owner=hex(seed), site=hex(site), target=hex(target),
                                         string_type=kind, size=size,
                                         hex=raw.hex(), strict_c_string=True,
                                         content_hex=content.hex()))
    windows = []
    for site in CALLSITES:
        owner, rows = context(site)
        windows.append(dict(site=hex(site), owner=owner, context=rows,
                            status='既有消费者字段窗口；不代表全函数新审阅'))
    incoming = []
    for seed in (*SEEDS, 0xA766EC):
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for xref in idautils.XrefsTo(target, 0):
                owner, rows = context(xref.frm, before=7, after=4)
                incoming.append(dict(seed=hex(seed), target=hex(target), site=hex(xref.frm),
                                     kind=int(xref.type), iscode=bool(xref.iscode), owner=owner,
                                     context=rows, status='引用导航；生命周期和对象归属待核'))
                if owner == hex(xref.frm) and ida_bytes.get_byte(xref.frm) == 0xE9:
                    pending.append(xref.frm)
    result = dict(schema=1, scope='四个新入口直接字符串、七个既有调用点、全局和入口引用导航',
                  literals=literals, rejected_literals=rejected_literals,
                  windows=windows, incoming=incoming,
                  context_disk_status='待verify_context.py逐条离线核验；IDA副本不可单独视为磁盘原证')
    (HERE / 'vehpet_context.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(group=summary, literals=len(literals), windows=len(windows), incoming=len(incoming))
