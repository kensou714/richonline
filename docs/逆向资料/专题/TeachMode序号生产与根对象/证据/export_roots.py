"""冻结后由主代理执行：只读导出已归档构造入口及调用者导航。"""
import importlib.util
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x7BAE60, 0x7DE310)


def context(site, owner):
    if owner is None:
        return []
    heads = sorted({ea for start, end in idautils.Chunks(owner.start_ea)
                    for ea in idautils.Heads(start, end)
                    if ida_bytes.is_code(ida_bytes.get_full_flags(ea))})
    if site not in heads:
        return []
    index = heads.index(site)
    rows = []
    for ea in heads[max(0, index - 7):index + 4]:
        size = idc.get_item_size(ea)
        data = ida_bytes.get_bytes(ea, size)
        rows.append(dict(va=hex(ea), size=size,
                         text=idc.generate_disasm_line(ea, 0) or '',
                         hex=data.hex() if data is not None else None))
    return rows


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_roots_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, SEEDS, HERE / 'roots_raw.json')
    incoming = []
    for seed in SEEDS:
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in idautils.XrefsTo(target, 0):
                owner = ida_funcs.get_func(x.frm)
                incoming.append(dict(seed=hex(seed), target=hex(target),
                                     site=hex(x.frm), kind=int(x.type),
                                     iscode=bool(x.iscode),
                                     owner=hex(owner.start_ea) if owner else None,
                                     context=context(x.frm, owner),
                                     status='调用者导航，G/Map对象归属与写入未核'))
                if (owner and owner.start_ea == x.frm
                        and ida_bytes.get_byte(x.frm) == 0xE9):
                    pending.append(x.frm)
    result = dict(schema=1, scope='仅G/Map已归档构造入口；incoming为待核导航',
                  seeds=[hex(seed) for seed in SEEDS], incoming=incoming)
    (HERE / 'roots_incoming.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(group=summary, incoming=len(incoming), path=str(HERE))
