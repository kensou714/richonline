"""只读发现 TeachMode 两条消费链附近的显式字段引用。"""
import importlib.util
import json
import re
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x63E210, 0x7284B0, 0x6A14B0)
PATTERN = re.compile(r'\[(?:e[abcd]x|e[sd]i)\+(25C|68)h\]', re.I)


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_group_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, SEEDS, HERE / 'seed_raw.json')
    incoming = []
    for seed in SEEDS:
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in idautils.XrefsTo(target, 0):
                f = ida_funcs.get_func(x.frm)
                incoming.append(dict(seed=hex(seed), target=hex(target),
                                     site=hex(x.frm), kind=int(x.type),
                                     iscode=bool(x.iscode),
                                     owner=hex(f.start_ea) if f else None))
                if f and f.start_ea == x.frm and ida_bytes.get_byte(x.frm) == 0xE9:
                    pending.append(x.frm)
    candidates, seen_sites = [], set()
    for entry in idautils.Functions():
        chunks = list(idautils.Chunks(entry))
        heads = sorted({ea for start, end in chunks for ea in idautils.Heads(start, end)
                        if ida_bytes.is_code(ida_bytes.get_full_flags(ea))})
        for index, ea in enumerate(heads):
            text = idc.generate_disasm_line(ea, 0) or ''
            match = PATTERN.search(text)
            if not match or ea in seen_sites:
                continue
            seen_sites.add(ea)
            context = []
            for at in heads[max(0, index - 4):index + 5]:
                size = idc.get_item_size(at)
                context.append(dict(va=hex(at), size=size,
                                    text=idc.generate_disasm_line(at, 0) or '',
                                    hex=ida_bytes.get_bytes(at, size).hex()))
            candidates.append(dict(owner=hex(entry), site=hex(ea),
                                   displacement=hex(int(match.group(1), 16)),
                                   text=text, context=context,
                                   status='候选，字段所属对象未核'))
    output = HERE / 'field_candidates.json'
    output.write_text(json.dumps(dict(schema=1, scope='全声明函数显式非栈寄存器偏移候选；不证明字段所属对象',
                                     incoming=incoming, candidates=candidates),
                                 ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(seed_summary=summary, candidate_count=len(candidates), path=str(output))
