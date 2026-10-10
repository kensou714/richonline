"""只读导出状态串来源与刷新调用；另保存嵌入序号绝对偏移候选。"""
import importlib.util
import json
import re
from pathlib import Path

import ida_bytes
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x82B090, 0x6AC390, 0x6AFA40, 0x628270)
PATTERN = re.compile(r'\[(?:e[abcd]x|e[sd]i)\+6C4h\]', re.I)


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_closure_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, SEEDS, HERE / 'closure_raw.json')
    rows, seen = [], set()
    for entry in idautils.Functions():
        heads = sorted({ea for start, end in idautils.Chunks(entry)
                        for ea in idautils.Heads(start, end)
                        if ida_bytes.is_code(ida_bytes.get_full_flags(ea))})
        for index, ea in enumerate(heads):
            text = idc.generate_disasm_line(ea, 0) or ''
            if not PATTERN.search(text) or ea in seen:
                continue
            seen.add(ea)
            context = []
            for at in heads[max(0, index - 6):index + 7]:
                size = idc.get_item_size(at)
                context.append(dict(va=hex(at), size=size,
                                    text=idc.generate_disasm_line(at, 0) or '',
                                    hex=ida_bytes.get_bytes(at, size).hex()))
            rows.append(dict(owner=hex(entry), site=hex(ea), text=text,
                             displacement='0x6c4', context=context,
                             status='候选，根对象来源未核'))
    output = HERE / 'absolute_index_candidates.json'
    output.write_text(json.dumps(dict(schema=1, scope='65Ch+68h=6C4h 显式偏移候选',
                                     candidates=rows), ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(summary=summary, candidates=len(rows), path=str(output))
