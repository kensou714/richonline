"""只读收集根对象 +65Ch 显式引用，寻找聚合复制而非单字段赋值。"""
import json
import re
from pathlib import Path

import ida_bytes
import idautils
import idc

HERE = Path(__file__).resolve().parent
PATTERN = re.compile(r'\[[^\]]*\+65Ch\]', re.I)


def export(db):
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
                             context=context, status='候选，根对象来源未核'))
    out = HERE / 'embedded_roots_candidates.json'
    out.write_text(json.dumps(dict(schema=1, candidates=rows),
                              ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), candidates=len(rows))
