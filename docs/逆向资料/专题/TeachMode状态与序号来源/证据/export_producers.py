"""只读导出字段候选生产者及所有直接跳板引用者。"""
import importlib.util
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x69DF50, 0x6A11E0, 0x6A1660, 0x6A18B0,
         0x6A21A0, 0x728C10, 0x72C050, 0x72C2D0)


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_producers_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, SEEDS, HERE / 'producers_raw.json')
    rows = []
    for seed in SEEDS:
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in idautils.XrefsTo(target, 0):
                f = ida_funcs.get_func(x.frm)
                rows.append(dict(seed=hex(seed), target=hex(target), site=hex(x.frm),
                                 kind=int(x.type), iscode=bool(x.iscode),
                                 owner=hex(f.start_ea) if f else None))
                if f and f.start_ea == x.frm and ida_bytes.get_byte(x.frm) == 0xE9:
                    pending.append(x.frm)
    output = HERE / 'producers_incoming.json'
    output.write_text(json.dumps(dict(schema=1, incoming=rows),
                                 ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(summary=summary, incoming=len(rows), path=str(output))
