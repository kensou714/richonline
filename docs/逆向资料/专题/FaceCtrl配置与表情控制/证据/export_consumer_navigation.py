"""最小导航：4F 工厂实际构造函数和它引用的数据窗口，暂不宣称虚表归属。"""
import json
import runpy
from pathlib import Path

import ida_bytes
import idautils
import idc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def export(db):
    shared = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))
    summary = shared['export_group'](db, [0x6FC000], str(HERE / 'consumer_constructor_raw.json'))
    rows = []
    for start, end in idautils.Chunks(0x6FC000):
        for ea in idautils.Heads(start, end):
            for x in idautils.XrefsFrom(ea, 0):
                if not x.iscode:
                    data = ida_bytes.get_bytes(x.to, 24)
                    rows.append(dict(site=hex(ea), target=hex(x.to), name=idc.get_name(x.to),
                                     text=idc.generate_disasm_line(ea, 0) or '',
                                     candidate_24_bytes=data.hex() if data is not None else None))
    (HERE / 'consumer_data_navigation.json').write_text(json.dumps(dict(scope='导航候选，不是虚表审阅', rows=rows),
                                                               ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(summary, data_candidates=len(rows))
