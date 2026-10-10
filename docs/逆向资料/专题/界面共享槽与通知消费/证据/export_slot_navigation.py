"""只读记录两个共享槽的静态交叉引用及置位块；不认领所在大函数。"""
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent


def export():
    import ida_funcs
    import idautils
    import idc
    destination = HERE / 'slot_xrefs.json'
    assert not destination.exists()
    slots = []
    for va in (0xA859C4, 0xA859CC):
        rows = []
        for ref in idautils.XrefsTo(va, 0):
            owner = ida_funcs.get_func(ref.frm)
            rows.append(dict(site_va=hex(ref.frm), kind=int(ref.type),
                             is_code=bool(ref.iscode),
                             owner_va=hex(owner.start_ea) if owner else None,
                             text=idc.generate_disasm_line(ref.frm, 0)))
        slots.append(dict(slot_va=hex(va), references=rows))
    core = HERE.parents[1] / '高扇入界面操作辅助/证据/export_owner_context.py'
    result = runpy.run_path(str(core))['export'](
        [0x733B1B, 0x733D76, 0x7340E6, 0x75137C],
        HERE / 'slot_owner_context.json', predecessor_depth=1)
    destination.write_text(json.dumps(dict(
        scope='IDA静态交叉引用；不是运行时可达性或穷尽别名写入证明', slots=slots),
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result
