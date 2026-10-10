"""只读导出16字节全局对象入口和真实构造；导航不计语义覆盖。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/6289C0全局对象')


def export(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    thunk = 0x607CFF
    raw = db.bytes.get_bytes_at(thunk, 5)
    if len(raw) != 5 or raw[0] != 0xE9:
        raise ValueError('构造跳板未匹配E9')
    constructor = thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True)
    summary = namespace['export_group'](db, [0x6289C0, constructor], HERE / '证据' / 'seed.json')
    references, calls, observed, seen, pending = [], [], [], set(), [0x6289C0]
    for x in db.xrefs.to_ea(0xA766E8):
        parent = db.functions.get_at(x.from_ea)
        refs = [dict(va=hex(i.ea), text=db.instructions.get_disassembly(i))
                for i in db.instructions.get_between(x.from_ea, x.from_ea + 24)]
        references.append(dict(site=hex(x.from_ea), kind=int(x.type),
            parent=hex(parent.start_ea) if parent else None, context=refs))
    while pending:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        for x in db.xrefs.to_ea(target):
            raw = db.bytes.get_bytes_at(x.from_ea, 5)
            if x.type == 19 and raw and raw[0] == 0xE9:
                observed.append(dict(va=hex(x.from_ea), idb_hex=raw.hex(), target=hex(target)))
                pending.append(x.from_ea)
            elif x.type in (16, 17):
                parent = db.functions.get_at(x.from_ea)
                calls.append(dict(site=hex(x.from_ea), target=hex(target),
                    parent=hex(parent.start_ea) if parent else None))
    core = json.loads((HERE / '证据' / 'seed.json').read_text(encoding='utf-8'))
    (HERE / '证据' / 'navigation.json').write_text(json.dumps(dict(
        disk_sha256=core['disk_sha256'], global_va='0xa766e8',
        global_idb_hex=db.bytes.get_bytes_at(0xA766E8, 4).hex(),
        global_refs=references, calls=calls, observed_e9_navigation=observed,
        scope='只读导航；不计局部语义或磁盘块覆盖'), ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(export=summary, constructor=hex(constructor), global_refs=len(references),
                callers=sorted({r['parent'] for r in calls if r['parent']}),
                global_parents=sorted({r['parent'] for r in references if r['parent']}))
