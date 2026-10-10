"""只读补核元素构造、释放与入口调用者；不把调用次数当语义覆盖。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    thunk = 0x605D06
    raw = db.bytes.get_bytes_at(thunk, 5)
    if raw[0] != 0xE9:
        raise ValueError('元素构造跳板未匹配')
    element = thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True)
    summary = namespace['export_group'](db, [element, 0x6B8210, 0x64A430],
                                         HERE / '证据' / 'layout_seeds.json')
    sites, observed_thunks = [], []
    pending, seen = [0x62A1D0], set()
    while pending:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        for xref in db.xrefs.to_ea(target):
            raw = db.bytes.get_bytes_at(xref.from_ea, 5)
            if xref.type == 19 and raw and raw[0] == 0xE9:
                observed_thunks.append(dict(va=hex(xref.from_ea), target=hex(target),
                                            idb_hex=raw.hex()))
                pending.append(xref.from_ea)
            elif xref.type in (16, 17):
                parent = db.functions.get_at(xref.from_ea)
                sites.append(dict(site=hex(xref.from_ea), target=hex(target),
                    function=hex(parent.start_ea) if parent else None,
                    scope='真实调用导航，不表示调用者语义已审阅'))
    core = json.loads((HERE / '证据' / 'layout_seeds.json').read_text(encoding='utf-8'))
    (HERE / '证据' / 'entry_callers.json').write_text(json.dumps(dict(
        disk_sha256=core['disk_sha256'], element_constructor=hex(element),
        calls=sites, observed_e9_navigation=observed_thunks,
        scope='调用边导航；跳板本轮只有IDB观察，后续纳入磁盘核验'),
        ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(export=summary, element=hex(element), real_calls=len(sites),
                callers=sorted({s['function'] for s in sites if s['function']}))
