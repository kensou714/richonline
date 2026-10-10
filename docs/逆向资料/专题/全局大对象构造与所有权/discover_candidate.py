"""IDA-MCP 只读候选勘察；仅导出入口/构造及全局引用，不改数据库。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    entry, constructor_thunk, global_va = 0x62A1D0, 0x60E9F1, 0xA76734
    raw = db.bytes.get_bytes_at(constructor_thunk, 5)
    if not raw or len(raw) != 5 or raw[0] != 0xE9:
        raise ValueError('候选构造跳板不是当前预期E9')
    constructor = constructor_thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True)
    summary = namespace['export_group'](db, [entry, constructor],
                                         HERE / '证据' / 'candidate_core.json')
    references = []
    for xref in db.xrefs.to_ea(global_va):
        parent = db.functions.get_at(xref.from_ea)
        context = [dict(va=hex(i.ea), text=db.instructions.get_disassembly(i))
                   for i in db.instructions.get_between(xref.from_ea, xref.from_ea + 24)]
        references.append(dict(source=hex(xref.from_ea), kind=int(xref.type),
            containing_function=hex(parent.start_ea) if parent else None,
            context=context, scope='导航上下文；尚未审阅或计入函数完成'))
    core = json.loads((HERE / '证据' / 'candidate_core.json').read_text(encoding='utf-8'))
    navigation = dict(disk_sha256=core['disk_sha256'], entry=hex(entry),
        constructor=hex(constructor), global_va=hex(global_va),
        global_idb_hex=db.bytes.get_bytes_at(global_va, 4).hex(),
        global_references=references,
        scope='候选全局引用导航；不证明调用职责或所有权闭合')
    (HERE / '证据' / 'candidate_navigation.json').write_text(
        json.dumps(navigation, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(core=summary, constructor=hex(constructor),
                global_references=len(references),
                parent_functions=sorted({r['containing_function'] for r in references
                                         if r['containing_function']}))
