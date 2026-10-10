"""只读导出真实消费者相邻调用，确认哪些 this 方法属于大对象。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')
THUNKS = [0x60C4B2, 0x61218C, 0x6085EC, 0x6128D0, 0x60A2AC,
          0x60771E, 0x6036E1]


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    targets = {}
    for thunk in THUNKS:
        raw = db.bytes.get_bytes_at(thunk, 5)
        if raw[0] != 0xE9:
            raise ValueError('方法跳板未匹配：' + hex(thunk))
        targets[hex(thunk)] = hex(thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True))
    summary = namespace['export_group'](db, [int(t, 16) for t in targets.values()],
                                         HERE / '证据' / 'consumer_methods.json')
    return dict(export=summary, targets=targets)
