"""只读导出文字记录追加、五行显示和关联字符串读取三个接口。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')
THUNKS = [0x607138, 0x60CE35, 0x60D1B9]


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    targets = {}
    for thunk in THUNKS:
        raw = db.bytes.get_bytes_at(thunk, 5)
        if raw[0] != 0xE9:
            raise ValueError('文字接口跳板未匹配：' + hex(thunk))
        targets[hex(thunk)] = hex(thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True))
    summary = namespace['export_group'](db, [int(v, 16) for v in targets.values()],
                                         HERE / '证据' / 'text_contract.json')
    return dict(export=summary, targets=targets)
