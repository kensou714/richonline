"""只读导出真实入口消费后的六个方法，按ECX数据流选择。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/6289C0全局对象')
THUNKS = [0x607C64, 0x60D853, 0x602967, 0x611426, 0x607B38, 0x601BD9]


def export(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    targets = {}
    for thunk in THUNKS:
        raw = db.bytes.get_bytes_at(thunk, 5)
        if len(raw) != 5 or raw[0] != 0xE9:
            raise ValueError('访问器跳板未匹配：' + hex(thunk))
        targets[hex(thunk)] = hex(thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True))
    summary = namespace['export_group'](db, [int(v, 16) for v in targets.values()], HERE / '证据' / 'accessors.json')
    return dict(export=summary, targets=targets)
