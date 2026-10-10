"""只读补核唯一记录提交接口，闭合写入槽与数量状态。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    thunk = 0x6068AA
    raw = db.bytes.get_bytes_at(thunk, 5)
    if raw[0] != 0xE9:
        raise ValueError('记录提交跳板未匹配')
    target = thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True)
    summary = namespace['export_group'](db, [target], HERE / '证据' / 'record_finalize.json')
    return dict(export=summary, target=hex(target))
