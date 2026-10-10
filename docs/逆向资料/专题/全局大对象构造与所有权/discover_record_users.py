"""只读导出三个真实调用者，寻找记录写入和显示消费边界。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')
TARGETS = [0x6A8660, 0x6A87D0, 0x736D10]


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    return namespace['export_group'](db, TARGETS, HERE / '证据' / 'record_users.json')
