"""只读导出已有启动/退出调用边命中的初始化及删除包装。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/6289C0全局对象')


def export(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    return namespace['export_group'](db, [0x6295C0, 0x7DBE50], HERE / '证据' / 'lifetime.json')
