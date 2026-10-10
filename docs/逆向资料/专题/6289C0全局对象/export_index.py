"""只读导出等级配置加载末尾调用的第二数组构建函数。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/6289C0全局对象')


def export(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    return namespace['export_group'](db, [0x7DC330], HERE / '证据' / 'index.json')
