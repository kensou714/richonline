"""只读导出相邻小访问接口及三个代表调用者，限制扩大范围。"""
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/全局大对象构造与所有权')
ADDRESSES = [0x62A340, 0x62A390, 0x62A3C0, 0x62A420, 0x62A450, 0x62A4B0,
             0x62A4E0, 0x62A540, 0x62A570, 0x62A5D0, 0x62A600,
             0x6A21A0, 0x7367B0, 0x737130]


def run(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    return namespace['export_group'](db, ADDRESSES,
                                     HERE / '证据' / 'accessors_and_consumers.json')
