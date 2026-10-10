"""大厅类型文字与跳表的有限补证；不导出函数，不推断注册表完整性。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'type_tables'
    output.mkdir(exist_ok=True)
    assert not (output / 'bounded_raw.json').exists(), '禁止覆盖历史补证'
    return runpy.run_path(str(CORE))['export'](dict(
        topic='大厅分类与索引列表生命周期：类型表与跳表',
        seeds=(), owner_sites=(),
        data_windows=(
            (0xA673A4, 16), (0xA237BC, 4), (0xA237B4, 6),
            (0xA237B0, 4), (0xA237AC, 4), (0x6A0083, 16),
            (0x6A0A63, 16),
        ),
        reuse_navigation=(),
    ), output)
