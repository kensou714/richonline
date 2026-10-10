"""只读补录 case60 的两级表项，避免将反汇编标签作为唯一证据。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent


def export():
    output = HERE / 'case60_table'
    output.mkdir(exist_ok=True)
    core = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
    return runpy.run_path(str(core))['export'](dict(
        topic='case60两级表项', seeds=(), owner_sites=(),
        data_windows=((0x82A391, 1), (0x82A341, 4)),
        reuse_navigation=()), output)
