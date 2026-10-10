"""只读补录金额事件分支的两级静态跳表。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'table_supplement'
    output.mkdir(exist_ok=True)
    return runpy.run_path(str(CORE))['export'](dict(
        topic='GoldCharge跳表有限补证', seeds=(), owner_sites=(),
        data_windows=((0x70B01B, 50),), reuse_navigation=()), output)
