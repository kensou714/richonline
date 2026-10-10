"""只读补录跳表首项；保留上一份50字节采证不覆盖。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent


def export():
    output = HERE / 'table_head_supplement'
    output.mkdir(exist_ok=True)
    core = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
    return runpy.run_path(str(core))['export'](dict(
        topic='GoldCharge跳表首项补证', seeds=(), owner_sites=(),
        data_windows=((0x70B017, 4),), reuse_navigation=()), output)
