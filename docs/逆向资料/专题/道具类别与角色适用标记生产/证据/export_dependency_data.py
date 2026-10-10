"""道具构造回调与浮点初值的有限补证，不扩大函数覆盖。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'dependency_data'
    output.mkdir(exist_ok=True)
    assert not (output / 'bounded_raw.json').exists(), '禁止覆盖历史补证'
    return runpy.run_path(str(CORE))['export'](dict(
        topic='道具类别与角色适用标记生产：构造回调与初值',
        seeds=(), owner_sites=(),
        data_windows=((0x5FF6EA, 5), (0x606A5D, 5), (0x60BDA5, 5), (0xA2B480, 8)),
        reuse_navigation=(),
    ), output)
