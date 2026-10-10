"""地图候选分派表、文件模式与RTC容量元数据；仅主代理串行采证。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'boundary_data'
    output.mkdir(exist_ok=True)
    assert not (output / 'bounded_raw.json').exists(), '禁止覆盖历史补证'
    return runpy.run_path(str(CORE))['export'](dict(
        topic='共享记录地图候选回调：跳表与路径RTC边界',
        seeds=(), owner_sites=(),
        data_windows=(
            (0x6AAB34, 16), (0xA2D950, 7), (0xA2D970, 3),
            (0x7E727A, 8), (0x7E7282, 12), (0x7E728E, 14),
        ),
        reuse_navigation=(),
    ), output)
