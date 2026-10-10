"""第二十六批地图地产候选筛选；加载不访问IDA，执行由主代理串行安排。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='地图地产候选筛选',
    seeds=(0x7E4660, 0x7E4750, 0x7E4830, 0x7E4930, 0x7E4A30),
    owner_sites=(0x7C8FCB, 0x7C9049, 0x7CA931, 0x7CA96C, 0x7CA9A7),
    data_windows=(),
    reuse_navigation=(
        '专题/回合等待与自动选择/证据/pending_functions.json',
        '专题/随机数状态与取样边界/证据/functions_raw.json',
        '专题/本地事件剩余消费者/证据/property_fields.json',
        '专题/40EE系列事件/证据/direct_helpers.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
