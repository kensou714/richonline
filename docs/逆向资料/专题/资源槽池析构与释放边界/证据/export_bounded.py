"""第二十九批槽池释放有限采证；仅root在冻结28后串行执行。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CORE_SHA = '565b9efb2ebc21730bc492fe5ca429885ba675f62b112a2a4dd5703a70654609'
CONFIG = dict(
    topic='资源槽池析构与释放边界',
    seeds=(0x6D7630, 0x62EB20, 0x62EB50),
    owner_sites=(0x6D8105, 0xA12AF3),
    data_windows=(),
    reuse_navigation=(
        '专题/图像资源/证据/20261009_图像加载函数群.json',
        '专题/资源槽池生产与归还/证据/bounded_raw.json',
        '专题/124字节共享数组生命周期/证据/reused_raw.json',
        '专题/4060系列事件/证据/callees.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖已存在原证'
    assert hashlib.sha256(CORE.read_bytes()).hexdigest() == CORE_SHA
    result = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(result, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
