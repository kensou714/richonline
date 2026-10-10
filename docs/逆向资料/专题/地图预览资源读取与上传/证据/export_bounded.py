"""第二十九批地图预览上传有限采证；仅root持IDA租约执行。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='地图预览资源读取与上传',
    # 只有首项是新主体；其余用于旧调用/锁/图像创建契约的当前块复核。
    seeds=(0x6DB5E0, 0x7E6F10, 0x6BFA00, 0x6BFA40, 0x811BA0),
    owner_sites=(0x7E6F64, 0x7E6F87, 0x7E6F95, 0x7E6FAC, 0x7E6FCC,
                 0x7E6FE3, 0x7E6FF8, 0x7E701E, 0x7E703F, 0x7E705A,
                 0x7E7076, 0x7E708D),
    data_windows=(),
    reuse_navigation=(
        '专题/录像文件与执行链/证据/io_and_parser_navigation.json',
        '专题/文本与容器/证据/config_map_consumers.json',
        '专题/图像资源/证据/20261009_图像加载函数群.json',
        '专题/地图与路径/证据/map_runtime_core.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
