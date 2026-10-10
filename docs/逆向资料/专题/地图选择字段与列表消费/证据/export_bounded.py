"""第二十三批地图选择字段固定范围；加载不执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='地图选择字段与列表消费',
    seeds=(0x73FC70, 0x6AA840, 0x6AA8C0, 0x6AA940, 0x6AA960, 0x6AA9C0, 0x73F420),
    owner_sites=(0x73F4B9, 0x73F581, 0x73F5AB, 0x73F5D2,
                 0x73F5F9, 0x73F620, 0x75E9C8),
    # pMapList 的当前磁盘窗口含 NUL；文本身份不等于运行时列表结构已恢复。
    data_windows=((0x73FE40, 9),),
    reuse_navigation=(
        '专题/MapView配置记录与预览消费/证据/closure_raw.json',
        '专题/MapView配置记录与预览消费/证据/leaf_raw.json',
        '专题/随机地图候选与配置索引/证据/functions_raw.json',
        '专题/随机地图候选与配置索引/证据/dependencies_raw.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
