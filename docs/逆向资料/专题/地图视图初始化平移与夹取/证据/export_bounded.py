"""第二十四批地图视图固定范围；加载不访问IDA或执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='地图视图初始化平移与夹取',
    seeds=(0x7B6C90, 0x7B6EF0, 0x638150, 0x650C10,
           0x7B6D50, 0x7B6F60, 0x7E1600),
    # 有限参数窗口；完整64F2A0旧原证作为来源，不能把窗口计成完整caller。
    owner_sites=(0x64F50A, 0x64F519, 0x64F532, 0x64F54C),
    data_windows=(),
    reuse_navigation=(
        '专题/断线与离席恢复/ida_disconnect_fields.json',
        '专题/断线与离席恢复/ida_disconnect_dependencies.json',
        '专题/TeachMode序号生产与根对象/证据/load_source_raw.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
