"""第二十三批共享记录判断门固定范围；加载不执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='124字节共享记录与判断门',
    seeds=(0x6B7D60, 0x6B7DC0, 0x6B7DF0, 0x6B7E70, 0x6B7F10,
           0x6B7F90, 0x734460, 0x6A5960, 0x6B7CE0),
    # 消费者本体已列种子；不重复添加内部窗口，不预设堆数组的运行时地址。
    owner_sites=(),
    data_windows=(),
    reuse_navigation=(
        '专题/游戏分派桥接/证据/property_and_6021_handlers.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
