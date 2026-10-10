"""第二十二批三组独立短界面槽；仅固定窗口，不自动扩展回调。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='界面共享槽与通知消费',
    seeds=(0x72E250, 0x72E2D0, 0x72E2F0, 0x7348F0, 0x7349D0, 0x7667A0, 0x766920),
    owner_sites=(0x6E8D60,),
    data_windows=((0xA84FE8, 4), (0xA859C4, 4), (0xA859CC, 4)),
    reuse_navigation=(
        '专题/主界面角色通知/证据/notify_contract.json',
        '专题/启动线程与退出/证据/startup_exit_functions.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
