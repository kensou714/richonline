"""第二十二批固定共享状态读写与单一消费本体；加载不执行。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='A839A0状态读写与消费',
    seeds=(0x6B77B0, 0x6B8320, 0x796DB0, 0x7978B0, 0x798D10,
           0x798D20, 0x798D40, 0x798D60, 0x768080),
    owner_sites=(0x6A12C8, 0x6AC4AC, 0x72CDE0, 0x73BCE2,
                 0x76831B, 0x768322, 0x768329, 0x768350),
    data_windows=((0xA839A0, 4),),
    reuse_navigation=(
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json',
        '专题/TeachMode状态与序号来源/证据/closure_raw.json',
        '专题/TeachBoard记录与消费/证据/helpers_raw.json',
        '专题/TeachBoard记录与消费/证据/reused_raw.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
