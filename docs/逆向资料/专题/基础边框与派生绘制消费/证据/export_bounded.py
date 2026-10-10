"""第二十五批基础边框与派生绘制消费；加载文件不访问 IDA。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='基础边框与派生绘制消费',
    seeds=(0x8E41D0, 0x90C070, 0x902180, 0x90A430, 0x8E46E0),
    owner_sites=(0x8E4790, 0x90223F, 0x9023CD, 0x90A4F1, 0x90A5BB,
                 0x90A637, 0x90A6A2, 0x909FDD, 0x90C054),
    # 这里只是函数表指针槽；相邻全局不能冒充表内回调槽。
    data_windows=((0xACC3C8, 4),),
    reuse_navigation=('专题/控件回调与事件表/证据/基础消费者.json',),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
