"""三个回调指针槽的有限补证；不推断完整事件表或运行时注册。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'callback_slots'
    output.mkdir(exist_ok=True)
    assert not (output / 'bounded_raw.json').exists(), '禁止覆盖历史补证'
    return runpy.run_path(str(CORE))['export'](dict(
        topic='建筑选择界面与许可证门：三个代码指针槽',
        seeds=(), owner_sites=(),
        data_windows=((0xA24CF4, 4), (0xA263B4, 4), (0xA263C8, 4)),
        reuse_navigation=(),
    ), output)
