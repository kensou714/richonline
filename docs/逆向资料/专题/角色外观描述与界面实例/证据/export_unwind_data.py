"""外观实例和工厂的异常元数据有限补证；保留原始状态表，不推断实机异常。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'unwind_data'
    output.mkdir(exist_ok=True)
    assert not (output / 'bounded_raw.json').exists(), '禁止覆盖历史补证'
    return runpy.run_path(str(CORE))['export'](dict(
        topic='角色外观描述与界面实例：异常状态表和动作桥',
        seeds=(), owner_sites=(),
        data_windows=((0xA58B60, 32), (0xA58B50, 16),
                      (0xA57FCC, 32), (0xA57FC4, 8),
                      (0x605590, 5), (0x60002C, 5), (0x60657B, 5)),
        reuse_navigation=(),
    ), output)
