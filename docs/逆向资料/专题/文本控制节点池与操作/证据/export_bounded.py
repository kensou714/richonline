"""只准备固定七入口；依赖共用器只读，不执行测宽或控件回调。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='文本控制节点池与操作',
    seeds=(0x6E52D0, 0x6FABE0, 0x6FACF0, 0x6FAD40, 0x8E02F0, 0x8EAA30, 0x8EAAF0),
    owner_sites=(0x8E16CF, 0x8E447D, 0x8FF4AC, 0x8FF5C3, 0x8FF83E, 0x8EA34E),
    data_windows=((0xACC3C4, 4),),
    reuse_navigation=('专题/列表控件行记录与布局/证据/list_functions.json',
                      '专题/提示文本生命周期/证据/lifecycle.json'),
)


def export():
    core = runpy.run_path(str(CORE))
    return core['export'](CONFIG, HERE)
