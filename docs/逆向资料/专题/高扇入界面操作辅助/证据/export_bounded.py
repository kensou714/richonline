"""只准备固定四短函数与有限上层窗口；不完整导出巨大窗口owner。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='高扇入界面操作辅助',
    seeds=(0x6E3A30, 0x71AA20, 0x71AAC0, 0x747C70),
    owner_sites=(0x75E882, 0x75EF1D, 0x748E87, 0x719DC4, 0x719F1C,
                 0x71A0B8, 0x71A763, 0x74599F, 0x7461E8, 0x74730A),
    data_windows=((0xA314F8, 4), (0xA3063C, 4), (0xA2A89C, 3)),
    reuse_navigation=('专题/界面系统/ida_ui_chain_raw.json',
                      '专题/输入与快捷键/ida_input_raw.json'),
)


def export():
    core = runpy.run_path(str(CORE))
    return core['export'](CONFIG, HERE)
