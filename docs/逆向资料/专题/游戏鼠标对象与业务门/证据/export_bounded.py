"""第二十二批固定鼠标对象与三条业务路径；加载不执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='游戏鼠标对象与业务门',
    seeds=(0x6BAAC0, 0x6516E0, 0x651960, 0x653850, 0x6278F0, 0x6BAD80, 0x691CC0),
    owner_sites=(0x627949, 0x80328E, 0x8032CE, 0x80356E),
    data_windows=((0xA766C0, 4),),
    reuse_navigation=(
        '专题/输入与快捷键/ida_input_raw.json',
        '专题/40B0系列事件/证据/request_helpers.json',
        '专题/道具与卡片操作/ida_cards_raw.json',
        '专题/启动线程与退出/证据/startup_exit_functions.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
