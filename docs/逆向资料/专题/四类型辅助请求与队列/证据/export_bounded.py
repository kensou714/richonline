"""只准备固定六入口；加载不执行采证，不自动扩展容器依赖。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = dict(
    topic='四类型辅助请求与队列',
    seeds=(0x859A80, 0x85A1E0, 0x85A4E0, 0x85A7A0, 0x85AA60, 0x85AD70),
    owner_sites=(0x6AB68D, 0x6AB6A4, 0x7644BE, 0x6AD5B3, 0x764BC2, 0x7501B5),
    data_windows=((0xACB8F8, 16), (0xACB8E8, 16), (0xA2F7D0, 16)),
    reuse_navigation=('专题/网络协议/证据/第二批/first_candidates_recheck.json',),
)


def export():
    core = runpy.run_path(str(HERE / 'export_preparation_core.py'))
    return core['export'](CONFIG, HERE)
