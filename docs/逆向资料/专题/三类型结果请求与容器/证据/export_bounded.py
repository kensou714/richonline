"""只准备固定六入口；已有 reader、泵与树容器原证按来源哈希复用。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='三类型结果请求与容器',
    seeds=(0x8BA7B0, 0x8BA8D0, 0x8BBA00, 0x8BBCD0, 0x8BC220, 0x8BC2C0),
    owner_sites=(0x754162, 0x754171, 0x754183, 0x755823, 0x8BB539, 0x8BAC02, 0x8BAD03),
    data_windows=((0xACBD64, 16), (0xACBD70, 16), (0xA3023C, 12), (0xA30248, 12)),
    reuse_navigation=('专题/网络协议/证据/第二批/first_candidates_recheck.json',
                      '专题/整数键树容器契约/证据/entries.json'),
)


def export():
    core = runpy.run_path(str(CORE))
    return core['export'](CONFIG, HERE)
