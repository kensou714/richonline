"""第二十八批大厅分类与列表有限采证；仅由主代理持IDA租约串行执行。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='大厅分类与索引列表生命周期',
    seeds=(0x69F6D0, 0x6A0B50, 0x6B8980, 0x6B8A00,
           0x6B8A60, 0x69F750, 0x6A0130),
    # 后三项已有原证，只复用并核当前块；新主体只限前四项。
    owner_sites=(0x69F791, 0x69F7A3, 0x69F7B5, 0x69F7C7, 0x69F7D9,
                 0x69FECA, 0x69FF28, 0x69FF3F, 0x69FF56, 0x69FF6D,
                 0x6A027C, 0x6A028E, 0x6A02A0, 0x6A02B2, 0x6A02C4,
                 0x6A08AA, 0x6A0908, 0x6A091F, 0x6A0936, 0x6A094D),
    # 类型文本由69F6D0实际引用提取；没有已核地址时不猜数据窗口。
    data_windows=(),
    reuse_navigation=(
        '专题/大厅区域频道配置/证据/lobby_regions_ida_raw.json',
        '专题/大厅URL读取与缓冲契约/证据/consumers_raw.json',
        '专题/界面系统/ida_ui_chain_raw.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证；进入IDA前拒绝'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
