"""第二十五批股票辅助固定范围；仅主代理串行执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='股票数值辅助与组合消费',
    seeds=(0x6C1C80, 0x6C1D00, 0x6C1D80, 0x6C08B0,
           0x6C0960, 0x6C0BF0, 0x6C0CE0),
    # 大型调用者仅局部参数窗口，不能记为新增完整owner。
    owner_sites=(0x77EF93, 0x77EFD3, 0x77EFE4),
    data_windows=(),
    reuse_navigation=(
        '专题/股票与交易流程/证据/stock_core.json',
        '专题/StockName与StockRace/证据/core_raw.json',
        '专题/StockName与StockRace/证据/function_review.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
