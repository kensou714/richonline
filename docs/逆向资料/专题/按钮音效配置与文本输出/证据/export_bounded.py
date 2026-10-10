"""第二十三批按钮配置与文本输出候选；加载不执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='按钮音效配置与文本输出',
    seeds=(0x90B6E0, 0x90D890, 0x90B9C0, 0x90BA00, 0x90BAD0, 0x90BF60, 0x90B500),
    owner_sites=(0x90B489, 0x8F7A8C, 0x90B10E, 0x90B117),
    # 各键按当前磁盘的独立 NUL 字符串定长，不扩大成整个只读数据区。
    data_windows=((0xA67A1C, 7), (0xA6877C, 10), (0xA68770, 8), (0xA68764, 9),
                  (0xA68FD8, 12), (0xA68FC8, 12), (0xA68FBC, 9), (0xA67A8C, 6)),
    reuse_navigation=(
        '专题/界面系统/第二批/ida_ui_batch2_raw.json',
        '专题/十六进制文本格式化/证据/hex_raw.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
