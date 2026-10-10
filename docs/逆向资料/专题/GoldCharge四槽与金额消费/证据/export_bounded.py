"""第二十二批固定四槽金额消费及提交短链；加载不执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='GoldCharge四槽与金额消费',
    seeds=(0x709E50, 0x70A7E0, 0x70ABA0, 0x70B050, 0x727CC0),
    owner_sites=(0x70AC94, 0x70AD08, 0x70AD7C, 0x70B070),
    data_windows=((0xA87480, 4), (0xA87484, 4), (0xA87488, 4), (0xA8748C, 4)),
    reuse_navigation=(
        '专题/文本与容器/证据/config_map_consumers.json',
        '专题/主界面角色通知/证据/notify_contract.json',
        '专题/商店与购买流程/证据/shop_helpers.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
