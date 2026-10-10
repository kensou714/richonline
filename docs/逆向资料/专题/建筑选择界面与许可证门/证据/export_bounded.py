"""第二十七批建筑选择固定范围；加载不访问IDA，仅主代理串行执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='建筑选择界面与许可证门',
    seeds=(0x712980, 0x71F130, 0x71F230, 0x7CEF00, 0x6A3A00),
    # 门的真实上层、控件参数槽生产、提交低字节及六字节调用；owner完整体优先复用。
    owner_sites=(0x7F8625, 0x71EF2D, 0x71EF41, 0x7BC407, 0x7BC432),
    data_windows=(),
    reuse_navigation=(
        '专题/Build配置与建筑资料消费/证据/bounded_raw.json',
        '专题/Build配置与建筑资料消费/证据/reused_audit.json',
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json',
        '专题/主界面角色通知/证据/notify_mapping_audio.json',
        '专题/40D0系列事件/证据/ui_helpers.json',
        '专题/回合等待与自动选择/证据/pending_functions.json',
        '专题/地图选择字段与列表消费/证据/reused_functions.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有采证，先由主代理核对批次'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
