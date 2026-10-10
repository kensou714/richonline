"""第二十五批名称查找与等待消费者固定范围；加载不访问IDA。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='名称查找与等待消费者',
    seeds=(0x6B20A0, 0x6B81D0, 0x6AD9F0, 0x73D560, 0x6AEBE0),
    owner_sites=(0x6AAF7D, 0x6AB20C),
    data_windows=(),
    reuse_navigation=(
        '专题/邮件与礼物分组/证据/functions.json',
        '专题/邮件与礼物分组/函数审阅清单.json',
        '专题/四类型辅助请求与队列/证据/reused_network.json',
        '专题/大厅玩家记录与装备字段/证据/record_lifecycle.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有采证，先由主代理核对批次'
    assert hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
