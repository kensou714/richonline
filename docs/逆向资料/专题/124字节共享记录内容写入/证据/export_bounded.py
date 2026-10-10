"""第二十四批共享记录内容写入固定范围；加载不访问IDA。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='124字节共享记录内容写入',
    seeds=(0x6A4DC0, 0x6A4E70, 0x6A51A0, 0x6AB280, 0x6A6E00,
           0x6AAD70, 0x6ADEC0, 0x6A54F0),
    owner_sites=(0x64981A, 0x64B6DC),
    data_windows=(),
    reuse_navigation=(
        '专题/登录与大厅状态/证据/ui_wait_transitions.json',
        '专题/大厅玩家记录与装备字段/证据/record_lifecycle.json',
        '专题/角色1416字段来源/证据/functions.json',
        '专题/124字节共享记录与判断门/证据/formal_functions.json',
        '专题/124字节共享记录与判断门/证据/reused_raw.json',
        '专题/124字节共享记录与判断门/证据/source_navigation.json',
    ),
)


def export():
    assert not (HERE/'bounded_raw.json').exists(), '禁止覆盖既有采证，先由主代理核对批次'
    assert hashlib.sha256((ROOT/'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
