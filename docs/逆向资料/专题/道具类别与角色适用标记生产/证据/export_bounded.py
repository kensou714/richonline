"""第二十七批固定四主体及类别表；加载不访问IDA，由主代理串行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CORE = HERE.parents[1]/'四类型辅助请求与队列/证据/export_preparation_core.py'
# 离线PE只用于固定采证边界；须由IDA原证和当前磁盘重新确认指针与NUL。
PART_STRINGS = (
    (0xA2DE90,4), (0xA2DE88,8), (0xA2DE80,5), (0xA2DE78,5),
    (0xA2DE70,5), (0xA2DE68,5), (0xA2DE60,5), (0xA2DE58,5),
    (0xA2DE50,6), (0xA2DE48,6), (0xA2DE40,5), (0xA2DE38,7),
    (0xA2DE30,7), (0xA2DE28,7), (0xA2DE1C,11), (0xA2DE10,12),
    (0xA2DE08,7), (0xA2DE00,7), (0xA2DDF8,7), (0xA2DDF0,7),
    (0xA2DDE8,7), (0xA2DDE0,7), (0xA2DDD8,7), (0xA2DDD0,7),
    (0xA2DDC8,7), (0xA2DDC0,7), (0xA2DDB8,7), (0xA2DDB0,7),
    (0xA2DDA8,7), (0xA2DDA0,7), (0xA2DD98,8),
)
CONFIG = dict(
    topic='道具类别与角色适用标记生产',
    seeds=(0x7FE7D0,0x7FE9E0,0x7FF1D0,0x7FF240),
    owner_sites=(0x623D41,),
    data_windows=((0xA675C0,124),)+PART_STRINGS,
    reuse_navigation=(
        '专题/NewProps与CombCard配置/证据/reused_raw.json',
        '专题/NewProps与CombCard配置/函数审阅清单.json',
        '专题/角色文本选择与控件消费/证据/formal_functions.json',
        '专题/角色文本选择与控件消费/函数审阅清单.json',
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json',
        '专题/Avatar配置与角色图片/证据/supplement_raw.json',
    ),
)


def export():
    assert not (HERE/'bounded_raw.json').exists(), '禁止覆盖已有采证'
    assert hashlib.sha256((ROOT/'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    report = runpy.run_path(str(CORE))['export'](CONFIG,HERE)
    return dict(report,prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
