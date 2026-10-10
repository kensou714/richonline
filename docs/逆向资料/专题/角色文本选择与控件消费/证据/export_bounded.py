"""第二十六批角色文本固定范围；加载不访问IDA，由主代理串行执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='角色文本选择与控件消费',
    seeds=(0x6F4DB0, 0x7014A0, 0x756460, 0x762E10),
    # 比较this+50h与局部var_140两种参数来源；只取调用附近窗口。
    owner_sites=(0x748206, 0x75B547),
    data_windows=(),
    reuse_navigation=(
        '专题/业务提示与期限映射/证据/callers.json',
        '专题/业务提示与期限映射/审阅清单.json',
        '专题/业务提示与期限映射/证据/followups.json',
        '专题/角色档案配置与字段消费/证据/bounded_raw.json',
        '专题/角色档案配置与字段消费/函数审阅清单.json',
        '专题/角色与精灵动画/证据/角色精灵_依赖原证.json',
        '专题/角色与精灵动画/函数审阅清单_角色精灵.json',
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有采证，先由主代理核对批次'
    assert hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
