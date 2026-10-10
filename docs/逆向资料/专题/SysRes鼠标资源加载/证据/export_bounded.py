"""第二十六批SysRes鼠标资源固定范围；仅主代理串行执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='SysRes鼠标资源加载',
    seeds=(0x6BAB70, 0x6DB9D0),
    # 启动函数仅取加载调用及返回检查窗口，不登记整个owner已审。
    owner_sites=(0x623CED,),
    # 字符串由core按IDA声明和首NUL严格采集；不把IAT值放入相等数据窗。
    data_windows=(),
    reuse_navigation=(
        '专题/股票与交易流程/证据/stock_core.json',
        '专题/游戏鼠标对象与业务门/证据/bounded_raw.json',
        '专题/游戏鼠标对象与业务门/证据/formal_functions.json',
        '专题/游戏鼠标对象与业务门/证据/reused_audit.json',
        '专题/游戏鼠标对象与业务门/证据/destructor_raw.json',
        '专题/游戏鼠标对象与业务门/证据/exit_dependency_raw.json',
        '专题/游戏鼠标对象与业务门/证据/exit_owner_context.json',
        '专题/40B0系列事件/证据/request_helpers.json',
        '专题/40EE系列事件/证据/direct_helpers.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
