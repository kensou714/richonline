"""第二十八批槽池生产归还有界采证；仅主代理串行执行export。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='资源槽池生产与归还',
    seeds=(0x6D75A0, 0x62EAE0, 0x6DFC30, 0x6DFD50, 0x6D7690, 0x6DBDF0,
           0x6DFCA0, 0x6D7660, 0x6DFD10),
    # 最后三项复用旧主体，仅补当前声明块；不计新导出。
    owner_sites=(0x6D7D29, 0x6D7E5D, 0x7DEA86, 0x75C5DC, 0x75C601, 0x798824),
    data_windows=(),
    reuse_navigation=(
        '专题/图像资源/证据/20261009_图像加载函数群.json',
        '专题/角色与精灵动画/证据/动画管理与骰子_IDA原始导出.json',
        '专题/地图与路径/证据/map_runtime_core.json',
        '专题/4019系列事件/证据/resource_loader_scope.json',
        '专题/资源配置分组记录生产/证据/bounded_raw.json',
        '专题/资源配置分组记录生产/证据/reused_functions.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证；进入IDA前拒绝'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
