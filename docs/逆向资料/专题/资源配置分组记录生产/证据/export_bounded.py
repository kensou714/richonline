"""第二十七批分组记录生产有限采证；仅主代理串行执行。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='资源配置分组记录生产',
    seeds=(0x6DFA10, 0x6D76C0, 0x6D7C00, 0x6D7C30, 0x6D7660, 0x6DFD10),
    # 后两项只复用旧汇编并取得当前块字节，不能算新导出主体。
    owner_sites=(0x6D7DF2, 0x6D803F, 0x6DA25F, 0x6DA2C8,
                 0x6DA316, 0x6DA394, 0x6DA3F9, 0x6DA457),
    # 当前磁盘push目标与首NUL长度已离线确认；采后仍按首NUL重核，非IDA字符串声明认领。
    data_windows=((0xA23EF4, 9), (0xA23F00, 10), (0xA23F0C, 5)),
    reuse_navigation=(
        '专题/4019系列事件/证据/resource_loader_scope.json',
        '专题/4019系列事件/证据/tail_chunk_reexport.json',
        '专题/图像资源/证据/20261009_图像加载函数群.json',
        '专题/124字节共享数组生命周期/证据/reused_raw.json',
        '专题/SysRes鼠标资源加载/证据/bounded_raw.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证；在进入IDA前拒绝'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
