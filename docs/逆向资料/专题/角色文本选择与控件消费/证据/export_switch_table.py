"""角色图像编号选择依赖的分派表补证；只读固定12项，不覆盖原证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='角色文本选择候选纠偏：图像编号分派表',
    seeds=(), owner_sites=(),
    data_windows=((0x6DBDB4, 48),),
    reuse_navigation=('专题/业务提示与期限映射/证据/followups.json',),
)


def export():
    destination = HERE / 'switch_table'
    assert not (destination / 'bounded_raw.json').exists(), '禁止覆盖已有分派表'
    destination.mkdir(exist_ok=True)
    result = runpy.run_path(str(CORE))['export'](CONFIG, destination)
    return dict(result, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
