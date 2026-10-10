"""名称查找的两项容器访问补证；主代理串行执行，保持既有原证不变。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='名称查找与等待消费者：两个容器访问契约',
    seeds=(0x85B800, 0x85B870),
    owner_sites=(),
    data_windows=(),
    reuse_navigation=(),
)


def export():
    destination = HERE / 'container_dependency'
    assert not (destination / 'bounded_raw.json').exists(), '禁止覆盖已有容器补证'
    destination.mkdir(exist_ok=True)
    result = runpy.run_path(str(CORE))['export'](CONFIG, destination)
    return dict(result, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
