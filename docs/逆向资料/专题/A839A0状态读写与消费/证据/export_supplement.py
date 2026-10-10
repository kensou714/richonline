"""只读补录 case60 局部、四路跳表与静态函数指针；不扩大 owner 语义范围。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'


def export():
    output = HERE / 'navigation_supplement'
    output.mkdir(exist_ok=True)
    config = dict(topic='A839A0有限补证', seeds=(),
                  owner_sites=(0x82A1F2, 0x82A209),
                  data_windows=((0x768455, 16), (0xA29C98, 32)),
                  reuse_navigation=())
    return runpy.run_path(str(CORE))['export'](config, output)
