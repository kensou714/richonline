"""由主任务持 IDA 租约补齐 FaceCtrl 释放包装与析构，不自动扩展外部依赖。"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def export(db):
    module = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))
    return module['export_group'](db, [0x629160, 0x64CE70], str(HERE / 'lifecycle_raw.json'))
