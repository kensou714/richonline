"""只读导出已经出现的叶层依赖；不按邻接函数扩围。"""
import importlib.util
from pathlib import Path

import ida_bytes

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
FUNCTIONS = (0x79C5E0, 0x79C660, 0x79C920, 0x79C950, 0x79D730, 0x79D790,
             0x79B520, 0x79B600, 0x79B640, 0x79CF40, 0x79CF90, 0x79CFD0)


def export(db):
    raw = ida_bytes.get_bytes(0x60D178, 5)
    if raw[0] != 0xE9:
        raise ValueError('析构回调桥不是预期E9')
    destructor = 0x60D178 + 5 + int.from_bytes(raw[1:], 'little', signed=True)
    path = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('rank_leaves_export', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_group(db, FUNCTIONS + (destructor,), HERE / 'rank_leaves_raw.json')
