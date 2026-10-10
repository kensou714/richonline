"""只读补证G单例、G内地图加载与EMP头字段写入，不重审完整EMP载荷。"""
import importlib.util
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x629C90, 0x64F2A0, 0x7DF010)


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_load_source_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_group(db, SEEDS, HERE / 'load_source_raw.json')
