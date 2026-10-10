"""只读导出返回字符串的叶访问器和管理单例退出本体。"""
import importlib.util
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_state_leaf_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_group(db, (0x62BB80, 0x8974F0), HERE / 'state_leaf_raw.json')
