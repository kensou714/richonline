"""只读导出状态串最终 getter 和管理单例的构造/退出调用。"""
import importlib.util
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_state_lifecycle_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_group(db, (0x62B8E0, 0x897440, 0xA205F0),
                               HERE / 'state_lifecycle_raw.json')
