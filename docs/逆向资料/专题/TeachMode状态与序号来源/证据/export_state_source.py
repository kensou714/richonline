"""只读闭合本地数据选择器 case47 的对象、账户与字符串访问器。"""
import importlib.util
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('teachmode_state_source_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_group(db, (0x8976E0, 0x82AB80, 0x82A900, 0x82BC80),
                               HERE / 'state_source_raw.json')
