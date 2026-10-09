"""在现有 IDA 数据库只读重建字符串专题原证，不创建函数或修改类型。"""
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    groups = {
        'string_seeds': [f.start_ea for f in db.functions.get_between(0x62B620, 0x62BE40)],
        'string_dependencies': [0x62BE70, 0x62BE90, 0x62BF70, 0x62BFC0, 0x62CA90,
                                0x91BE10, 0x91F6D0, 0x91FB00, 0x91FC60],
        'string_growth': [0x62C850, 0x62C8C0, 0x91BDA0],
        'string_limit': [0x62DD00],
        'string_allocation': [0x62DCC0, 0x91BD30],
        'string_consumers': [0x62E920, 0x79D3D0, 0x88EE20, 0x691AB0],
    }
    results = {}
    for name, addresses in groups.items():
        results[name] = export(db, addresses, HERE / '证据' / (name + '.json'))
    return results

