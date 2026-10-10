"""只读补证称号容器短依赖与退出清理；由主代理串行运行。"""
import hashlib
import importlib.util
import json
from pathlib import Path

import ida_bytes

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
FUNCTIONS = (0x79A510, 0x79ADE0, 0x79AE10, 0x79B080, 0x79C5A0,
             0x79C610, 0x79CD60, 0xA1FF90, 0x819A20)


def export(db):
    path = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('rank_supplement_export', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, FUNCTIONS, HERE / 'rank_supplement_raw.json')
    # off 自动名不证明指针槽；本次另存直接 push 的四字节实参来源。
    data = dict(num_va='0xa2a9d8', num_idb_hex=ida_bytes.get_bytes(0xA2A9D8, 4).hex(),
                consumer_site='0x755b92',
                consumer_idb_hex=ida_bytes.get_bytes(0x755B92, 5).hex())
    paths = ('专题/文本段键解析与预处理/证据/functions_raw.json',
             '专题/文本段键解析与预处理/证据/bridges_constants_raw.json',
             '专题/文本与容器/证据/parser_kpd_functions.json',
             '专题/股票与交易流程/证据/stock_core.json')
    data['reused_sources'] = [dict(path='docs/逆向资料/' + p,
                                  sha256=hashlib.sha256((ROOT / 'docs/逆向资料' / p).read_bytes()).hexdigest())
                              for p in paths]
    (HERE / 'rank_reuse_and_num_raw.json').write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return summary
