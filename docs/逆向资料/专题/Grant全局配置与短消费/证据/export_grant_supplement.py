"""只导出缺失构造辅助；复用原主体，仅核旧游标声明边界与四字节键。"""
import hashlib
import importlib.util
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
REUSED = ('docs/逆向资料/专题/大厅URL读取与缓冲契约/证据/functions_raw.json',
          'docs/逆向资料/专题/文本与容器/证据/parser_kpd_functions.json')


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('grant_supplement', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, (0x7D9C30,), HERE / 'grant_supplement_raw.json')
    rows = []
    for ea in (0x8198E0, 0x81A090):
        function = ida_funcs.get_func(ea)
        rows.append(dict(va=hex(ea), declared_start=hex(function.start_ea) if function else None,
                         declared_end=hex(function.end_ea) if function else None,
                         declared_chunks=[dict(start_va=hex(start), end_va=hex(end))
                                          for start, end in idautils.Chunks(ea)],
                         boundary='仅核当前声明；主体字节复用原来源并离线重新解码核磁盘'))
    raw = ida_bytes.get_bytes(0xA2D500, 4)
    output = dict(reused_declarations=rows,
                  key_literal=dict(va='0xa2d500', requested_size=4,
                                   idb_hex=raw.hex() if raw is not None else None,
                                   boundary='限定四字节原证；人工核num加00，不依赖IDA字符串自动类型'),
                  reused_sources=[dict(path=p, sha256=hashlib.sha256((ROOT / p).read_bytes()).hexdigest())
                                  for p in REUSED])
    (HERE / 'grant_reuse_declarations_raw.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(core=summary, reused_declarations=len(rows), key_bytes=len(raw) if raw else 0)
