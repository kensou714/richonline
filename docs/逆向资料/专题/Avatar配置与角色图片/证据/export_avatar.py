"""主代理串行执行的Avatar有限只读导出；准备阶段不执行。"""
import importlib.util
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x641650, 0x6416B0, 0x6416E0, 0x641750, 0x642320, 0x6464F0)
CALLSITES = (0x623DD4, 0x642A15, 0x642A54, 0x642A93, 0x642AD2, 0x642B11,
             0x641FFC, 0x642011, 0x642097, 0x6420F2, 0x642167, 0x6421CE, 0x642235)


def context(site, before=12, after=18):
    owner = ida_funcs.get_func(site)
    if not owner:
        return None, []
    heads = sorted({ea for start, end in idautils.Chunks(owner.start_ea)
                    for ea in idautils.Heads(start, end)
                    if ida_bytes.is_code(ida_bytes.get_full_flags(ea))})
    if site not in heads:
        return hex(owner.start_ea), []
    index = heads.index(site)
    rows = []
    for ea in heads[max(0, index - before):index + after + 1]:
        size = idc.get_item_size(ea)
        raw = ida_bytes.get_bytes(ea, size)
        rows.append(dict(va=hex(ea), size=size, hex=raw.hex() if raw else None,
                         text=idc.generate_disasm_line(ea, 0) or ''))
    return hex(owner.start_ea), rows


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('avatar_group', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, SEEDS, HERE / 'avatar_raw.json')
    literals, rejected = [], []
    for seed in SEEDS:
        for start, end in idautils.Chunks(seed):
            for site in idautils.Heads(start, end):
                for target in idautils.DataRefsFrom(site):
                    kind = idc.get_str_type(target)
                    if kind is None or kind < 0:
                        continue
                    size = idc.get_item_size(target)
                    if not 0 < size <= 512:
                        continue
                    content = ida_bytes.get_strlit_contents(target, -1, kind)
                    raw = ida_bytes.get_bytes(target, size)
                    strict = (kind == 0 and idc.get_item_head(target) == target and
                              content is not None and raw == content + b'\0' and
                              content and all(32 <= value <= 126 for value in content))
                    if not strict:
                        rejected.append(dict(owner=hex(seed), site=hex(site), target=hex(target),
                                             string_type=kind, size=size,
                                             reason='未通过精确ASCII C串声明门'))
                        continue
                    literals.append(dict(owner=hex(seed), site=hex(site), target=hex(target),
                                         string_type=kind, size=size, hex=raw.hex(),
                                         content_hex=content.hex(), strict_c_string=True))
    # 格式自动名不能替代原字节；此探针不声称覆盖完整IDA字符串声明。
    probe = ida_bytes.get_bytes(0xA22810, 128)
    assert probe is not None and len(probe) == 128
    first = probe.find(b'\0')
    candidate = probe[:first] if first > 0 else b''
    candidate_valid = bool(candidate) and all(32 <= value <= 126 for value in candidate)
    data = [dict(va='0xa22810', size=128, hex=probe.hex(),
                 scope='128B有界首NUL探针；不是完整IDA声明',
                 first_nul=first, ascii_candidate_hex=candidate.hex() if candidate_valid else None)]
    windows = []
    for site in CALLSITES:
        owner, rows = context(site)
        assert rows, '候选调用点不是已声明指令：' + hex(site)
        windows.append(dict(site=hex(site), owner=owner, context=rows,
                            status='有限生产消费窗口，不等于全调用者审阅'))
    incoming = []
    for seed in (*SEEDS, 0xA766F4):
        pending, seen = [seed], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for xref in idautils.XrefsTo(target, 0):
                owner, rows = context(xref.frm, before=7, after=4)
                incoming.append(dict(seed=hex(seed), target=hex(target), site=hex(xref.frm),
                                     kind=int(xref.type), iscode=bool(xref.iscode), owner=owner,
                                     context=rows, status='引用导航，不计完成覆盖'))
                if owner == hex(xref.frm) and ida_bytes.get_byte(xref.frm) == 0xE9:
                    pending.append(xref.frm)
    result = dict(schema=1, scope='六新主体、直接字串、十三消费窗与引用导航',
                  literals=literals, rejected_literals=rejected, data=data,
                  windows=windows, incoming=incoming,
                  context_disk_status='待离线逐条核验，IDA副本不单独作为磁盘原证')
    (HERE / 'avatar_context.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(group=summary, literals=len(literals), windows=len(windows), incoming=len(incoming))
