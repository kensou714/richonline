"""由主代理串行补采记录默认值、释放责任、类型查询与三项类型表；不扩大角色绘制范围。"""
import importlib.util
import json
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x63FB20, 0x63FB90, 0x629570, 0x7FDB10, 0x646690)


def export(db, context_only=False):
    spec = importlib.util.spec_from_file_location('vehpet_export', HERE / 'export_vehpet.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    helper_spec = importlib.util.spec_from_file_location('vehpet_helper', ROOT / 'docs/逆向资料/全量分析/export_function_group.py')
    helper = importlib.util.module_from_spec(helper_spec)
    helper_spec.loader.exec_module(helper)
    summary = '复用既有supplement_raw，不重新导出主体' if context_only else helper.export_group(db, SEEDS, HERE / 'supplement_raw.json')
    # 两个4B ASCII数据项在IDA非string标记；明确固定宽度与NUL，不据自动名读指针。
    data = []
    for target, size in ((0xA226FC, 4), (0xA22700, 4), (0xA672F8, 12),
                         (0x612155, 5), (0x60CDCC, 5), (0x60212E, 5), (0x60A0D6, 5)):
        raw = ida_bytes.get_bytes(target, size)
        assert raw is not None and len(raw) == size
        data.append(dict(va=hex(target), size=size, hex=raw.hex(),
                         scope='固定数据或E9桥；指令/表/ASCII契约须另核'))
    literals = []
    table = ida_bytes.get_bytes(0xA672F8, 12)
    for index in range(3):
        target = int.from_bytes(table[index * 4:index * 4 + 4], 'little')
        # IDA的item可能合并短字符串与填充；有界读取只保留首个NUL之前的ASCII。
        bounded = ida_bytes.get_bytes(target, 128)
        assert bounded is not None and b'\0' in bounded
        content = bounded.split(b'\0', 1)[0]
        raw, size, kind = content + b'\0', len(content) + 1, 0
        assert content and all(32 <= value <= 126 for value in content)
        literals.append(dict(index=index, target=hex(target), size=size, hex=raw.hex(),
                             string_type=kind, content_hex=content.hex(), strict_c_string=True,
                             boundary_source='128B有界读取首NUL；不依赖IDA item声明',
                             bounded_hex=bounded.hex()))
    incoming = []
    pending, seen = [0x7FDB10, 0x646690], set()
    while pending:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        for xref in idautils.XrefsTo(target, 0):
            owner, rows = module.context(xref.frm, before=10, after=10)
            incoming.append(dict(target=hex(target), site=hex(xref.frm), kind=int(xref.type),
                                 owner=owner, context=rows, status='调用导航，仅局部窗口'))
            if owner == hex(xref.frm) and ida_bytes.get_byte(xref.frm) == 0xE9:
                pending.append(xref.frm)
    result = dict(schema=1, data=data, literals=literals, incoming=incoming,
                  scope='五依赖全本体、12B表、两个4B ASCII项、三C串、类型与smoke查询有限引用窗口')
    (HERE / 'supplement_context.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(group=summary, data=len(data), literals=len(literals), incoming=len(incoming))
