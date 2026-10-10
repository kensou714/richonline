"""只读导出 FaceCtrl 种子、局部依赖和引用；由主任务持租约执行。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_nalt
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs' / '逆向资料'
HERE = Path(__file__).resolve().parent
SEEDS = (0x64CE50, 0x64CEC0, 0x64D180)
LOCAL_CANDIDATES = {0x64CE70, 0x64D2E0}
GLOBAL = 0xA7673C
REUSE = (
    ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', (0x628FB0, 0x623EE0)),
    ('专题/文本过滤与字码转换/证据/caller_functions.json', (0x64A9F0,)),
)


def export(db):
    """一次执行，保留候选而不自动展开庞大的调用者函数。"""
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    bridges = {}

    def disk(ea, size):
        matches = [(rva, raw_at) for _, rva, raw_size, raw_at in sections
                   if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(matches) <= 1, hex(ea)
        if not matches:
            return None
        rva, raw_at = matches[0]
        offset = raw_at + ea - base - rva
        return image[offset:offset + size]

    def identity(ea, size):
        data = ida_bytes.get_bytes(ea, size)
        original = disk(ea, size)
        assert data is not None, hex(ea)
        if original is not None:
            assert data == original, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    idb_hex=data.hex(), disk_hex=original.hex() if original is not None else None,
                    matching=data == original if original is not None else None,
                    disk_backed=original is not None, sha256=hashlib.sha256(data).hexdigest())

    def resolve(ea):
        chain = []
        while ea not in chain and len(chain) < 16:
            raw = ida_bytes.get_bytes(ea, 5)
            if raw is None or raw[0] != 0xE9:
                break
            chain.append(ea)
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            bridges[hex(ea)] = dict(identity(ea, 5), target=hex(target))
            ea = target
        return ea, chain

    def incoming(ea):
        pending, visited, rows = [ea], set(), []
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            for x in idautils.XrefsTo(target, 0):
                owner = ida_funcs.get_func(x.frm)
                rows.append(dict(site=hex(x.frm), target=hex(target), kind=int(x.type),
                                 iscode=bool(x.iscode), owner=hex(owner.start_ea) if owner else None,
                                 text=idc.generate_disasm_line(x.frm, 0) or ''))
                if x.iscode:
                    impl, chain = resolve(x.frm)
                    if chain and impl == target:
                        pending.append(x.frm)
        return rows

    reused, source_rows = [], []
    coverage = json.loads((DOCS / '全量分析/evidence_coverage.json').read_text(encoding='utf-8'))
    covered = {int(r['va'], 16): r['evidence'] for r in coverage['functions']}
    for relative, addresses in REUSE:
        path = DOCS / relative
        raw = path.read_bytes()
        records = json.loads(raw.decode('utf-8'))['functions']
        lookup = {int(row['va'], 16): row for row in records}
        for ea in addresses:
            assert ea in lookup, (relative, hex(ea))
            reused.append(dict(va=hex(ea), source=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                               record=lookup[ea]))
        source_rows.append(dict(path=relative, sha256=hashlib.sha256(raw).hexdigest()))

    fresh = {ea for ea in SEEDS if ea not in covered}
    external, data_refs, strings, rejected_strings = [], [], {}, {}
    # 只纳入真实直接调用的两个局部候选；外部依赖先留作下一轮筛选。
    for ea in SEEDS:
        function = ida_funcs.get_func(ea)
        assert function and function.start_ea == ea, hex(ea)
        for start, end in idautils.Chunks(ea):
            for head in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                    continue
                for x in idautils.XrefsFrom(head, 0):
                    if x.iscode and int(x.type) in (16, 17):
                        target, chain = resolve(x.to)
                        target_function = ida_funcs.get_func(target)
                        declared = bool(target_function and target_function.start_ea == target)
                        if target in LOCAL_CANDIDATES and declared and target not in covered:
                            fresh.add(target)
                        external.append(dict(owner=hex(ea), site=hex(head), target=hex(x.to),
                                             implementation=hex(target), chain=[hex(t) for t in chain],
                                             declared_function=declared,
                                             reuse_sources=covered.get(target, [])))
                    elif not x.iscode:
                        data_refs.append(dict(owner=hex(ea), site=hex(head), target=hex(x.to),
                                              kind=int(x.type), text=idc.generate_disasm_line(head, 0) or ''))
                        value = idc.get_strlit_contents(x.to, -1, idc.STRTYPE_C)
                        if value is not None:
                            row = dict(identity(x.to, len(value) + 1), value_hex=value.hex())
                            # IDA 可把非字符串数据返回为候选，必须核实实际终止字节。
                            if bytes.fromhex(row['idb_hex']) == value + b'\0':
                                strings[hex(x.to)] = row
                            else:
                                rejected_strings[hex(x.to)] = dict(row, reason='候选后续字节不是NUL，不能作为C字符串')

    shared = runpy.run_path(str(DOCS / '全量分析/export_function_group.py'))
    summary = shared['export_group'](db, sorted(fresh), str(HERE / 'facectrl_raw.json'))
    assert not summary['function_mismatches'] and not summary['thunk_mismatches'], summary
    context = dict(schema=1, scope='只读引用与复用档案；候选不是已审阅函数',
                   disk_sha256=hashlib.sha256(image).hexdigest(),
                   idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                   seeds=[hex(ea) for ea in SEEDS], fresh=[hex(ea) for ea in sorted(fresh)],
                   covered_seeds=[dict(va=hex(ea), sources=covered[ea]) for ea in SEEDS if ea in covered],
                   incoming={hex(ea): incoming(ea) for ea in (*SEEDS, 0x628FB0)},
                   singleton=dict(identity(GLOBAL, 4), incoming=incoming(GLOBAL)),
                   calls=external, data_references=data_refs, strings=list(strings.values()),
                   rejected_string_candidates=list(rejected_strings.values()),
                   reused_functions=reused, reuse_sources=source_rows)
    # incoming 的反向遍历也会发现跳板，必须在遍历结束后保存。
    context['bridges'] = list(bridges.values())
    (HERE / 'facectrl_context.json').write_text(json.dumps(context, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(summary, context=str(HERE / 'facectrl_context.json'),
                bridges=len(bridges), reused=len(reused), data_references=len(data_refs))
