"""第二十一批有限采证共用器；加载文件不访问 IDA，执行须由主代理串行安排。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs/逆向资料'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def export(config, output_dir):
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import idautils
    import idc

    output_dir = Path(output_dir)
    assert output_dir.is_dir()
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    assert image[:2] == b'MZ'
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    coverage_bytes = (DOCS / '全量分析/evidence_coverage.json').read_bytes()
    covered = {int(row['va'], 16): row['evidence'] for row in
               json.loads(coverage_bytes)['functions']}
    bridges, strings, rejected, sources = {}, {}, {}, {}

    def identity(ea, size, require_disk=True):
        assert 0 < size <= 1048576, (hex(ea), size)
        raw = ida_bytes.get_bytes(ea, size)
        matches = [(rva, off) for _, rva, length, off in sections
                   if 0 <= ea - base - rva and ea - base - rva + size <= length]
        assert len(matches) <= 1, ('非唯一磁盘支持范围', hex(ea), size)
        if not matches:
            assert not require_disk, ('函数/字符串无磁盘支持', hex(ea), size)
            virtual = [(rva, length) for length, rva, _, _ in sections
                       if 0 <= ea - base - rva and ea - base - rva + size <= length]
            assert len(virtual) == 1, ('非唯一虚拟节范围', hex(ea), size)
            assert raw is None or len(raw) == size, hex(ea)
            return dict(start_va=hex(ea), size=size, idb_hex=raw.hex() if raw is not None else None,
                        disk_hex=None, matching=None,
                        sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None,
                        pending_status='仅IDA虚拟零填充区快照；不是运行时内存或磁盘字节')
        assert raw is not None and len(raw) == size, hex(ea)
        rva, off = matches[0]
        at = off + ea - base - rva
        disk = image[at:at + size]
        assert len(disk) == size and disk == raw, ('磁盘/IDB字节不同', hex(ea))
        return dict(start_va=hex(ea), size=size, idb_hex=raw.hex(), disk_hex=disk.hex(),
                    matching=True, sha256=hashlib.sha256(raw).hexdigest())

    def source_ref(relative):
        if relative not in sources:
            path = DOCS / relative
            assert path.resolve().is_relative_to(DOCS.resolve()), relative
            raw = path.read_bytes()
            data = json.loads(raw)
            baseline = (data.get('disk_sha256', data.get('idb_input_sha256', data.get('sha256')))
                        if isinstance(data, dict) else None)
            sources[relative] = dict(path=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                                     declared_binary_sha256=baseline,
                                     current_baseline_declared=bool(baseline and baseline.lower() == EXPECTED_SHA),
                                     pending_status='仅复用来源；语义和版本有效性仍须按记录复核')
        return sources[relative]

    def resolve(ea):
        seen = []
        while True:
            assert ea not in seen, ('桥循环', [hex(x) for x in seen])
            raw = ida_bytes.get_bytes(ea, 5)
            if raw is None or len(raw) != 5 or raw[0] != 0xE9:
                return ea, seen
            assert len(seen) < 16, '直接桥链超过有限上限'
            owner = ida_funcs.get_func(ea)
            if owner is None or owner.start_ea != ea:
                return ea, seen
            chunks = list(idautils.Chunks(ea))
            if len(chunks) != 1 or chunks[0] != (ea, ea + 5):
                return ea, seen
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            bridges[hex(ea)] = dict(identity(ea, 5), target_va=hex(target),
                                   pending_status='已核直接E9桥；不代表业务已审阅')
            seen.append(ea)
            ea = target

    def line(ea):
        return idc.generate_disasm_line(ea, 0) or ''

    def owner_window(site):
        owner = ida_funcs.get_func(site)
        if owner is None:
            return dict(owner_va=None, site_va=hex(site), assembly=[], pending_status='无函数归属')
        chunks = [(a, b) for a, b in idautils.Chunks(owner.start_ea) if a <= site < b]
        assert len(chunks) == 1, hex(site)
        start, end = chunks[0]
        heads = list(idautils.Heads(max(start, site - 64), min(end, site + 64)))
        assert site in heads, ('xref不是已声明指令头', hex(site))
        index = heads.index(site)
        selected = heads[max(0, index - 5):index + 6]
        rows = []
        for ea in selected:
            next_ea = min(ida_bytes.get_item_end(ea), end)
            rows.append(dict(site_va=hex(ea), text=line(ea), bytes=identity(ea, next_ea - ea)))
        return dict(owner_va=hex(owner.start_ea), site_va=hex(site), assembly=rows,
                    pending_status='有限调用窗口；不计作owner完整审阅')

    def incoming(ea):
        pending, visited, rows = [ea], set(), []
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            for xref in idautils.XrefsTo(target, 0):
                assert len(rows) < 256, ('入边超过有限上限', hex(ea))
                endpoint, chain = resolve(xref.frm) if xref.iscode else (xref.frm, [])
                row = dict(site_va=hex(xref.frm), target_va=hex(target), kind=int(xref.type),
                           is_code=bool(xref.iscode), text=line(xref.frm),
                           verified_bridge=bool(chain and bridges[hex(xref.frm)]['target_va'] == hex(target)),
                           final_implementation_va=hex(endpoint) if chain else None)
                if int(xref.type) in (16, 17):
                    row['owner_window'] = owner_window(xref.frm)
                rows.append(row)
                if row['verified_bridge']:
                    pending.append(xref.frm)
        return rows

    def string_candidate(ea):
        if hex(ea) in strings or hex(ea) in rejected:
            return
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_strlit(flags) or ida_bytes.get_item_head(ea) != ea:
            return
        kind = ida_nalt.get_str_type(ea)
        allowed = {idc.STRTYPE_C: 1, idc.STRTYPE_C_16: 2}
        if kind not in allowed:
            rejected[hex(ea)] = dict(target_va=hex(ea), reason='非已声明C/UTF16字符串')
            return
        size = ida_bytes.get_item_size(ea)
        if size <= 0 or size > 4098:
            rejected[hex(ea)] = dict(target_va=hex(ea), reason='无声明范围或超过有限长度')
            return
        width = allowed[kind]
        terminator = bytes(width)
        audit = identity(ea, size)
        raw = bytes.fromhex(audit['idb_hex'])
        value = raw[:-width]
        units = [value[i:i + width] for i in range(0, len(value), width)]
        if size < width or size % width or raw[-width:] != terminator or terminator in units:
            rejected[hex(ea)] = dict(target_va=hex(ea), byte_audit=audit,
                                    reason='原字节/NUL边界或字符宽度不满足严格契约')
            return
        strings[hex(ea)] = dict(target_va=hex(ea), ida_string_type=kind, unit_width=width,
                               payload_hex=value.hex(), nul_hex=terminator.hex(), byte_audit=audit,
                               pending_status='仅原字符串字节；编码和业务含义待审阅')

    functions, reuse, audits, calls, data = [], [], [], [], []
    for seed in config['seeds']:
        owner = ida_funcs.get_func(seed)
        assert owner is not None and owner.start_ea == seed, hex(seed)
        chunk_rows = [identity(a, b - a) for a, b in idautils.Chunks(seed)]
        audits.append(dict(seed_va=hex(seed), chunk_byte_ranges=chunk_rows,
                           pending_status='当前逐块字节已核；完整语义待审阅'))
        if seed in covered:
            refs = [source_ref(relative) for relative in covered[seed]]
            reuse.append(dict(seed_va=hex(seed), sources=refs, pending_status='已有原证复用待审'))
        else:
            assembly = []
            for a, b in idautils.Chunks(seed):
                for head in idautils.Heads(a, b):
                    assembly.append(dict(site_va=hex(head), text=line(head),
                                         is_code=bool(ida_bytes.is_code(ida_bytes.get_full_flags(head)))))
            try:
                pseudocode = ida_hexrays.decompile(seed)
                decompile_error = None
            except Exception as error:
                pseudocode, decompile_error = None, str(error)
            functions.append(dict(seed_va=hex(seed), end_va=hex(owner.end_ea),
                                  name=idc.get_func_name(seed), assembly=assembly,
                                  pseudocode=str(pseudocode) if pseudocode is not None else None,
                                  decompile_error=decompile_error, chunk_byte_ranges=chunk_rows,
                                  pending_status='仅导出待完整语义审阅'))
        for a, b in idautils.Chunks(seed):
            for head in idautils.Heads(a, b):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                    continue
                for xref in idautils.XrefsFrom(head, 0):
                    if int(xref.type) in (16, 17):
                        endpoint, chain = resolve(xref.to)
                        calls.append(dict(seed_va=hex(seed), site_va=hex(head), target_va=hex(xref.to),
                                          implementation_va=hex(endpoint), bridges=[hex(x) for x in chain],
                                          existing_sources=[source_ref(x) for x in covered.get(endpoint, [])]))
                    elif not xref.iscode:
                        data.append(dict(seed_va=hex(seed), site_va=hex(head), target_va=hex(xref.to),
                                         kind=int(xref.type), text=line(head)))
                        string_candidate(xref.to)
    for relative in config['reuse_navigation']:
        source_ref(relative)
    result = dict(schema='richonline-bounded-preparation-1', topic=config['topic'],
                  pending_status='仅只读原证准备；无业务结论', disk_sha256=EXPECTED_SHA,
                  exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  coverage_source_sha256=hashlib.sha256(coverage_bytes).hexdigest(),
                  seeds=[dict(seed_va=hex(x), pending_status='待完整语义审阅') for x in config['seeds']],
                  functions=functions, reused_seeds=reuse, current_chunk_audits=audits,
                  calls=calls, data_references=data, strings=list(strings.values()),
                  rejected_string_candidates=list(rejected.values()),
                  incoming={hex(x): incoming(x) for x in config['seeds']},
                  explicit_owner_windows=[owner_window(x) for x in config['owner_sites']],
                  data_windows=[identity(x, size, require_disk=False) for x, size in config['data_windows']],
                  reuse_sources=list(sources.values()))
    result['verified_direct_bridges'] = list(bridges.values())
    output = output_dir / 'bounded_raw.json'
    assert not output.exists(), '禁止覆盖既有采证，先由主代理核对批次'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(new_function_exports=len(functions), reused_seeds=len(reuse), output=str(output),
                pending_status='仅导出；不登记语义完成')
