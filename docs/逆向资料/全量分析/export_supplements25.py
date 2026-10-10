"""第二十五批必要依赖补证；只读 IDA 和磁盘，禁止覆盖已保存原证。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CONFIG = {
    '124字节共享数组生命周期': ((0x6B7C60, 0x6A76E0, 0x6B9AF0, 0x6A1190), ()),
    '名称查找与等待消费者': ((0x858E50, 0x858EA0, 0x922830, 0x9228E0), ()),
    '基础边框与派生绘制消费': ((0x8EA8D0,), ((0x8E4330, 16),)),
}


def export(topic):
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import idautils
    import idc

    seeds, windows = CONFIG[topic]
    output = ROOT / 'docs/逆向资料/专题' / topic / '证据/supplement_raw.json'
    assert output.parent.is_dir() and not output.exists(), '补证目录不存在或原证已存在'
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe+24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe+52)[0]
    table = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, table+i*40+8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]

    def identity(ea, size):
        assert 0 < size <= 1048576
        matches = [(rva, off) for _, rva, length, off in sections
                   if 0 <= ea-base-rva and ea-base-rva+size <= length]
        assert len(matches) == 1, ('无唯一磁盘支持范围', hex(ea), size)
        rva, off = matches[0]
        disk = image[off+ea-base-rva:off+ea-base-rva+size]
        raw = ida_bytes.get_bytes(ea, size)
        assert raw is not None and len(raw) == size and disk == raw, ('IDB/磁盘不等', hex(ea))
        return dict(start_va=hex(ea), size=size, idb_hex=raw.hex(), disk_hex=disk.hex(),
                    matching=True, sha256=hashlib.sha256(raw).hexdigest())

    bridges = {}

    def resolve(ea):
        seen = []
        while True:
            assert ea not in seen, ('E9桥循环', hex(ea))
            raw = ida_bytes.get_bytes(ea, 5)
            owner = ida_funcs.get_func(ea)
            if raw is None or len(raw) != 5 or raw[0] != 0xE9 or owner is None:
                return ea, seen
            if owner.start_ea != ea or list(idautils.Chunks(ea)) != [(ea, ea+5)]:
                return ea, seen
            assert len(seen) < 16
            target = ea+5+struct.unpack_from('<i', raw, 1)[0]
            bridges[hex(ea)] = dict(identity(ea, 5), target_va=hex(target),
                                   pending_status='仅直接E9桥；端点不递归导出')
            seen.append(ea)
            ea = target

    functions, calls, refs = [], [], []
    for seed in seeds:
        owner = ida_funcs.get_func(seed)
        assert owner is not None and owner.start_ea == seed, ('不是函数入口', hex(seed))
        chunks = list(idautils.Chunks(seed))
        assembly = []
        for start, end in chunks:
            for head in idautils.Heads(start, end):
                is_code = bool(ida_bytes.is_code(ida_bytes.get_full_flags(head)))
                assembly.append(dict(site_va=hex(head),
                                     text=idc.generate_disasm_line(head, 0) or '',
                                     is_code=is_code))
                if not is_code:
                    continue
                for xref in idautils.XrefsFrom(head, 0):
                    if int(xref.type) in (16, 17):
                        endpoint, chain = resolve(xref.to)
                        calls.append(dict(seed_va=hex(seed), site_va=hex(head),
                                          target_va=hex(xref.to), implementation_va=hex(endpoint),
                                          bridges=[hex(x) for x in chain]))
                    elif not xref.iscode:
                        refs.append(dict(seed_va=hex(seed), site_va=hex(head),
                                         target_va=hex(xref.to), kind=int(xref.type)))
        try:
            pseudocode = ida_hexrays.decompile(seed)
            decompile_error = None
        except Exception as error:
            pseudocode, decompile_error = None, str(error)
        functions.append(dict(seed_va=hex(seed), end_va=hex(owner.end_ea),
                              name=idc.get_func_name(seed), assembly=assembly,
                              chunk_byte_ranges=[identity(a, b-a) for a, b in chunks],
                              pseudocode=str(pseudocode) if pseudocode is not None else None,
                              decompile_error=decompile_error,
                              pending_status='必要依赖完整声明块原证；语义未自动登记'))
    result = dict(schema='richonline-bounded-supplement-25-1', topic=topic,
                  disk_sha256=EXPECTED_SHA,
                  exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  seeds=[hex(x) for x in seeds], functions=functions, calls=calls,
                  data_references=refs, data_windows=[identity(a, n) for a, n in windows],
                  verified_direct_bridges=list(bridges.values()),
                  pending_status='只读补证；不自动计入语义覆盖')
    payload = (json.dumps(result, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
    with output.open('xb') as stream:
        stream.write(payload)
    return dict(path=str(output), sha256=hashlib.sha256(payload).hexdigest(),
                functions=len(functions), bridges=len(bridges), data_windows=len(windows))
