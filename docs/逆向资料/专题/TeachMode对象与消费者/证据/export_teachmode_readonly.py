"""只读导出 TeachMode 对象初始化、相邻记录函数和直接调用者。"""
import hashlib
import json
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_nalt
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x628E30, 0x8102F0, 0x810330, 0x810360, 0x8103B0, 0x810D20)


def export(db):
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    def identity(ea, size):
        data = ida_bytes.get_bytes(ea, size)
        original = disk(ea, size)
        assert data is not None and data == original, hex(ea)
        return dict(va=hex(ea), end_va=hex(ea + size), size=size,
                    idb_hex=data.hex(), disk_hex=original.hex(), equal=True,
                    sha256=hashlib.sha256(data).hexdigest())

    def resolve(ea):
        chain = []
        while ea not in chain and ida_bytes.get_byte(ea) == 0xE9:
            chain.append(ea)
            ea += 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
        return ea, chain

    def incoming(ea):
        result = []
        pending, seen = [ea], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in idautils.XrefsTo(target, 0):
                owner = ida_funcs.get_func(x.frm)
                result.append(dict(site=hex(x.frm), target=hex(target),
                                   owner=hex(owner.start_ea) if owner else None,
                                   iscode=bool(x.iscode), kind=int(x.type)))
                impl, chain = resolve(x.frm)
                if x.iscode and impl == target and chain:
                    pending.append(x.frm)
        return result

    def function(ea):
        f = ida_funcs.get_func(ea)
        assert f and f.start_ea == ea, hex(ea)
        chunks, instructions, outgoing = [], [], []
        for start, end in idautils.Chunks(ea):
            chunks.append(identity(start, end - start))
            for head in idautils.Heads(start, end):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                    continue
                size = idc.get_item_size(head)
                instructions.append(dict(va=hex(head), size=size,
                                         text=idc.generate_disasm_line(head, 0) or '',
                                         hex=ida_bytes.get_bytes(head, size).hex()))
                for x in idautils.XrefsFrom(head, 0):
                    if x.iscode and any(a <= x.to < b for a, b in idautils.Chunks(ea)):
                        continue
                    impl, chain = resolve(x.to) if x.iscode else (x.to, [])
                    outgoing.append(dict(site=hex(head), target=hex(x.to),
                                         implementation=hex(impl), chain=[hex(a) for a in chain],
                                         target_name=idc.get_name(x.to),
                                         iscode=bool(x.iscode), kind=int(x.type)))
        try:
            pseudocode, error = db.pseudocode.get_text(ea), None
        except Exception as exc:
            pseudocode, error = [], str(exc)
        return dict(va=hex(ea), end_va=hex(f.end_ea), name=idc.get_func_name(ea),
                    chunks=chunks, instructions=instructions, incoming=incoming(ea),
                    outgoing=outgoing, pseudocode=pseudocode, pseudocode_error=error)

    functions = {ea: function(ea) for ea in SEEDS}
    caller_seeds = (0x628E30, 0x810D20)
    callers = {int(x['owner'], 16) for ea in caller_seeds for x in functions[ea]['incoming']
               if x['iscode'] and x['owner'] is not None}
    for ea in sorted(callers - functions.keys()):
        functions[ea] = function(ea)
    # 收集调用者所触及的短函数，以保留可能内联在外部区域的记录访问器。
    short_callees = set()
    for ea in callers:
        for x in functions[ea]['outgoing']:
            if not x['iscode'] or x['kind'] not in (17, 18):
                continue
            target = int(x['implementation'], 16)
            f = ida_funcs.get_func(target)
            if f and f.start_ea == target and 0 < f.end_ea - f.start_ea <= 160:
                short_callees.add(target)
    for ea in sorted(short_callees - functions.keys()):
        functions[ea] = function(ea)
    globals_ = {int(x['target'], 16) for x in functions[0x628E30]['outgoing']
                if not x['iscode'] and 0xA00000 <= int(x['target'], 16) < 0xB00000}
    global_rows = []
    for ea in sorted(globals_):
        global_rows.append(dict(identity(ea, 4), incoming=incoming(ea)))
    result = dict(schema=1, scope='只读函数、跳板、全局字节与直接调用者；不修改 IDB',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  idb_input_sha256=ida_nalt.retrieve_input_file_sha256().hex(),
                  seeds=[hex(ea) for ea in SEEDS], callers=[hex(ea) for ea in sorted(callers)],
                  short_callees=[hex(ea) for ea in sorted(short_callees)],
                  functions=list(functions.values()), globals=global_rows)
    out = HERE / 'teachmode_raw.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), functions=len(functions),
                callers=result['callers'], globals=[r['va'] for r in global_rows])


def export_bridges(db):
    """补充已有原证中所有直接 E9 链的 IDB/磁盘桥字节，不再次反编译。"""
    raw = json.loads((HERE / 'teachmode_raw.json').read_text(encoding='utf-8'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == raw['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    addresses = {int(ea, 16) for row in raw['functions'] for edge in row['outgoing']
                 for ea in edge['chain']}
    addresses.add(0x5FF852)  # 作为构造回调实参的地址引用，不属于直接调用chain。
    rows = []
    for ea in sorted(addresses):
        matches = [(rva, off) for _, rva, size, off in sections
                   if base + rva <= ea and ea + 5 <= base + rva + size]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        disk = image[off + ea - base - rva:off + ea - base - rva + 5]
        idb = ida_bytes.get_bytes(ea, 5)
        assert idb == disk and idb[0] == 0xE9, hex(ea)
        rows.append(dict(va=hex(ea), size=5, idb_hex=idb.hex(), disk_hex=disk.hex(),
                         target=hex(ea + 5 + struct.unpack_from('<i', idb, 1)[0]), equal=True))
    out = HERE / 'bridge_raw.json'
    out.write_text(json.dumps(dict(schema=1, disk_sha256=raw['disk_sha256'], bridges=rows),
                              ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(path=str(out), bridges=len(rows))
