"""只读导出输入法导入包装、引用闭包及句柄存储身份。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def collect(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    result = export(db, [0x82759E, 0x8275A4, 0x8275AA, 0x8275B0, 0x8275B6, 0x7A4830],
                    str(HERE / '证据/ime_import_wrappers.json'))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    opt_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + opt_size + 40 * index
        vs, rva, rs, off = struct.unpack_from('<IIII', blob, at + 8)
        sections.append(dict(name=blob[at:at+8].rstrip(b'\0').decode('ascii'),
                             virtual_size=vs, rva=rva, raw_size=rs, raw_offset=off))

    def identity(ea, size):
        rva = ea - base
        section = next(s for s in sections if s['rva'] <= rva < s['rva'] + max(s['virtual_size'], s['raw_size']))
        delta = rva - section['rva']
        backed = delta + size <= section['raw_size']
        raw = blob[section['raw_offset']+delta:section['raw_offset']+delta+size] if backed else None
        current = db.bytes.get_bytes_at(ea, size)
        return dict(va=hex(ea), size=size, idb_hex=current.hex(), section=section,
                    disk_hex=raw.hex() if raw is not None else None,
                    disk_backed=backed, matching=current == raw if backed else None,
                    pe_zero_fill=not backed and delta >= section['raw_size'] and delta + size <= section['virtual_size'])

    def inbound(target):
        pending, seen, edges, bridges = [target], set(), [], []
        while pending:
            address = pending.pop()
            if address in seen:
                continue
            seen.add(address)
            for x in db.xrefs.to_ea(address):
                owner = db.functions.get_at(x.from_ea)
                raw = db.bytes.get_bytes_at(x.from_ea, 5)
                bridge = bool(raw and raw[0] == 0xE9 and x.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == address)
                edges.append(dict(source=hex(x.from_ea), target=hex(address), kind=int(x.type),
                                  owner=hex(owner.start_ea) if owner else None, bridge=bridge))
                if bridge:
                    bridges.append(identity(x.from_ea, 5))
                    pending.append(x.from_ea)
        return dict(target=hex(target), edges=edges, bridges=bridges)

    imports = [dict(va=hex(i.address), name=i.name) for i in db.imports.get_all_imports() if 'Imm' in (i.name or '')]
    targets = [0x625C10, 0x623AD0, 0x629FB0, 0xA76504]
    targets += [0x82759E, 0x8275A4, 0x8275AA, 0x8275B0, 0x8275B6]
    data = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), imports=imports,
                globals=[identity(0xA76504, 4)], inbound=[inbound(ea) for ea in targets],
                scope='IDA静态xref闭包；只递归E9入口，不证明间接调用、动态解析或运行期生命周期')
    (HERE / '证据/ime_references.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(export=result, imports=len(imports), inbound_targets=len(targets), globals=data['globals'])
