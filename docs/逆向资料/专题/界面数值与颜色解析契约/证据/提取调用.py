"""只读导出颜色入口所有直接引用及调用点附近的属性/存储原证。"""
import hashlib
import json
import struct
from pathlib import Path

import ida_bytes
import ida_funcs
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/界面数值与颜色解析契约/证据'


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe+6)[0]
    optional = struct.unpack_from('<H', blob, pe+20)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8) for i in range(count)]

    def raw(ea, size):
        for virtual, rva, raw_size, offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= raw_size:
                disk = blob[offset+relative:offset+relative+size]
                actual = ida_bytes.get_bytes(ea, size)
                assert actual == disk, hex(ea)
                return dict(va=hex(ea), size=size, disk_hex=disk.hex(), idb_hex=actual.hex(), matching=True)
        raise ValueError(hex(ea))

    refs = [dict(source_va=hex(x.frm), target_va=hex(target), kind=int(x.type))
            for target in [0x60C9A3, 0x8E0450] for x in idautils.XrefsTo(target)]
    sites, owners, strings = [], {}, {}
    for ref in refs:
        address = int(ref['source_va'], 16)
        if ref['target_va'] != '0x60c9a3' or idc.print_insn_mnem(address) != 'call':
            continue
        function = ida_funcs.get_func(address)
        assert function is not None
        owner = function.start_ea
        if owner not in owners:
            owners[owner] = dict(va=hex(owner), name=idc.get_func_name(owner),
                                scope='仅审调用点上下文，不等于完整owner审阅',
                                pseudocode=db.pseudocode.get_text(owner))
        instructions = sorted(idautils.FuncItems(owner))
        position = instructions.index(address)
        context = []
        for instruction in instructions[max(0, position-14):position+17]:
            row = raw(instruction, ida_bytes.get_item_size(instruction))
            row['text'] = idc.generate_disasm_line(instruction, 0)
            row['data_refs'] = []
            for target in idautils.DataRefsFrom(instruction):
                text = idc.get_strlit_contents(target)
                if not text or not 1 < len(text) < 256:
                    continue
                try:
                    value = text.decode('ascii', errors='strict')
                except UnicodeDecodeError:
                    continue
                if target not in strings:
                    item = raw(target, len(text)+1)
                    assert bytes.fromhex(item['disk_hex']) == text+b'\0'
                    item['text'] = value
                    strings[target] = item
                row['data_refs'].append(dict(target_va=hex(target), text=value))
            context.append(row)
        sites.append(dict(site=hex(address), owner_va=hex(owner), context=context))
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), entry=raw(0x60C9A3, 5),
                  references=refs, owners=list(owners.values()), sites=sites,
                  strings=list(strings.values()))
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / 'color_calls.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(sites=len(sites), owners=len(owners), strings=len(strings))
