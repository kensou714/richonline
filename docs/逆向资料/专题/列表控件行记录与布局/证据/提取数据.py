"""当前IDA租约内只读回读列表虚表与属性字符串；保留逐范围磁盘比较。"""
import hashlib
import json
import struct
from pathlib import Path

import ida_bytes
import idautils
import idc

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/列表控件行记录与布局/证据'


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe+6)[0]
    optional = struct.unpack_from('<H', blob, pe+20)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8)
                for i in range(count)]
    def raw(ea, size):
        for virtual, rva, raw_size, raw_offset in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= raw_size:
                disk = blob[raw_offset+relative:raw_offset+relative+size]
                actual = ida_bytes.get_bytes(ea, size)
                assert actual == disk, hex(ea)
                return dict(va=hex(ea), size=size, disk_hex=disk.hex(),
                            idb_hex=actual.hex(), matching=True)
        raise ValueError(hex(ea))
    ranges, strings, refs = [], {}, []
    for function in [0x8F8080]:
        for ins in idautils.FuncItems(function):
            for target in idautils.DataRefsFrom(ins):
                text = idc.get_strlit_contents(target)
                if text and 1 < len(text) < 256:
                    try:
                        value = text.decode('ascii', errors='strict')
                    except UnicodeDecodeError:
                        continue
                    if target not in strings:
                        row = raw(target, len(text)+1)
                        assert bytes.fromhex(row['disk_hex']) == text+b'\0'
                        row['text'] = value
                        strings[target] = row
                    refs.append(dict(function_va=hex(function), instruction_va=hex(ins),
                                     target_va=hex(target), text=value))
    vtable = raw(0xA307D4, 272)
    slots = []
    for offset in [0, 232, 244, 252]:
        target = struct.unpack_from('<I', bytes.fromhex(vtable['disk_hex']), offset)[0]
        chain = []
        while db.bytes.get_bytes_at(target, 1) == b'\xe9':
            row = raw(target, 5)
            next_target = target+5+int.from_bytes(bytes.fromhex(row['disk_hex'])[1:], 'little', signed=True)
            row['target'] = hex(next_target)
            ranges.append(row)
            chain.append(hex(target))
            target = next_target
            assert len(chain) < 16
        slots.append(dict(offset=offset, entry=hex(struct.unpack_from('<I', bytes.fromhex(vtable['disk_hex']), offset)[0]),
                          implementation=hex(target), thunks=chain))
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), vtable=vtable,
                  slots=slots, strings=list(strings.values()), references=refs, thunk_ranges=ranges)
    (HERE / 'list_data.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dict(strings=len(strings), references=len(refs), slots=slots)
