"""补导对话框调用、消息注册、清理与已证虚表叶；只读。"""
from pathlib import Path
import json
import struct
import hashlib

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/随机显示输入对话框生命周期/证据'
TARGETS = (0x911E40, 0x9169B0, 0x917040, 0x9156E0, 0x918E90, 0x918EF0)


def export(db):
    namespace = {}
    shared = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(shared.read_text('utf-8'), str(shared), 'exec'), namespace)
    summary = namespace['export_group'](db, TARGETS, str(BASE / 'closure_raw.json'))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<III', blob, pe + 24 + optional_size + index * 40 + 12)
                for index in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def identity(va, size):
        disk = next(blob[offset + va - image_base - rva:offset + va - image_base - rva + size]
                    for rva, length, offset in sections
                    if 0 <= va - image_base - rva and va - image_base - rva + size <= length)
        live = db.bytes.get_bytes_at(va, size)
        assert live == disk
        return dict(va=hex(va), size=size, idb_hex=live.hex(), disk_hex=disk.hex(), matching=True)

    table = identity(0xA31690, 52)
    entries = []
    for index, target in enumerate(struct.unpack('<13I', bytes.fromhex(table['disk_hex']))):
        bridge = identity(target, 5)
        raw = bytes.fromhex(bridge['disk_hex'])
        assert raw[0] == 0xE9
        bridge['target'] = hex(target + 5 + struct.unpack('<i', raw[1:])[0])
        entries.append(dict(offset=index * 4, bridge=bridge))
    incoming = []
    for target in TARGETS:
        references = []
        for xref in db.xrefs.to_ea(target):
            ins = db.instructions.get_at(xref.from_ea)
            owner = db.functions.get_at(xref.from_ea)
            references.append(dict(site=hex(xref.from_ea), kind=int(xref.type),
                                   function=hex(owner.start_ea) if owner else None,
                                   disassembly=db.instructions.get_disassembly(ins) if ins else None,
                                   bytes=identity(xref.from_ea, ins.size) if ins else None))
        incoming.append(dict(target=hex(target), references=references))
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), table=table, vtable_entries=entries,
                  incoming=incoming, scope='13 个已写入表项的桥及选定叶；非全部控件虚表')
    (BASE / 'closure_navigation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                                encoding='utf-8')
    return dict(summary, vtable_entries=len(entries), incoming_targets=len(incoming))
