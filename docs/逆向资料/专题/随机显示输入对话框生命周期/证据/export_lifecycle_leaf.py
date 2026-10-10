"""末轮补导实际析构、消息表及窗口创建；外部调用者只作导航。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/随机显示输入对话框生命周期/证据'
TARGETS = (0x9154F0, 0x916AA0, 0x915750, 0x918FB0, 0x91A5C0)


def export(db):
    namespace = {}
    shared = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(shared.read_text('utf-8'), str(shared), 'exec'), namespace)
    summary = namespace['export_group'](db, TARGETS, str(BASE / 'leaf_raw.json'))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
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

    incoming = []
    for target in (0x606602, 0x6037D1, 0x611093, 0x6112D2):
        references = []
        for xref in db.xrefs.to_ea(target):
            ins = db.instructions.get_at(xref.from_ea)
            owner = db.functions.get_at(xref.from_ea)
            references.append(dict(site=hex(xref.from_ea), kind=int(xref.type),
                                   function=hex(owner.start_ea) if owner else None,
                                   disassembly=db.instructions.get_disassembly(ins) if ins else None,
                                   bytes=identity(xref.from_ea, ins.size) if ins else None))
        incoming.append(dict(target=hex(target), references=references))
    result = dict(disk_sha256=digest, incoming=incoming,
                  scope='末轮局部叶与桥 incoming；外部业务调用者未全审')
    (BASE / 'leaf_navigation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                             encoding='utf-8')
    return dict(summary, incoming_targets=len(incoming))
