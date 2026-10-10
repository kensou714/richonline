"""ASTable有限只读导出；由共享IDA租约持有者显式调用。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/ASTable配置与动作消费/证据'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = (0x627DB0, 0x640100, 0x640230, 0x640B70, 0x640BD0, 0x640C30, 0x7FB1C0)


def export(db, phase='core'):
    if phase not in ('core', 'navigation', 'closure', 'lifetime', 'fields'):
        raise ValueError('未知阶段：' + str(phase))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, raw_size, offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((image_base + rva, raw_size, offset))

    def disk(va, size):
        for start, count, offset in sections:
            if start <= va and va + size <= start + count:
                return blob[offset + va - start:offset + va - start + size]
        return None

    def identity(va, size):
        live = db.bytes.get_bytes_at(va, size)
        original = disk(va, size)
        return dict(va=hex(va), size=size, idb_hex=live.hex() if live is not None else None,
                    disk_hex=original.hex() if original is not None else None,
                    matching=live == original if original is not None else None)

    def save(name, result):
        BASE.mkdir(parents=True, exist_ok=True)
        (BASE / name).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    if phase == 'core':
        helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        namespace = {}
        exec(compile(helper.read_text('utf-8'), str(helper), 'exec'), namespace)
        return namespace['export_group'](db, SEEDS, str(BASE / 'functions_raw.json'))

    if phase in ('closure', 'lifetime', 'fields'):
        helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        namespace = {}
        exec(compile(helper.read_text('utf-8'), str(helper), 'exec'), namespace)
        if phase == 'fields':
            source = ROOT / 'docs/逆向资料/专题/TeachBoard记录与消费/证据/closure_raw.json'
            content = source.read_bytes()
            reused = json.loads(content)
            assert reused['disk_sha256'] == SHA
            function = next(item for item in reused['functions'] if int(item['va'], 16) == 0x646960)
            save('fields_reused.json', dict(disk_sha256=SHA, source=str(source.relative_to(ROOT)).replace('\\', '/'),
                                           source_sha256=hashlib.sha256(content).hexdigest(), functions=[function],
                                           scope='复用TeachBoard646960原证，不增加本批新导出计数'))
            return namespace['export_group'](db, (0x640140, 0x646B10, 0x646A20), str(BASE / 'fields_raw.json'))
        if phase == 'lifetime':
            value = disk(0x604C76, 5)
            assert value and value[0] == 0xE9
            target = 0x604C76 + 5 + int.from_bytes(value[1:], 'little', signed=True)
            return namespace['export_group'](db, (target, 0x6466C0, 0x646720, 0x646800), str(BASE / 'lifetime_raw.json'))
        targets = []
        for bridge in (0x611AB6, 0x60E28A):
            value = disk(bridge, 5)
            assert value and value[0] == 0xE9
            targets.append(bridge + 5 + int.from_bytes(value[1:], 'little', signed=True))
        targets.extend((0x646750, 0x7D7A90))
        result = namespace['export_group'](db, tuple(dict.fromkeys(targets)), str(BASE / 'closure_raw.json'))
        windows = []
        for start, end in ((0x624613, 0x624666),):
            assembly = [dict(va=hex(ins.ea), text=db.instructions.get_disassembly(ins),
                             bytes=identity(ins.ea, ins.size))
                        for ins in db.instructions.get_between(start, end) if ins.ea >= start]
            windows.append(dict(start_va=hex(start), end_va=hex(end), assembly=assembly,
                                scope='A766F0关闭局部；不认领整关闭函数'))
        save('closure_navigation.json', dict(disk_sha256=SHA, callbacks=[identity(a, 5) for a in (0x611AB6, 0x60E28A)], windows=windows))
        return result

    raw = json.loads((BASE / 'functions_raw.json').read_text('utf-8'))
    assert raw['disk_sha256'] == SHA
    incoming = []
    for target in SEEDS + (0xA766F0,):
        refs = []
        for reference in db.xrefs.to_ea(target):
            ins = db.instructions.get_at(reference.from_ea)
            owner = db.functions.get_at(reference.from_ea)
            refs.append(dict(site=hex(reference.from_ea), kind=int(reference.type),
                             owner=hex(owner.start_ea) if owner else None,
                             text=db.instructions.get_disassembly(ins) if ins else None,
                             bytes=identity(ins.ea, ins.size) if ins else None))
        incoming.append(dict(target=hex(target), references=refs))

    loader = next(item for item in raw['functions'] if item['va'] == '0x640230')
    strings = {}
    for item in loader['assembly']:
        for reference in db.xrefs.from_ea(int(item['va'], 16)):
            if int(reference.type) in (16, 17, 19, 21):
                continue
            original = disk(reference.to_ea, 256)
            if original is None or b'\0' not in original:
                continue
            value = original[:original.index(0)]
            if not value or any(byte < 32 or byte > 126 for byte in value):
                continue
            entry = strings.setdefault(hex(reference.to_ea), dict(bytes=identity(reference.to_ea, len(value) + 1),
                                                               ascii=value.decode('ascii'), sites=[]))
            entry['sites'].append(item['va'])
    windows = []
    for start, end, purpose in ((0x623D98, 0x623DD0, '启动ASTable局部；非整启动函数'),
                                (0x7C1039, 0x7C1070, '7FB1C0上游动作局部；不认领完整角色动作')):
        assembly = []
        for ins in db.instructions.get_between(start, end):
            assembly.append(dict(va=hex(ins.ea), text=db.instructions.get_disassembly(ins),
                                 bytes=identity(ins.ea, ins.size)))
        windows.append(dict(start_va=hex(start), end_va=hex(end), scope=purpose,
                            assembly=assembly,
                            caveat='按实际指令保存，窗口边缘不保证完整连续跨度'))
    save('navigation_raw.json', dict(disk_sha256=SHA, incoming=incoming, strings=list(strings.values()),
                                    windows=windows, data=[identity(0xA766F0, 4)],
                                    scope='直接引用、实际ASCII引用字节与两个局部窗口；导航不新增函数认领'))
    return dict(incoming_targets=len(incoming), ascii_strings=len(strings), windows=len(windows))
