"""MapView 记录与预览消费只读导出；必须由共享 IDA 租约持有者显式执行。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/MapView配置记录与预览消费/证据'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
REUSE = {
    '角色1416字段来源/证据/functions.json': (0x7E8EB0,),
    '随机地图候选与配置索引/证据/dependencies_raw.json': (0x628C60, 0x7E9610),
}
NEW = (0x7E8E40, 0x622D50, 0x7E93A0)
FOLLOWUP = (0x7ECD20, 0x71E1B0, 0x73F420, 0x73FE50)
LEAF = (0x7E9490, 0x7E9510, 0x7E9590, 0x7E9690, 0x6293E0)
LIFETIME = (0x7E8E60,)
TARGETS = (0x628C60, 0x7E8EB0, 0x7E9610, 0x622D50, 0x7E93A0,
           0x6015B7, 0x6034D9, 0x612C5E, 0xA76704)


def export(db, phase='core'):
    """core 导出最小新入口并复核旧证；navigation 只生成引用窗口。"""
    if phase not in ('core', 'navigation', 'closure', 'leaf', 'lifetime'):
        raise ValueError('未知阶段：' + str(phase))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, raw_size, raw_offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((image_base + rva, raw_size, raw_offset))

    def disk_bytes(va, size):
        for start, count, offset in sections:
            relative = va - start
            if 0 <= relative and relative + size <= count:
                return blob[offset + relative:offset + relative + size]
        return None

    def identity(va, size):
        live = db.bytes.get_bytes_at(va, size)
        disk = disk_bytes(va, size)
        return dict(va=hex(va), size=size,
                    idb_hex=live.hex() if live is not None else None,
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=live == disk if disk is not None else None,
                    storage='磁盘映射' if disk is not None else '仅 IDB 当前值')

    BASE.mkdir(parents=True, exist_ok=True)
    if phase in ('leaf', 'lifetime'):
        ns = {}
        shared = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        exec(compile(shared.read_text('utf-8'), str(shared), 'exec'), ns)
        return ns['export_group'](db, LEAF if phase == 'leaf' else LIFETIME,
                                  str(BASE / (phase + '_raw.json')))
    if phase == 'closure':
        ns = {}
        shared = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        exec(compile(shared.read_text('utf-8'), str(shared), 'exec'), ns)
        summary = ns['export_group'](db, FOLLOWUP, str(BASE / 'closure_raw.json'))
        windows = []
        for start, end, scope in (
                (0x623F90, 0x623FD0, '启动 MapView 调用局部窗口，不认领整个启动函数'),
                (0x6244B0, 0x624500, '关闭时单例回收局部窗口，不认领整个关闭函数')):
            assembly = []
            calls = []
            for ins in db.instructions.get_between(start, end):
                assembly.append(dict(va=hex(ins.ea), text=db.instructions.get_disassembly(ins),
                                     bytes=identity(ins.ea, ins.size)))
                for ref in db.xrefs.from_ea(ins.ea):
                    if int(ref.type) not in (16, 17):
                        continue
                    address = ref.to_ea
                    raw = db.bytes.get_bytes_at(address, 5)
                    target = address
                    if raw and raw[0] == 0xE9:
                        target = address + 5 + int.from_bytes(raw[1:], 'little', signed=True)
                    calls.append(dict(site=hex(ins.ea), target=hex(address), implementation=hex(target)))
            windows.append(dict(scope=scope, start_va=hex(start), end_va=hex(end),
                                assembly=assembly, calls=calls))
        data = [identity(0xA67568, 16)]
        raw = bytes.fromhex(data[0]['disk_hex'])
        for pointer in struct.unpack('<4I', raw):
            value = disk_bytes(pointer, 128)
            assert value is not None and b'\0' in value
            data.append(identity(pointer, value.index(0) + 1))
        result = dict(disk_sha256=SHA, windows=windows, data=data,
                      scope='四个最小新入口、四项频道字符串和启动/关闭局部；所有权仍需目标函数证据')
        (BASE / 'closure_navigation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return dict(summary, windows=len(windows), data=len(data))
    if phase == 'core':
        sources = []
        reused = []
        for relative, addresses in REUSE.items():
            path = ROOT / 'docs/逆向资料/专题' / relative
            data = path.read_bytes()
            source = json.loads(data.decode('utf-8'))
            assert source['disk_sha256'] == SHA
            selected = [item for item in source['functions'] if int(item['va'], 16) in addresses]
            assert len(selected) == len(addresses)
            for item in selected:
                for key in ('byte_ranges', 'chunk_byte_ranges'):
                    for old in item[key]:
                        audit = identity(int(old['va'], 16), old['size'])
                        assert audit['matching'] and audit['disk_hex'] == old['disk_hex']
                record = dict(item)
                record['reuse_source'] = str(path.relative_to(ROOT)).replace('\\', '/')
                record['status'] = '历史原证复用；本专题语义待审阅'
                reused.append(record)
            sources.append(dict(path=str(path.relative_to(ROOT)).replace('\\', '/'),
                                sha256=hashlib.sha256(data).hexdigest(),
                                entries=[hex(address) for address in addresses]))
        result = dict(disk_sha256=SHA, scope='历史原证逐范围复核；历史部分分析不转为完整审阅',
                      sources=sources, functions=reused)
        (BASE / 'reused_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                            encoding='utf-8')
        ns = {}
        shared = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        exec(compile(shared.read_text('utf-8'), str(shared), 'exec'), ns)
        summary = ns['export_group'](db, NEW, str(BASE / 'functions_raw.json'))
        return dict(summary, reused_functions=len(reused))

    incoming = []
    bridges = []
    for target in TARGETS:
        refs = []
        for ref in db.xrefs.to_ea(target):
            ins = db.instructions.get_at(ref.from_ea)
            owner = db.functions.get_at(ref.from_ea)
            refs.append(dict(site=hex(ref.from_ea), kind=int(ref.type),
                             function=hex(owner.start_ea) if owner else None,
                             disassembly=db.instructions.get_disassembly(ins) if ins else None,
                             bytes=identity(ref.from_ea, ins.size) if ins else None))
        incoming.append(dict(target=hex(target), references=refs))
        raw = db.bytes.get_bytes_at(target, 5)
        if raw and raw[0] == 0xE9:
            record = identity(target, 5)
            record['target'] = hex(target + 5 + int.from_bytes(raw[1:], 'little', signed=True))
            bridges.append(record)
    result = dict(disk_sha256=SHA,
                  scope='入口、桥与单例槽直接引用；调用者待消费路径筛选，不认领完整 UI',
                  incoming=incoming, bridges=bridges,
                  windows=[identity(0xA76704, 4), identity(0xA2D9B8, 16)])
    (BASE / 'navigation_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                             encoding='utf-8')
    return dict(targets=len(incoming), bridges=len(bridges),
                incoming_sites=sum(len(item['references']) for item in incoming))
