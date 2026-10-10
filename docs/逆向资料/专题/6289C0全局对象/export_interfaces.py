"""只读导出真实析构及入口调用后窗口，定位ECX接收方法和资源常量。"""
import json
import struct
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/6289C0全局对象')


def export(db):
    namespace = {}
    exporter = HERE.parents[1] / '全量分析' / 'export_function_group.py'
    exec(compile(exporter.read_text(encoding='utf-8'), str(exporter), 'exec'), namespace)
    summary = namespace['export_group'](db, [0x7DBDD0], HERE / '证据' / 'destructor.json')
    disk = (HERE.parents[3] / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    opt = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe+24+opt+i*40+8) for i in range(count)]

    def identity(va, size):
        actual = None
        for _, rva, raw_size, raw_offset in sections:
            rel = va-base-rva
            if 0 <= rel and rel+size <= raw_size:
                actual = disk[raw_offset+rel:raw_offset+rel+size]
                break
        saved = db.bytes.get_bytes_at(va, size)
        return dict(va=hex(va), size=size, idb_hex=saved.hex(),
                    disk_hex=actual.hex() if actual is not None else None, matching=saved==actual)

    navigation = json.loads((HERE / '证据' / 'navigation.json').read_text(encoding='utf-8'))
    windows = []
    for c in navigation['calls']:
        start = int(c['site'], 16)
        instructions = list(db.instructions.get_between(start, start+48))
        end = instructions[-1].ea + instructions[-1].size
        windows.append(dict(site=c['site'], parent=c['parent'],
            bytes=identity(start, end-start),
            assembly=[dict(va=hex(i.ea), text=db.instructions.get_disassembly(i)) for i in instructions]))
    constants = []
    for va in [0xA2D5D4, 0xA2D5D8]:
        constants.append(dict(bytes=identity(va, 4),
                              interpretation='直接字符串字节；IDA的off名称不表示指针'))
    data = dict(disk_sha256=navigation['disk_sha256'], windows=windows, constants=constants,
                scope='有限调用后导航窗口及常量；不计完整函数语义，字节独立对盘')
    (HERE / '证据' / 'interface_navigation.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(export=summary, windows=len(windows), constants=len(constants))
