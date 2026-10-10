"""补齐已选定的最小存储契约和静态数据窗；载入时无 IDA 副作用。"""
import hashlib
import json
import re
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/StockName与StockRace/证据'
SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
ENTRIES = (0x6C5D70, 0x6C7A40, 0x6C7BE0, 0x6C7AA0, 0x6C7AE0,
           0x6C5510, 0x6C7A00, 0x6C88D0, 0x6C82C0, 0x6C8910,
           0x6C56B0, 0x6C8250)


def run(db):
    """由持共享 IDA 租约的执行者调用；不修改数据库。"""
    blob = (ROOT / 'RnClient.exe').read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError('磁盘 EXE 指纹变化')
    ns = {}
    source = BASE / 'export_ida.py'
    exec(compile(source.read_text('utf-8'), str(source), 'exec'), ns)
    read = ns['disk_view'](blob)
    ns = {}
    source = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(source.read_text('utf-8'), str(source), 'exec'), ns)
    summary = ns['export_group'](db, ENTRIES, BASE / 'supplement_raw.json')

    def identity(va, size):
        live = db.bytes.get_bytes_at(va, size)
        disk = read(va, size)
        return dict(va=hex(va), size=size,
                    idb_hex=live.hex() if live is not None else None,
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=live == disk if disk is not None else None)

    def string_window(va):
        chars = bytearray()
        for offset in range(128):
            part = read(va + offset, 1)
            if part is None:
                raise ValueError('字符串没有磁盘映射')
            chars.extend(part)
            if part == b'\0':
                item = identity(va, len(chars))
                item['ascii'] = chars[:-1].decode('ascii')
                return item
        raise ValueError('字符串超过所选窗口')

    rtc = []
    for va in (0x6C1474, 0x6C17F0):
        count, array = struct.unpack('<II', read(va, 8))
        if count > 16:
            raise ValueError('RTC 数量异常')
        variables = []
        for index in range(count):
            at = array + index * 12
            offset, size, name = struct.unpack('<iII', read(at, 12))
            variables.append(dict(offset=offset, size=size,
                                  descriptor=identity(at, 12),
                                  name=string_window(name)))
        rtc.append(dict(header=identity(va, 8), variables=variables))

    source = ROOT / 'docs/逆向资料/专题/股票与交易流程/证据/stock_core.json'
    old = json.loads(source.read_text('utf-8'))
    init = next(f for f in old['functions'] if int(f['va'], 16) == 0x6C0E50)
    callbacks = []
    for slot, target in re.findall(r'\*\(this \+ (\d+)\) = sub_([0-9A-Fa-f]+)',
                                   '\n'.join(init['pseudocode'])):
        va = int(target, 16)
        bridge = identity(va, 5)
        raw = read(va, 5)
        if raw[0] != 0xE9:
            raise ValueError('所选回调不是直接 E9 桥')
        bridge['target'] = hex(va + 5 + struct.unpack('<i', raw[1:])[0])
        callbacks.append(dict(slot=int(slot), offset=hex(int(slot) * 4),
                              bridge=bridge))
    registered = identity(0x606643, 5)
    raw = read(0x606643, 5)
    registered['target'] = hex(0x606643 + 5 + struct.unpack('<i', raw[1:])[0])
    result = dict(disk_sha256=SHA256,
                  scope='选定 RTC 与字面量、虚表前两槽及 74 个直接桥；不含回调本体审阅',
                  strings=[string_window(0xA23C44), string_window(0xA23C48)],
                  vtable_prefix=identity(0xA22600, 8), rtc=rtc,
                  registered_callback=registered, callbacks=callbacks)
    (BASE / 'supplement_data.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(functions=summary, callbacks=len(callbacks), rtc=len(rtc),
                data_matching=all(item['bridge']['matching'] for item in callbacks))
