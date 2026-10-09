"""在 IDA-MCP 中只读补存 4060..406C 注册跳板与局部栈描述。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/4060系列事件'


def export(db):
    """仅保存证据文件，不重命名、不改类型、不修补 IDB 或 EXE。"""
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    optional_size = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + optional_size + 40 * i + 8)
                for i in range(count)]

    def identity(va, size):
        actual = None
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                actual = disk[offset + relative:offset + relative + size]
                break
        original = db.bytes.get_bytes_at(va, size)
        if original is None or len(original) != size:
            raise ValueError('IDA 字节读取失败：' + hex(va))
        return {'va': hex(va), 'size': size, 'idb_hex': original.hex(),
                'disk_hex': actual.hex() if actual is not None else None,
                'matching': original == actual}

    registrations = []
    entries = [0x60C106, 0x6016B6, 0x605C70, 0x60ACD9, 0x610EC2,
               0x60B1C0, 0x6081D7, 0x60ACD4, 0x6125B0, 0x606427,
               0x61001C, 0x5FF1AE, 0x60243F]
    handlers = [0x663870, 0x663A50, 0x663C50, 0x663E50, 0x664040,
                0x664230, 0x6644C0, 0x6646C0, 0x664930, 0x664BC0,
                0x664DF0, 0x665020, 0x665200]
    for i, (entry, handler) in enumerate(zip(entries, handlers)):
        raw = db.bytes.get_bytes_at(entry, 5)
        if raw[0] != 0xE9:
            raise ValueError('注册入口不是 E9 跳板：' + hex(entry))
        target = entry + 5 + int.from_bytes(raw[1:], 'little', signed=True)
        expected = 0x7F0050 + 0x20 * i
        if target != expected:
            raise ValueError('注册 wrapper 不匹配：' + hex(entry))
        bridge = identity(entry, 5)
        bridge['target'] = hex(target)
        at = 0x7EE635 + 10 * i
        registrations.append({'code': hex(0x4060 + i), 'slot': hex(0xA9E260 + 4 * i),
                              'registration_write': identity(at, 10),
                              'instruction': db.instructions.get_disassembly(db.instructions.get_at(at)),
                              'bridge_thunk': bridge, 'wrapper': hex(target),
                              'handler': hex(handler)})

    rtc = []
    for function, descriptor in [(0x664230, 0x664459), (0x6646C0, 0x6648C5),
                                 (0x7C0230, 0x7C039A), (0x7C03C0, 0x7C0526)]:
        count, pointer = struct.unpack('<II', db.bytes.get_bytes_at(descriptor, 8))
        if not 0 < count < 32:
            raise ValueError('RTC 描述项数异常：' + hex(descriptor))
        row = {'function': hex(function), 'descriptor': identity(descriptor, 8),
               'count': count, 'variables': []}
        for i in range(count):
            at = pointer + 12 * i
            offset, size, name = struct.unpack('<iII', db.bytes.get_bytes_at(at, 12))
            raw = bytearray()
            for n in range(256):
                byte = db.bytes.get_bytes_at(name + n, 1)
                raw.extend(byte)
                if byte == b'\0':
                    break
            else:
                raise ValueError('RTC 变量名没有终止符')
            row['variables'].append({'stack_offset': offset, 'buffer_size': size,
                                     'name': raw[:-1].decode('ascii'),
                                     'layout': identity(at, 12), 'name_bytes': identity(name, len(raw))})
        rtc.append(row)
    data = {'disk_sha256': hashlib.sha256(disk).hexdigest(),
            'scope': '4060..406C 注册指令、入口 E9 字节及四处 RTC 描述；只读静态证据',
            'registrations': registrations, 'rtc': rtc}
    (HERE / '证据/registration_and_rtc.json').write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'registrations': len(registrations),
            'rtc': [{'function': r['function'], 'variables':
                     [(v['name'], v['stack_offset'], v['buffer_size']) for v in r['variables']]}
                    for r in rtc]}
