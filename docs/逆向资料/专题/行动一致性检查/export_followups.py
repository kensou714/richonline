"""在已连接的 IDA-MCP 数据库中只读导出行动一致性检查补证。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/行动一致性检查'


def export(db):
    """复用项目导出器；不重命名、不改类型、不修补数据库字节。"""
    shared = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), shared)
    functions = shared['export_group'](db, [0x694DB0, 0x7F72A0, 0x6802A0],
                                       HERE / '证据/position_followups.json')
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    section_count = struct.unpack_from('<H', disk, pe + 6)[0]
    optional_size = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + optional_size + 40 * i + 8)
                for i in range(section_count)]

    def identity(va, size):
        actual = None
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                actual = disk[offset + relative:offset + relative + size]
                break
        original = db.bytes.get_bytes_at(va, size)
        return {'va': hex(va), 'size': size, 'idb_hex': original.hex(),
                'disk_hex': actual.hex() if actual is not None else None,
                'matching': original == actual if actual is not None else None,
                'file_backed': actual is not None}

    rtc = []
    for va in [0x662BD6, 0x64FAE8]:
        count, pointer = struct.unpack('<II', db.bytes.get_bytes_at(va, 8))
        row = {'descriptor': identity(va, 8), 'count': count, 'variables': []}
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
    registration = {'code': '0x4044', 'dispatch_base': '0xa8e0e0', 'slot': '0xa9e1f0',
                    'slot_calculation': '0xa8e0e0 + 4 * 0x4044',
                    'idb_slot_observation': identity(0xA9E1F0, 4),
                    'slot_observation_note': '该地址不在磁盘原始节范围；IDA 读值不代表磁盘或运行时初值',
                    'registration_write': identity(0x7EE5DB, 10),
                    'instruction': db.instructions.get_disassembly(db.instructions.get_at(0x7EE5DB)),
                    'bridge_thunk': identity(0x60B1C5, 5),
                    'bridge': '0x7eff30', 'handler_thunk': identity(0x60A469, 5),
                    'handler': '0x662b20'}
    callers = []
    for va in [0x60A086, 0x60ED07]:
        callers.append({'thunk': identity(va, 5),
                        'callers': [{'site': hex(x.from_ea),
                                     'function': hex(db.functions.get_at(x.from_ea).start_ea)
                                     if db.functions.get_at(x.from_ea) else None,
                                     'instruction': db.instructions.get_disassembly(db.instructions.get_at(x.from_ea)),
                                     'byte_range': identity(x.from_ea, db.instructions.get_at(x.from_ea).size)}
                                    for x in db.xrefs.to_ea(va)]})
    data = {'disk_sha256': hashlib.sha256(disk).hexdigest(),
            'scope': 'RTC 描述、4044 注册写入及位置辅助函数直接调用点；均为只读静态证据',
            'rtc': rtc, 'registration': registration, 'position_callers': callers}
    (HERE / '证据/check_layout_and_registration.json').write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    scan = json.loads((HERE / '证据/position_displacement_scan.json').read_text(encoding='utf-8'))
    verified = []
    for candidate in scan['hits']:
        va = int(candidate['va'], 16)
        ins = db.instructions.get_at(va)
        match = identity(va, ins.size)
        verified.append({**candidate, 'instruction_size': ins.size,
                         'current_disassembly': db.instructions.get_disassembly(ins),
                         'declared_function': hex(db.functions.get_at(va).start_ea),
                         'same_function': int(candidate['function'], 16) == db.functions.get_at(va).start_ea,
                         'same_raw_hex': candidate['raw_hex'] == match['idb_hex'], 'byte_range': match})
    result = {'disk_sha256': hashlib.sha256(disk).hexdigest(), 'scope': scan['scope'],
              'hits': verified, 'count': len(verified),
              'all_matching': all(r['same_function'] and r['same_raw_hex'] and r['byte_range']['matching']
                                  for r in verified)}
    (HERE / '证据/position_displacement_verified.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'functions': functions, 'rtc_sizes': [r['variables'][0]['buffer_size'] for r in rtc],
            'candidate_count': len(verified), 'candidates_matching': result['all_matching']}
