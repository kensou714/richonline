"""重读当前 EXE，核对本专题原证；只验证字节身份，不模拟游戏。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def validate():
    """按 PE 文件映射核验所有带 idb_hex 的字节记录，失败即非零退出。"""
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    if disk[:2] != b'MZ' or disk[pe:pe + 4] != b'PE\0\0':
        raise ValueError('当前客户端不是有效 PE 文件')
    if struct.unpack_from('<H', disk, pe + 24)[0] != 0x10B:
        raise ValueError('本验证器仅处理当前 PE32 客户端')
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    optional_size = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + optional_size + 40 * i + 8)
                for i in range(count)]

    def disk_bytes(va, size):
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return disk[offset + relative:offset + relative + size]
        return None

    def byte_records(value):
        if isinstance(value, dict):
            if all(key in value for key in ('va', 'size', 'idb_hex')):
                yield value
            for child in value.values():
                yield from byte_records(child)
        elif isinstance(value, list):
            for child in value:
                yield from byte_records(child)

    failures, unmapped, seen = [], [], {}
    function_vas, thunk_vas = set(), set()
    files = ['handlers.json', 'helpers.json', 'callees.json', 'funds.json',
             'registration_and_rtc.json']
    sha = hashlib.sha256(disk).hexdigest()
    for name in files:
        data = json.loads((HERE / '证据' / name).read_text(encoding='utf-8'))
        if data.get('disk_sha256') != sha:
            failures.append({'file': name, 'reason': 'EXE SHA256 与导出基线不同'})
        for item in data.get('functions', []):
            function_vas.add(item['va'])
        for item in data.get('thunks', []):
            thunk_vas.add(item['va'])
        for item in byte_records(data):
            va, size = int(item['va'], 16), item['size']
            saved = bytes.fromhex(item['idb_hex'])
            actual = disk_bytes(va, size)
            key = (va, size)
            if key in seen and seen[key] != saved:
                failures.append({'file': name, 'va': item['va'], 'reason': '同范围导出不一致'})
            seen[key] = saved
            if actual is None:
                unmapped.append({'file': name, 'va': item['va'], 'size': size})
            elif (len(saved) != size or saved != actual
                  or item.get('disk_hex') != actual.hex() or item.get('matching') is not True):
                failures.append({'file': name, 'va': item['va'], 'size': size,
                                 'reason': '保存原证与磁盘字节不一致'})
            if 'target' in item:
                thunk_vas.add(item['va'])
                if not saved or saved[0] != 0xE9 or len(saved) != 5:
                    failures.append({'file': name, 'va': item['va'], 'reason': 'E9 跳板形状不符'})
                elif va + 5 + int.from_bytes(saved[1:], 'little', signed=True) != int(item['target'], 16):
                    failures.append({'file': name, 'va': item['va'], 'reason': 'E9 目标不符'})
    result = {'disk_sha256': sha, 'evidence_files': len(files),
              'unique_exported_functions': len(function_vas), 'unique_jump_thunks': len(thunk_vas),
              'unique_byte_ranges': len(seen), 'unmapped': unmapped, 'failures': failures,
              'scope': '只核证据身份；函数导出数量不代表语义审阅或实机验收数量'}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if failures or unmapped else 0


if __name__ == '__main__':
    raise SystemExit(validate())
