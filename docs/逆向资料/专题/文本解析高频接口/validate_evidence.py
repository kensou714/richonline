"""核对原证磁盘身份、E9 目标及声明尾块覆盖；不执行客户端。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    if disk[:2] != b'MZ' or disk[pe:pe + 4] != b'PE\0\0':
        raise ValueError('无效 PE')
    if struct.unpack_from('<H', disk, pe + 24)[0] != 0x10B:
        raise ValueError('仅适用当前 PE32')
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    opt = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + opt + 40 * i + 8)
                for i in range(count)]

    def read(va, size):
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return disk[offset + relative:offset + relative + size]
        return None

    def records(node):
        if isinstance(node, dict):
            if {'va', 'size', 'idb_hex'} <= node.keys():
                yield node
            for value in node.values():
                yield from records(value)
        elif isinstance(node, list):
            for value in node:
                yield from records(value)

    errors, spans, funcs, tails, thunks = [], {}, set(), set(), set()
    sha = hashlib.sha256(disk).hexdigest()
    files = sorted((HERE / '证据').glob('*.json'))
    for path in files:
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('disk_sha256') != sha:
            errors.append([path.name, 'SHA256不符'])
        for r in records(data):
            va, size = int(r['va'], 16), r['size']
            saved = bytes.fromhex(r['idb_hex'])
            actual = read(va, size)
            if actual is None or len(saved) != size or saved != actual or r.get('disk_hex') != actual.hex() or r.get('matching') is not True:
                errors.append([path.name, r['va'], '字节或存档断言不符'])
            key = (va, size)
            if key in spans and spans[key] != saved:
                errors.append([path.name, r['va'], '重复范围冲突'])
            spans[key] = saved
            if 'target' in r:
                thunks.add(va)
                if len(saved) != 5 or saved[0] != 0xE9 or va + 5 + int.from_bytes(saved[1:], 'little', signed=True) != int(r['target'], 16):
                    errors.append([path.name, r['va'], 'E9目标不符'])
        for f in data.get('functions', []):
            funcs.add(f['va'])
            if not f.get('declared_chunks'):
                errors.append([path.name, f['va'], '缺少get_chunks声明'])
            ranges = sorted((int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['byte_ranges'])
            for chunk in f.get('declared_chunks', []):
                lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                if not chunk['is_main']:
                    tails.add((f['va'], lo, hi))
                cursor = lo
                for start, end in ranges:
                    if start <= cursor < end:
                        cursor = min(hi, end)
                if cursor != hi:
                    errors.append([path.name, f['va'], chunk['start_va'], '尾块/主块字节未连续覆盖'])
    result = dict(disk_sha256=sha, evidence_files=len(files), exported_functions=len(funcs),
                  declared_tail_chunks=len(tails), unique_byte_ranges=len(spans),
                  unique_e9_thunks=len(thunks), errors=errors,
                  scope='原证身份和声明块覆盖；不是函数语义完成率或运行验收')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
