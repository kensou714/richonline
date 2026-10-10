"""核对磁盘身份、E9目标、主尾块、清单及中文注释式文档。"""
import hashlib
import json
import struct
from pathlib import Path
from export_supplement import GROUPS

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    if disk[:2] != b'MZ' or disk[pe:pe + 4] != b'PE\0\0':
        raise ValueError('无效PE')
    if struct.unpack_from('<H', disk, pe + 24)[0] != 0x10B:
        raise ValueError('仅适用当前PE32')
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

    errors, byte_map, funcs, tails, thunks, chunks = [], {}, {}, set(), set(), set()
    sha = hashlib.sha256(disk).hexdigest()
    files = [HERE / '证据' / (name + '.json')
             for name in sorted([*GROUPS, 'startup_windows'])]
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        raise ValueError('原证缺失：' + repr(missing))
    for path in files:
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('disk_sha256') != sha:
            errors.append([path.name, 'SHA256不符'])
        for r in records(data):
            va, size = int(r['va'], 16), r['size']
            saved, actual = bytes.fromhex(r['idb_hex']), read(va, size)
            if actual is None or len(saved) != size or saved != actual or r.get('disk_hex') != actual.hex() or r.get('matching') is not True:
                errors.append([path.name, r['va'], '字节或存档断言不符'])
            for offset, value in enumerate(saved):
                address = va + offset
                if address in byte_map and byte_map[address] != value:
                    errors.append([path.name, hex(address), '重复字节冲突'])
                byte_map[address] = value
            if 'target' in r:
                thunks.add(va)
                if len(saved) != 5 or saved[0] != 0xE9 or va + 5 + int.from_bytes(saved[1:], 'little', signed=True) != int(r['target'], 16):
                    errors.append([path.name, r['va'], 'E9目标不符'])
        for f in data.get('functions', []):
            if f['va'] in funcs and f != funcs[f['va']]:
                errors.append([f['va'], '重复函数原证冲突'])
            funcs[f['va']] = f
            if not f.get('declared_chunks'):
                errors.append([path.name, f['va'], '缺少get_chunks声明'])
            ranges = sorted((int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['byte_ranges'])
            for chunk in f.get('declared_chunks', []):
                lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                chunks.add((f['va'], lo, hi))
                if not chunk['is_main']:
                    tails.add((f['va'], lo, hi))
                cursor = lo
                for start, end in ranges:
                    if start <= cursor < end:
                        cursor = min(hi, end)
                if cursor != hi:
                    errors.append([path.name, f['va'], chunk['start_va'], '主尾块未连续覆盖'])
    review = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    rows = review['functions']
    if len(rows) != len(funcs) or {r['va'] for r in rows} != funcs.keys():
        errors.append(['审阅清单与原证集合不符'])
    for row in rows:
        for source in row['review_sources']:
            if not (HERE / source).is_file():
                errors.append([row['va'], '原证路径不存在'])
        if row['document'] and not (HERE / row['document']).is_file():
            errors.append([row['va'], '正文不存在'])
    for path in HERE.glob('*.txt'):
        for line, content in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if content.strip() and not content.lstrip().startswith('//'):
                errors.append([path.name, line, '不是注释式排版'])
    result = dict(disk_sha256=sha, evidence_files=len(files), exported_functions=len(funcs),
                  declared_chunks=len(chunks), declared_tail_chunks=len(tails),
                  unique_verified_bytes=len(byte_map), unique_e9_thunks=len(thunks),
                  review_status_counts=review['status_counts'], errors=errors,
                  scope='原证身份和声明块覆盖；不证明整函数语义或实机行为')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
