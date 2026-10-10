"""独立核对PE32身份、主尾块、E9和显式清单；不证明运行时语义。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path
from build_review import EVIDENCE

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    if disk[:2] != b'MZ' or disk[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', disk, pe + 24)[0] != 0x10B:
        raise ValueError('当前样本不是PE32')
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    opt = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + opt + 40 * i + 8) for i in range(count)]

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

    sha = hashlib.sha256(disk).hexdigest()
    errors, byte_map, funcs, chunks, tails, thunks = [], {}, {}, set(), set(), set()
    for name in EVIDENCE:
        path = HERE / '证据' / (name + '.json')
        data = json.loads(path.read_text(encoding='utf-8'))
        if data['disk_sha256'] != sha:
            errors.append([path.name, 'SHA256不符'])
        for r in records(data):
            va, size = int(r['va'], 16), r['size']
            saved, actual = bytes.fromhex(r['idb_hex']), read(va, size)
            if actual is None or len(saved) != size or saved != actual or r.get('disk_hex') != actual.hex() or r.get('matching') is not True:
                errors.append([path.name, r['va'], '字节或存档断言不符'])
            for off, value in enumerate(saved):
                addr = va + off
                if addr in byte_map and byte_map[addr] != value:
                    errors.append([hex(addr), '重复字节冲突'])
                byte_map[addr] = value
            if 'target' in r:
                thunks.add(va)
                if len(saved) != 5 or saved[0] != 0xE9 or va + 5 + int.from_bytes(saved[1:], 'little', signed=True) != int(r['target'], 16):
                    errors.append([path.name, r['va'], 'E9目标不符'])
        for f in data['functions']:
            if f['va'] in funcs and f != funcs[f['va']]:
                errors.append([f['va'], '函数原证冲突'])
            funcs[f['va']] = f
            ranges = sorted((int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['byte_ranges'])
            for c in f['declared_chunks']:
                lo, hi = int(c['start_va'], 16), int(c['end_va'], 16)
                chunks.add((f['va'], lo, hi))
                if not c['is_main']:
                    tails.add((f['va'], lo, hi))
                cursor = lo
                for start, end in ranges:
                    if start <= cursor < end:
                        cursor = min(end, hi)
                if cursor != hi:
                    errors.append([f['va'], c['start_va'], '主尾块不连续'])
    review = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    if {r['va'] for r in review['functions']} != funcs.keys() or len(review['functions']) != len(funcs):
        errors.append(['清单集合不符'])
    if review['status_counts'] != dict(Counter(r['status'] for r in review['functions'])):
        errors.append(['清单状态计数不符'])
    for row in review['functions']:
        for source in row['review_sources']:
            if not (HERE / source).is_file():
                errors.append([row['va'], '原证不存在'])
        if row['document'] and not (HERE / row['document']).is_file():
            errors.append([row['va'], '正文不存在'])
    for path in HERE.glob('*.txt'):
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if line.strip() and not line.lstrip().startswith('//'):
                errors.append([path.name, number, '非注释式正文'])
    navigation = json.loads((HERE / '证据' / 'entry_callers.json').read_text(encoding='utf-8'))
    navigation_checks = []
    for r in navigation['observed_e9_navigation']:
        saved = bytes.fromhex(r['idb_hex'])
        va = int(r['va'], 16)
        actual = read(va, len(saved))
        matching = saved == actual and len(saved) == 5 and saved[0] == 0xE9 and va + 5 + int.from_bytes(saved[1:], 'little', signed=True) == int(r['target'], 16)
        navigation_checks.append(dict(va=r['va'], target=r['target'], matching=matching))
        if not matching:
            errors.append([r['va'], '导航E9磁盘核验不符'])
    result = dict(disk_sha256=sha, evidence_files=len(EVIDENCE), exported_functions=len(funcs),
                  declared_chunks=len(chunks), declared_tail_chunks=len(tails),
                  unique_verified_bytes=len(byte_map), unique_e9_thunks=len(thunks),
                  review_status_counts=review['status_counts'], navigation_e9_checks=navigation_checks,
                  errors=errors, scope='显式原证身份与主尾块覆盖；导航不计语义，未证明实机行为')
    (HERE / '核验结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
