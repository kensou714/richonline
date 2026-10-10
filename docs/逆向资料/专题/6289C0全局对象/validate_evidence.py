"""独立复核 PE32、函数块、E9、导航窗口与当前资源；不证明实机语义。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

from build_review import EVIDENCE

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def records(node):
    if isinstance(node, dict):
        if {'va', 'size', 'idb_hex'} <= node.keys():
            yield node
        for value in node.values():
            yield from records(value)
    elif isinstance(node, list):
        for value in node:
            yield from records(value)


def main():
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    if disk[:2] != b'MZ' or disk[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', disk, pe + 24)[0] != 0x10B:
        raise ValueError('当前样本不是 PE32')
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    optional_size = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + optional_size + 40 * i + 8)
                for i in range(count)]

    def read(va, size):
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return disk[offset + relative:offset + relative + size]
        return None

    sha = hashlib.sha256(disk).hexdigest()
    errors, byte_map, functions, chunks, tails, thunks = [], {}, {}, set(), set(), set()
    for name in EVIDENCE:
        path = HERE / '证据' / (name + '.json')
        data = json.loads(path.read_text(encoding='utf-8'))
        if data['disk_sha256'] != sha:
            errors.append([path.name, 'EXE SHA256 不符'])
        for item in records(data):
            va, size = int(item['va'], 16), item['size']
            saved, actual = bytes.fromhex(item['idb_hex']), read(va, size)
            if actual is None or len(saved) != size or saved != actual or item.get('disk_hex') != actual.hex() or item.get('matching') is not True:
                errors.append([path.name, item['va'], '块字节不符'])
            for off, value in enumerate(saved):
                addr = va + off
                if addr in byte_map and byte_map[addr] != value:
                    errors.append([hex(addr), '重叠字节冲突'])
                byte_map[addr] = value
            if 'target' in item:
                thunks.add(va)
                if len(saved) != 5 or saved[0] != 0xE9 or va + 5 + int.from_bytes(saved[1:], 'little', signed=True) != int(item['target'], 16):
                    errors.append([path.name, item['va'], 'E9 目标不符'])
        for function in data['functions']:
            if function['va'] in functions and function != functions[function['va']]:
                errors.append([function['va'], '函数原证冲突'])
            functions[function['va']] = function
            ranges = sorted((int(r['va'], 16), int(r['va'], 16) + r['size']) for r in function['byte_ranges'])
            for chunk in function['declared_chunks']:
                lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                chunks.add((function['va'], lo, hi))
                if not chunk['is_main']:
                    tails.add((function['va'], lo, hi))
                cursor = lo
                for start, end in ranges:
                    if start <= cursor < end:
                        cursor = min(end, hi)
                if cursor != hi:
                    errors.append([function['va'], chunk['start_va'], '函数块不连续'])
    review = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    if {r['va'] for r in review['functions']} != functions.keys() or len(review['functions']) != len(functions):
        errors.append(['审阅清单函数集合不符'])
    if review['status_counts'] != dict(Counter(r['status'] for r in review['functions'])):
        errors.append(['审阅状态计数不符'])
    for row in review['functions']:
        if not (HERE / row['document']).is_file() or any(not (HERE / p).is_file() for p in row['review_sources']):
            errors.append([row['va'], '正文或原证路径不存在'])
    for path in HERE.glob('*.txt'):
        for line_no, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if line.strip() and not line.lstrip().startswith('//'):
                errors.append([path.name, line_no, '非注释式正文'])
    navigation_checks = []
    for name in ('navigation', 'interface_navigation'):
        data = json.loads((HERE / '证据' / (name + '.json')).read_text(encoding='utf-8'))
        if data['disk_sha256'] != sha:
            errors.append([name, '导航 EXE SHA256 不符'])
        for item in records(data):
            saved = bytes.fromhex(item['idb_hex'])
            va = int(item['va'], 16)
            matching = saved == read(va, len(saved)) and item.get('disk_hex', saved.hex()) == saved.hex()
            if 'target' in item:
                matching = matching and len(saved) == 5 and saved[0] == 0xE9 and va + 5 + int.from_bytes(saved[1:], 'little', signed=True) == int(item['target'], 16)
            navigation_checks.append(dict(va=item['va'], matching=matching))
            if not matching:
                errors.append([name, item['va'], '导航字节或 E9 不符'])
    resource_checks = []
    for name in ('resource', 'vip_resource'):
        data = json.loads((HERE / '证据' / (name + '.json')).read_text(encoding='utf-8'))
        raw = (ROOT / data['source']).read_bytes()
        matching = len(raw) == data['source_size'] and hashlib.sha256(raw).hexdigest() == data['source_sha256']
        resource_checks.append(dict(source=data['source'], matching=matching))
        if not matching:
            errors.append([data['source'], '资源身份不符'])
    result = dict(disk_sha256=sha, evidence_files=len(EVIDENCE), exported_functions=len(functions),
                  declared_chunks=len(chunks), declared_tail_chunks=len(tails),
                  unique_verified_bytes=len(byte_map), unique_e9_thunks=len(thunks),
                  review_status_counts=review['status_counts'], navigation_checks=navigation_checks,
                  resource_checks=resource_checks, errors=errors,
                  scope='显式函数原证与导航/资源身份复核；不证明完整异常或实机行为')
    (HERE / '核验结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
