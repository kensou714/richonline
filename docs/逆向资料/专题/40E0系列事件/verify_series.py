"""复核已保存IDA字节与当前PE，声明块必须逐字节覆盖。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]

def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for i in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        _, rva, size, offset = struct.unpack_from('<IIII', blob, pe + 24 + opt + 40*i + 8)
        sections.append((rva, size, offset))

    def check(r):
        va, n = int(r['va'], 16), r['size']
        raw = bytes.fromhex(r['idb_hex'])
        for rva, size, offset in sections:
            delta = va - base - rva
            if 0 <= delta and delta + n <= size:
                disk = blob[offset + delta:offset + delta + n]
                return len(raw) == n and raw == disk and r['disk_hex'] == disk.hex() and r['matching']
        return False

    functions, thunks, ranges, chunks, extras = {}, {}, {}, set(), {}
    failures = []
    for path in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        for f in data.get('functions', []):
            assert f.get('declared_chunks'), (path.name, f['va'])
            for c in f['declared_chunks']:
                start, end = int(c['start_va'], 16), int(c['end_va'], 16)
                cursor = start
                for r in sorted(f['byte_ranges'], key=lambda x: int(x['va'], 16)):
                    low, high = int(r['va'], 16), int(r['va'], 16) + r['size']
                    if low <= cursor < high:
                        cursor = min(high, end)
                    if cursor == end:
                        break
                assert cursor == end, (f['va'], hex(cursor))
                chunks.add((f['va'], start, end))
            functions[f['va']] = f
            for r in f['byte_ranges']:
                ranges[(r['va'], r['size'])] = r
                if not check(r):
                    failures.append(path.name + ':' + r['va'])
        for r in data.get('thunks', []):
            thunks[r['va']] = r
            if not check(r):
                failures.append(path.name + ':' + r['va'])
        for r in data.get('regions', []):
            extras[(r['va'], r['size'])] = r
            if not check(r):
                failures.append(path.name + ':' + r['va'])
    reviews = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert {r['va'] for r in reviews} == set(functions)
    raw_undefined = json.loads((HERE / '证据/undefined_638670.json').read_text(encoding='utf-8'))
    cursor = int(raw_undefined['start_va'], 16)
    rebuilt = bytearray()
    for instruction in raw_undefined['assembly']:
        assert int(instruction['va'], 16) == cursor
        instruction_raw = bytes.fromhex(instruction['hex'])
        assert len(instruction_raw) == instruction['size'] and instruction['text']
        rebuilt.extend(instruction_raw)
        cursor += instruction['size']
    assert cursor == int(raw_undefined['end_va'], 16)
    assert rebuilt.hex() == raw_undefined['bytes_hex']
    assert len(rebuilt) == raw_undefined['size']
    original = extras[(raw_undefined['start_va'], raw_undefined['size'])]
    assert original['idb_hex'] == rebuilt.hex() and check(original)
    undefined = [{'va': '0x638670', 'end_va': '0x63870a', 'status': '未定义范围原证已保存',
                  'conclusion': '动画33虚表首项指向本范围；48条带VA指令覆盖154字节，与当前PE一致。',
                  'unknown': 'IDA没有函数声明，未增加139函数覆盖数；完整启动语义待进一步整理。',
                  'evidence': '证据/undefined_638670.json', 'document': '02_陷阱地图与动画.txt'}]
    (HERE / '未定义范围审阅.json').write_text(json.dumps(undefined, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    resources = json.loads((HERE / '资源原证.json').read_text(encoding='utf-8'))
    for resource in resources:
        if hashlib.sha256((ROOT / resource['path']).read_bytes()).hexdigest() != resource['sha256']:
            failures.append(resource['path'])
    report = {'disk_sha256': hashlib.sha256(blob).hexdigest(), 'declared_functions': len(functions),
              'declared_chunks': len(chunks), 'declared_chunks_fully_covered': True,
              'instruction_bytes': sum(r['size'] for r in ranges.values()), 'unique_thunks': len(thunks),
              'extra_regions': len(extras), 'resources': len(resources), 'undefined_ranges': len(undefined),
              'states': dict(Counter(r['status'] for r in reviews)), 'failures': failures,
              'scope': '静态原证与当前PE比对；运行时全局未按磁盘常量核验，未运行客户端。'}
    (HERE / '专题验证.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    assert not failures

if __name__ == '__main__':
    main()
