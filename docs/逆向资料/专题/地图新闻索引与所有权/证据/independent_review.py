"""独审只读核验：当前PE、完整声明块、调用跳板与反向引用。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = Path('F:/大富翁online/Richonline')
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', blob, 60)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt + 40 * i + 8) for i in range(count)]

    def disk(va, size):
        for _, rva, raw_size, offset in sections:
            d = va - base - rva
            if 0 <= d and d + size <= raw_size:
                return blob[offset + d:offset + d + size]
        raise AssertionError(('无PE后备', hex(va), size))

    ranges, comparisons = {}, 0

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and raw == disk(va, size) == bytes.fromhex(row['disk_hex'])
        assert row.get('matching', True) is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == raw, ('IDA字节', row['va'])
        if 'target' in row:
            assert size == 5 and raw[0] == 0xe9
            assert va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
        if (va, size) in ranges:
            assert ranges[(va, size)] == raw
        ranges[(va, size)] = raw
        comparisons += 1

    def read(path):
        return json.loads(path.read_text(encoding='utf-8-sig'))

    data = read(HERE / 'functions.json')
    external = read(HERE / '外部挂接.json')
    nav = read(HERE / 'inbound.json')
    review = read(TOPIC / '函数审阅清单.json')
    assert data['disk_sha256'] == external['disk_sha256'] == EXPECTED
    functions = {f['va']: f for f in data['functions']}
    assert len(functions) == len(data['functions']) == 37
    entries = declared_bytes = chunks_total = call_count = 0
    thunks = {int(r['va'], 16): r for r in data['thunks'] + external['thunks']}
    for f in functions.values():
        start = int(f['va'], 16)
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert len(declared) == len(f['declared_chunks'])
        assert {(s, e) for s, e, _ in declared} == {
            (int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['chunk_byte_ranges']}
        for r in f['byte_ranges'] + f['chunk_byte_ranges']:
            check(r)
        asm = {int(i['va'], 16): (i['size'], i['text']) for i in f['assembly']}
        assert len(asm) == len(f['assembly'])
        for s, e, _ in declared:
            cursor = s
            for va, (size, _) in sorted(asm.items()):
                if s <= va < e:
                    assert va == cursor and va + size <= e, ('块内缺口或重叠', f['va'], hex(va))
                    cursor += size
            assert cursor == e, ('块尾缺口', f['va'], hex(e))
        if db is not None:
            live = db.functions.get_at(start)
            assert live is not None and live.start_ea == start and live.end_ea == int(f['end_va'], 16)
            chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in chunks} == declared
            actual = {i.ea: (i.size, db.instructions.get_disassembly(i))
                      for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
            assert actual == asm, ('完整块汇编', f['va'])
        chunks_total += len(declared)
        declared_bytes += sum(e - s for s, e, _ in declared)
        entries += len(asm)

    for r in data['thunks'] + external['thunks'] + external['byte_ranges']:
        check(r)
    for f in list(functions.values()) + [external]:
        for edge in f['calls']:
            va, target = int(edge['site'], 16), int(edge['target'], 16)
            raw = disk(va, 5)
            assert raw[0] == 0xe8 and va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target
            for bridge in edge['thunks']:
                assert target == int(bridge, 16) and target in thunks
                target = int(thunks[target]['target'], 16)
            assert target == int(edge['implementation'], 16)
            call_count += 1

    # 对每个原始目标独立重建递归E9反向导航，包含普通流入而不限于call。
    refs = navigation_bridges = 0
    assert {r['target'] for r in nav} == set(functions) and len(nav) == 37
    for group in nav:
        saved = {(int(r['source'], 16), int(r['target'], 16), r['kind'], r['owner'], r['bridge'])
                 for r in group['edges']}
        assert len(saved) == len(group['edges'])
        for source, target, _, _, bridge in saved:
            raw = disk(source, 5)
            is_bridge = raw[0] == 0xe9 and source + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target
            assert is_bridge == bridge
        if db is not None:
            pending, seen, actual = [int(group['target'], 16)], set(), set()
            while pending:
                target = pending.pop()
                if target in seen:
                    continue
                seen.add(target)
                for x in db.xrefs.to_ea(target):
                    raw = db.bytes.get_bytes_at(x.from_ea, 5)
                    bridge = bool(raw and len(raw) == 5 and raw[0] == 0xe9 and
                                  x.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
                    owner = db.functions.get_at(x.from_ea)
                    actual.add((x.from_ea, target, int(x.type), hex(owner.start_ea) if owner else None, bridge))
                    if bridge:
                        pending.append(x.from_ea)
            assert actual == saved, ('完整递归引用集合', group['target'], actual ^ saved)
        refs += len(saved)
        navigation_bridges += sum(r[-1] for r in saved)
    if db is not None:
        for row in external['assembly']:
            instruction = db.instructions.get_at(int(row['va'], 16))
            assert db.instructions.get_disassembly(instruction) == row['text']
    assert len(review['functions']) == 37 and {r['va'] for r in review['functions']} == set(functions)
    assert all(all(r.get(k) for k in ('status', 'conclusion', 'unknown', 'evidence')) for r in review['functions'])
    for path in TOPIC.glob('*.txt'):
        assert all(not s.strip() or s.startswith('//') for s in path.read_text(encoding='utf-8-sig').splitlines())
    return dict(exe_sha256=EXPECTED, functions=len(functions), complete_chunks=chunks_total,
                assembly_entries=entries, declared_bytes=declared_bytes,
                function_thunks=len(data['thunks']), unique_thunks=len(thunks), checked_calls=call_count,
                external_excerpt_bytes=sum(r['size'] for r in external['byte_ranges']),
                navigation_targets=len(nav), navigation_references=refs, navigation_bridges=navigation_bridges,
                byte_comparisons=comparisons, unique_ranges=len(ranges), range_byte_sum=sum(len(v) for v in ranges.values()),
                manual_levels=dict(Counter(r['status'] for r in review['functions'])),
                live_ida_checked=db is not None, mismatches=0,
                scope='完整声明块、汇编和引用归属；范围长度和未合并重叠，静态原证不替代实机验收。')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
