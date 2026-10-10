"""独审者的只读核对：声明块、PE、调用与虚槽、解析器字符串。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/大富翁online/Richonline')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = ['list_functions.json', 'list_dependencies.json', 'list_lifecycle.json']


def read(name):
    return json.loads((HERE / name).read_text(encoding='utf-8-sig'))


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    n = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40 * i + 8) for i in range(n)]

    def disk(va, size):
        for _, rva, length, offset in sections:
            d = va - base - rva
            if 0 <= d and d + size <= length:
                return blob[offset + d:offset + d + size]
        raise AssertionError(('无PE后备', hex(va), size))

    ranges, comparisons = {}, 0

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and raw == disk(va, size) == bytes.fromhex(row['disk_hex'])
        assert row['matching'] is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == raw
        assert (va, size) not in ranges or ranges[(va, size)] == raw
        ranges[(va, size)] = raw
        comparisons += 1
        return raw

    functions, thunks = {}, {}
    for name in SOURCES:
        source = read(name)
        assert source['disk_sha256'] == SHA
        for f in source['functions']:
            assert f['va'] not in functions
            functions[f['va']] = f
        for row in source['thunks']:
            raw = check(row)
            assert raw[0] == 0xe9 and int(row['va'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
            assert row['va'] not in thunks or thunks[row['va']] == row['target']
            thunks[row['va']] = row['target']
    instructions = calls = refs = declared_bytes = tails = chunks_total = 0
    for f in functions.values():
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert len(declared) == len(f['declared_chunks'])
        assert {(s, e) for s, e, _ in declared} == {(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges'] + f['chunk_byte_ranges']:
            check(row)
        assembly = {int(i['va'], 16): i['text'] for i in f['assembly']}
        assert len(assembly) == len(f['assembly'])
        assert all(any(s <= a < e for s, e, _ in declared) for a in assembly)
        if db is not None:
            live = db.functions.get_at(int(f['va'], 16))
            assert live.start_ea == int(f['va'], 16) and live.end_ea == int(f['end_va'], 16)
            chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in chunks} == declared
            actual = {}
            for c in chunks:
                for ins in db.instructions.get_between(c.start_ea, c.end_ea):
                    assert c.start_ea <= ins.ea and ins.ea + ins.size <= c.end_ea
                    actual[ins.ea] = db.instructions.get_disassembly(ins)
            assert actual == assembly, ('完整汇编', f['va'])
            assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(live.start_ea)} == {(r['source'], r['kind']) for r in f['references']}
        for edge in f['calls']:
            site, target = int(edge['site'], 16), int(edge['target'], 16)
            raw = disk(site, 5)
            assert raw[0] in (0xe8, 0xe9) and site + 5 + struct.unpack_from('<i', raw, 1)[0] == target
            assert site in assembly
            seen = set()
            for bridge in edge['thunks']:
                assert bridge == hex(target) and bridge not in seen
                seen.add(bridge)
                target = int(thunks[bridge], 16)
            assert target == int(edge['implementation'], 16)
            calls += 1
        instructions += len(assembly)
        chunks_total += len(declared)
        declared_bytes += sum(e-s for s, e, _ in declared)
        tails += sum(not main for _, _, main in declared)
        refs += len(f['references'])
    data = read('list_data.json')
    assert data['disk_sha256'] == SHA
    table = check(data['vtable'])
    for row in data['thunk_ranges']:
        raw = check(row)
        assert raw[0] == 0xe9 and int(row['va'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
        assert row['va'] not in thunks or thunks[row['va']] == row['target']
        thunks[row['va']] = row['target']
    expected_slots = {0: '0x8e39d0', 232: '0x8f7d40', 244: '0x8f4690', 252: '0x8f42d0'}
    assert len(data['slots']) == 4 and {s['offset'] for s in data['slots']} == set(expected_slots)
    for slot in data['slots']:
        target = struct.unpack_from('<I', table, slot['offset'])[0]
        assert hex(target) == slot['entry']
        for bridge in slot['thunks']:
            assert hex(target) == bridge
            target = int(thunks[bridge], 16)
        assert hex(target) == slot['implementation'] == expected_slots[slot['offset']]
    strings = {}
    for row in data['strings']:
        assert check(row) == row['text'].encode('ascii') + b'\0'
        assert row['va'] not in strings
        strings[row['va']] = row['text']
    saved_refs = set()
    for r in data['references']:
        owner, site, target = r['function_va'], int(r['instruction_va'], 16), int(r['target_va'], 16)
        assert owner in functions and any(int(i['va'], 16) == site for i in functions[owner]['assembly'])
        assert strings[hex(target)] == r['text']
        raw = disk(site, 5)
        assert raw[0] == 0x68 and struct.unpack_from('<I', raw, 1)[0] == target
        saved_refs.add((site, target))
    assert len(saved_refs) == len(data['references'])
    if db is not None:
        actual_refs = set()
        for ins in db.instructions.get_between(0x8f8080, int(functions['0x8f8080']['end_va'], 16)):
            for x in db.xrefs.from_ea(ins.ea):
                if hex(x.to_ea) in strings:
                    actual_refs.add((ins.ea, x.to_ea))
        assert actual_refs == saved_refs, '字符串引用集合'
    review = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8-sig'))['functions']
    assert len(review) == len(functions) == 42 and {f['va'] for f in review} == set(functions)
    levels = dict(Counter(f['status'] for f in review))
    assert levels == {'主体已审阅': 37, '局部已审阅': 5}
    assert all(r['scope'] and r['conclusion'] and r['unknown'] for r in review)
    for path in HERE.parent.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    union = []
    for a, n in sorted(ranges):
        if union and a <= union[-1][1]:
            union[-1][1] = max(union[-1][1], a+n)
        else:
            union.append([a, a+n])
    return dict(exe_sha256=SHA, functions=len(functions), complete_chunks=chunks_total,
                non_main_chunks=tails, assembly_entries=instructions, declared_bytes=declared_bytes,
                unique_thunks=len(thunks), checked_calls=calls, function_references=refs,
                vtable_slots=4, strings=len(strings), string_references=len(saved_refs),
                byte_comparisons=comparisons, unique_ranges=len(ranges), union_bytes=sum(b-a for a,b in union),
                review_levels=levels, live_ida_checked=db is not None, mismatches=0,
                scope='当前PE与保存IDA原证；实时检查汇编和引用集合，不替代实机或全依赖审阅。')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = []
    for name in SOURCES:
        for f in read(name)['functions']:
            lines.extend(['// ' + f['va'] + ' ' + f['name'], '// ' + '-' * 76])
            lines.extend('// ' + i['va'] + ' ' + i['text'] for i in f['assembly'])
            lines.append('//')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))
