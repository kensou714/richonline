"""独审原证：磁盘字节、完整声明块、控制跳板、引用归属和D3DX出处。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/大富翁online/Richonline')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def read(name):
    return json.loads((HERE / name).read_text(encoding='utf-8-sig'))


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    nt = struct.unpack_from('<I', blob, 60)[0]
    count = struct.unpack_from('<H', blob, nt + 6)[0]
    optional = struct.unpack_from('<H', blob, nt + 20)[0]
    base = struct.unpack_from('<I', blob, nt + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, nt + 24 + optional + 40 * i + 8) for i in range(count)]

    def disk(va, size):
        for _, rva, raw_size, offset in sections:
            d = va - base - rva
            if 0 <= d and d + size <= raw_size:
                return blob[offset + d:offset + d + size]
        raise AssertionError(('无PE后备', hex(va), size))

    comparisons, ranges = 0, {}

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and raw == disk(va, size) == bytes.fromhex(row['disk_hex'])
        assert row['matching'] is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == raw, ('IDA字节', row['va'])
        if (va, size) in ranges:
            assert ranges[(va, size)] == raw
        ranges[(va, size)] = raw
        comparisons += 1
        return raw

    sources = [read('functions_raw.json'), read('identity_callers.json')]
    assert all(s['disk_sha256'] == SHA for s in sources)
    functions = {f['va']: f for s in sources for f in s['functions']}
    assert len(functions) == sum(len(s['functions']) for s in sources) == 14
    thunks = {}
    for source in sources:
        for row in source['thunks']:
            raw = check(row)
            va = int(row['va'], 16)
            assert raw[0] == 0xe9 and va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
            assert row['va'] not in thunks or thunks[row['va']] == row
            thunks[row['va']] = row
    instructions = chunks_total = chunk_bytes = calls = function_refs = 0
    for f in functions.values():
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert len(declared) == len(f['declared_chunks'])
        assert {(s, e) for s, e, _ in declared} == {(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges'] + f['chunk_byte_ranges']:
            check(row)
        assembly = {int(r['va'], 16): r['text'] for r in f['assembly']}
        assert len(assembly) == len(f['assembly'])
        assert all(any(s <= a < e for s, e, _ in declared) for a in assembly)
        if db is not None:
            live = db.functions.get_at(int(f['va'], 16))
            assert live.start_ea == int(f['va'], 16) and live.end_ea == int(f['end_va'], 16)
            chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in chunks} == declared
            actual = {}
            for c in chunks:
                cursor = c.start_ea
                for ins in db.instructions.get_between(c.start_ea, c.end_ea):
                    assert ins.ea == cursor and ins.ea + ins.size <= c.end_ea
                    cursor += ins.size
                    actual[ins.ea] = db.instructions.get_disassembly(ins)
                assert cursor == c.end_ea, ('块尾缺口', f['va'])
            assert actual == assembly, ('完整汇编', f['va'])
            actual_refs = {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(live.start_ea)}
            assert actual_refs == {(r['source'], r['kind']) for r in f['references']}
        for edge in f['calls']:
            site, target = int(edge['site'], 16), int(edge['target'], 16)
            raw = disk(site, 5)
            assert raw[0] in (0xe8, 0xe9) and site + 5 + struct.unpack_from('<i', raw, 1)[0] == target
            for bridge in edge['thunks']:
                assert hex(target) == bridge and bridge in thunks
                target = int(thunks[bridge]['target'], 16)
            assert target == int(edge['implementation'], 16)
            calls += 1
        instructions += len(assembly)
        chunks_total += len(declared)
        chunk_bytes += sum(e - s for s, e, _ in declared)
        function_refs += len(f['references'])
    nav = read('navigation_data.json')
    assert nav['disk_sha256'] == SHA and len(nav['targets']) == 9 and len(nav['data_records']) == 15
    control_refs = data_refs = 0
    for target in nav['targets']:
        raw = check(target['thunk'])
        address = int(target['target'], 16)
        assert raw[0] == 0xe9
        saved = {(int(r['site'], 16), r['kind'], r['function'], r['text']) for r in target['references']}
        assert len(saved) == len(target['references'])
        for r in target['references']:
            raw = check(r['bytes'])
            if raw[0] in (0xe8, 0xe9):
                assert int(r['site'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == address
        if db is not None:
            actual = set()
            for x in db.xrefs.to_ea(address):
                ins, owner = db.instructions.get_at(x.from_ea), db.functions.get_at(x.from_ea)
                actual.add((x.from_ea, int(x.type), hex(owner.start_ea) if owner else None,
                            db.instructions.get_disassembly(ins) if ins else None))
            assert actual == saved, ('导航引用', target['target'])
        control_refs += len(saved)
    for row in nav['data_records']:
        raw = check(row)
        if 'ascii' in row:
            assert raw == row['ascii'].encode('ascii') + b'\0'
        if 'references' in row:
            if db is not None:
                assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(int(row['va'], 16))} == {(r['site'], r['kind']) for r in row['references']}
            data_refs += len(row['references'])
    assert disk(0xA51D70, 22) == b'D3DX9 Shader Compiler\0' and disk(0xA45020, 23) == b'D3DX9 Shader Assembler\0'
    assert struct.unpack('<I', disk(0xA75FE4, 4))[0] == 0xA51D70 and struct.unpack('<I', disk(0xA6DF58, 4))[0] == 0xA45020
    for fva, site, pointer, call, impl in [('0xa0b1aa', 0xA0B76C, 0xA75FE4, 0xA0B810, '0x9d0a78'), ('0x9916f1', 0x991856, 0xA6DF58, 0x9918E3, '0x98e8c1')]:
        assert int.to_bytes(pointer, 4, 'little') in disk(site, 6)
        assert any(int(e['site'], 16) == call and e['implementation'] == impl for e in functions[fva]['calls'])
    review = read('function_review.json')
    assert {r['va'] for r in review['functions']} == set(functions) and len(review['functions']) == 14
    levels = Counter(r['review_status'] for r in review['functions'])
    assert dict(levels) == review['counts'] == {'局部语义已审阅': 11, '部分分析': 3}
    assert all(r['full_dependency_closure'] is False and r['conclusion'] and r['unknown'] and all((HERE / p).exists() for p in r['evidence']) for r in review['functions'])
    for path in HERE.parent.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    return dict(exe_sha256=SHA, functions=14, complete_chunks=chunks_total, assembly_entries=instructions,
                declared_bytes=chunk_bytes, unique_thunks=len(thunks), checked_calls=calls,
                function_references=function_refs, navigation_targets=9, navigation_references=control_refs,
                data_records=15, explicit_data_references=data_refs, byte_comparisons=comparisons,
                unique_ranges=len(ranges), range_byte_sum=sum(len(r) for r in ranges.values()),
                manual_levels=dict(levels), live_ida_checked=db is not None, mismatches=0,
                scope='原始字节、完整声明块及导航出处；未合并重叠范围，不替代语义或实机验收。')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = []
    for source in ['functions_raw.json', 'identity_callers.json']:
        for f in read(source)['functions']:
            lines.extend(['// ' + f['va'] + ' ' + f['name'], '// ' + '-' * 76])
            lines.extend('// ' + r['va'] + ' ' + r['text'] for r in f['assembly'])
            lines.append('//')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))
