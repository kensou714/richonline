"""独立复核当前PE与可选实时IDA；仅生成独审结果，不修改作者原证。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(r'F:\大富翁online\Richonline')
SDK = Path(r'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\imm.h')


def sdk_evidence():
    raw = SDK.read_bytes()
    lines = raw.decode('utf-8-sig').splitlines()
    selected = [{'start_line': a, 'end_line': b, 'text': '\n'.join(lines[a-1:b])}
                for a, b in [(53, 65), (621, 627)]]
    for row in selected:
        row['utf8_sha256'] = hashlib.sha256(row['text'].encode('utf-8')).hexdigest()
    assert '#define CFS_POINT                       0x0002' in selected[1]['text']
    assert '#define CFS_FORCE_POSITION              0x0020' in selected[1]['text']
    return dict(source=str(SDK), file_sha256=hashlib.sha256(raw).hexdigest(), excerpts=selected)


def recompute_author_outputs():
    saved = Path.write_text
    captured = {}

    def capture(path, value, *args, **kwargs):
        captured[path.resolve()] = value
        return len(value)

    Path.write_text = capture
    try:
        runpy.run_path(str(HERE.parent/'validate.py'), run_name='__main__')
    finally:
        Path.write_text = saved
    assert len(captured) == 2
    for path, value in captured.items():
        assert json.loads(value) == json.loads(path.read_text(encoding='utf-8'))
    return len(captured)


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    assert sha == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe = struct.unpack_from('<I', blob, 60)[0]
    n = struct.unpack_from('<H', blob, pe + 6)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+opt+40*i+8) for i in range(n)]

    def disk(va, size):
        for _, rva, raw_size, offset in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw_size:
                return blob[offset+delta:offset+delta+size]
        raise AssertionError(('未映射', hex(va), size))

    comparisons = 0
    ranges = set()

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        expected = bytes.fromhex(row['idb_hex'])
        assert len(expected) == size and disk(va, size) == expected
        assert expected == bytes.fromhex(row['disk_hex']) and row['matching']
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == expected
        comparisons += 1
        ranges.add((va, size))

    functions, instructions, chunks, thunks = {}, {}, set(), {}
    for name in ['ime_seeds.json', 'ime_dependencies.json', 'ime_import_wrappers.json', 'ime_init_caller.json']:
        data = json.loads((HERE/name).read_text(encoding='utf-8'))
        assert data['disk_sha256'] == sha
        for f in data['functions']:
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main'])
                        for c in f['declared_chunks']}
            assert {(s, e) for s, e, _ in declared} == {
                (int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
            assert f['bytes_match_disk']
            for row in f['byte_ranges'] + f['chunk_byte_ranges']:
                check(row)
            for ins in f['assembly']:
                va = int(ins['va'], 16)
                assert any(s <= va < e for s, e, _ in declared)
                assert any(int(r['va'], 16) <= va < int(r['va'], 16)+r['size'] for r in f['byte_ranges'])
                if va in instructions:
                    assert instructions[va] == ins['text']
                instructions[va] = ins['text']
            if f['va'] in functions:
                for key in ['declared_chunks', 'chunk_byte_ranges', 'byte_ranges', 'assembly', 'calls']:
                    assert functions[f['va']][key] == f[key]
            functions[f['va']] = f
            chunks.update((f['va'], s, e) for s, e, _ in declared)
            if db is not None:
                live = db.functions.get_at(int(f['va'], 16))
                assert live.start_ea == int(f['va'], 16)
                live_chunks = list(db.functions.get_chunks(live))
                assert {(c.start_ea, c.end_ea, c.is_main) for c in live_chunks} == declared
                actual = {i.ea: db.instructions.get_disassembly(i) for c in live_chunks
                          for i in db.instructions.get_between(c.start_ea, c.end_ea)}
                assert actual == {int(i['va'], 16): i['text'] for i in f['assembly']}
                calls = []
                for c in live_chunks:
                    for ins in db.instructions.get_between(c.start_ea, c.end_ea):
                        for x in db.xrefs.from_ea(ins.ea):
                            if x.type in (16, 17):
                                calls.append(dict(site=hex(ins.ea), target=hex(x.to_ea)))
                assert calls == [{k: c[k] for k in ('site', 'target')} for c in f['calls']]
        for row in data['thunks']:
            check(row)
            code = bytes.fromhex(row['idb_hex'])
            assert code[0] == 0xE9
            assert int(row['va'], 16)+5+int.from_bytes(code[1:], 'little', signed=True) == int(row['target'], 16)
            if row['va'] in thunks:
                assert thunks[row['va']] == row
            thunks[row['va']] = row

    refs = json.loads((HERE/'ime_references.json').read_text(encoding='utf-8'))
    assert refs['disk_sha256'] == sha
    assert len(refs['imports']) == 5
    import_rva = struct.unpack_from('<I', blob, pe+24+96+8)[0]
    import_rows = []
    descriptor = import_rva
    while True:
        original, stamp, forward, dll, iat = struct.unpack('<IIIII', disk(base+descriptor, 20))
        if not any((original, stamp, forward, dll, iat)):
            break
        lookup, index = original or iat, 0
        while True:
            value = struct.unpack('<I', disk(base+lookup+4*index, 4))[0]
            if not value:
                break
            if not value & 0x80000000:
                name_bytes, cursor = bytearray(), base+value+2
                while disk(cursor, 1) != b'\0':
                    name_bytes.extend(disk(cursor, 1))
                    cursor += 1
                name = name_bytes.decode('ascii')
                if 'Imm' in name:
                    import_rows.append(dict(va=hex(base+iat+4*index), name=name))
            index += 1
        descriptor += 20
    assert import_rows == refs['imports']
    if db is not None:
        actual_imports = [dict(va=hex(i.address), name=i.name)
                          for i in db.imports.get_all_imports() if 'Imm' in (i.name or '')]
        assert actual_imports == refs['imports']
    for row in refs['globals']:
        check(row)
    for group in refs['inbound']:
        for row in group['bridges']:
            check(row)
            code = bytes.fromhex(row['idb_hex'])
            assert code[0] == 0xE9
        if db is not None:
            targets = [group['target']] + [b['va'] for b in group['bridges']]
            for target in targets:
                actual = {(hex(x.from_ea), hex(x.to_ea), int(x.type))
                          for x in db.xrefs.to_ea(int(target, 16))}
                expected = {(r['source'], r['target'], r['kind'])
                            for r in group['edges'] if r['target'] == target}
                assert actual == expected
    global_edges = next(r['edges'] for r in refs['inbound'] if r['target'] == '0xa76504')
    assert [(r['source'], r['kind']) for r in global_edges] == [('0x623b00', 2), ('0x629fb3', 3)]
    getter = functions['0x629fb0']
    assert any('dword_A76504' in i['text'] for i in getter['assembly'])
    pos = functions['0x625c10']
    assert disk(0x625C5C, 4).hex() == '8d440604'
    assert disk(0x625C72, 7).hex() == 'c745cc20000000'
    assert [(c['site'], c['implementation']) for c in pos['calls'][:3]] == [
        ('0x625c2d', '0x629f80'), ('0x625c42', '0x629f20'), ('0x625c4d', '0x629f50')]
    assert any('return *(this + 89)' in s for s in functions['0x629ef0']['pseudocode'])
    assert any('this + 90' in s for s in functions['0x629f20']['pseudocode'])
    assert any('return *(this + 91)' in s for s in functions['0x629f50']['pseudocode'])
    assert [c['implementation'] for c in pos['calls'] if c['site'] in ['0x625c6d', '0x625c8f', '0x625ca0', '0x625cbb']] == [
        '0x8275b6', '0x8275b0', '0x8275aa', '0x8275a4']
    assert any('case 0x10Du:' in s for s in functions['0x7a29e0']['pseudocode'])
    dispatch = {int(i['va'], 16): i['text'] for i in functions['0x8e8a10']['assembly']}
    assert dispatch[0x8E8A5A].startswith('add     eax, 0FFFFFF00h')
    assert dispatch[0x8E8A5F] == 'cmp     eax, 5'
    assert dispatch[0x8E8A62].startswith('ja      def_8E8A68')
    assert dispatch[0x8E8B0D].startswith('lea     eax, [ecx-200h]')
    assert dispatch[0x8E8B13] == 'cmp     eax, 0Ah'
    assert dispatch[0x8E8B16].startswith('ja      def_8E8B1C')
    assert disk(0x8E8B16, 6).hex() == '0f87dc010000'
    assert dispatch[0x8E8CFB] == 'xor     al, al'
    assert dispatch[0x8E8CFF] == 'retn    10h'
    for row in refs['imports']:
        wrapper = {'ImmGetContext': 0x82759E, 'ImmGetCandidateWindow': 0x8275AA,
                   'ImmSetCompositionWindow': 0x8275B0, 'ImmGetCompositionWindow': 0x8275B6,
                   'ImmSetCandidateWindow': 0x8275A4}[row['name']]
        assert disk(wrapper, 6) == b'\xff\x25'+struct.pack('<I', int(row['va'], 16))
    review_path = HERE/'function_review.json'
    if review_path.is_file():
        review = json.loads(review_path.read_text(encoding='utf-8'))
        assert {r['va'] for r in review['functions']} == set(functions)
        for row in review['functions']:
            assert row['status'] and row['conclusion'] and row['unknown']
            assert row['full_dependency_closure'] is False
            for path in row['evidence']:
                assert (HERE/path).is_file()
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//')
                   for line in path.read_text(encoding='utf-8').splitlines())
    sdk = sdk_evidence()
    reproduced_outputs = recompute_author_outputs()
    return dict(scope='当前PE与保存原证；实时IDA为可选，只验证声明函数、E9入口和保存静态xref，不证明运行期输入法行为。',
                ida_live=db is not None, exe_sha256=sha, functions=len(functions), chunks=len(chunks),
                instruction_addresses=len(instructions), unique_thunks=len(thunks), import_entries=len(refs['imports']),
                inbound_groups=len(refs['inbound']), global_edges=len(global_edges), byte_comparisons=comparisons,
                distinct_address_size_ranges=len(ranges), range_size_sum=sum(s for _, s in ranges), mismatches=0,
                sdk_file_sha256=sdk['file_sha256'], author_outputs_reproduced=reproduced_outputs)


if __name__ == '__main__':
    (HERE/'independent_sdk_constants.json').write_text(json.dumps(sdk_evidence(), ensure_ascii=False, indent=2), encoding='utf-8')
    result = audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
