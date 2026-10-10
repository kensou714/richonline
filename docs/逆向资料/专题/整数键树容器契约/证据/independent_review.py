"""独立核对整数键树局部契约；只写独审结果，不改原证、IDB 或客户端。"""
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import runpy
import struct
import sys

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = Path(r'F:\大富翁online\Richonline')
SOURCES = ['callers_and_node.json', 'direct_dependencies.json', 'entries.json',
           'head_and_clear.json', 'lifecycle.json', 'reader_and_cleanup.json',
           'startup_windows.json', 'tree_helpers.json']
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def reproduce_author():
    original = Path.write_text
    original_path = list(sys.path)
    captures = {}

    def capture(path, value, *args, **kwargs):
        captures[path.resolve()] = value
        return len(value)

    Path.write_text = capture
    sys.path.insert(0, str(TOPIC))
    try:
        with redirect_stdout(io.StringIO()):
            ns = runpy.run_path(str(TOPIC/'build_review.py'), run_name='review')
            ns['main']()
    finally:
        Path.write_text = original
        sys.path[:] = original_path
    assert len(captures) == 2
    for path, text in captures.items():
        if path.suffix == '.json':
            assert json.loads(text) == json.loads(path.read_text('utf-8'))
        else:
            assert text == path.read_text('utf-8')
    try:
        sys.path.insert(0, str(TOPIC))
        with redirect_stdout(io.StringIO()) as output:
            ns = runpy.run_path(str(TOPIC/'validate_evidence.py'), run_name='review')
            assert ns['main']() is False
    finally:
        sys.path[:] = original_path
    return len(captures), json.loads(output.getvalue())


def audit(db=None):
    raw = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    base = struct.unpack_from('<I', raw, pe+52)[0]
    opt = struct.unpack_from('<H', raw, pe+20)[0]
    sections = [struct.unpack_from('<IIII', raw, pe+24+opt+40*i+8)
                for i in range(struct.unpack_from('<H', raw, pe+6)[0])]

    def disk(va, size):
        for _, rva, raw_size, at in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw_size:
                return raw[at+delta:at+delta+size]
        raise AssertionError((hex(va), size, '缺磁盘映射'))

    byte_map, ranges = {}, set()
    comparisons = 0

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        value = bytes.fromhex(row['idb_hex'])
        assert len(value) == size and disk(va, size) == value
        assert value.hex() == row['disk_hex'] and row['matching'] is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == value
        for index, byte in enumerate(value):
            if va+index in byte_map:
                assert byte_map[va+index] == byte
            byte_map[va+index] = byte
        ranges.add((va, size))
        comparisons += 1

    functions, chunks, tails, thunks, instructions, windows = {}, set(), set(), {}, {}, []
    for name in SOURCES:
        source = json.loads((HERE/name).read_text('utf-8'))
        assert source['disk_sha256'] == SHA
        for f in source.get('functions', []):
            if f['va'] in functions:
                assert functions[f['va']] == f
            functions[f['va']] = f
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main'])
                        for c in f['declared_chunks']}
            assert {(s, e) for s, e, _ in declared} == {
                (int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
            assert f['bytes_match_disk'] is True
            for row in f['byte_ranges']+f['chunk_byte_ranges']:
                check(row)
            for i in f['assembly']:
                va = int(i['va'], 16)
                assert any(s <= va < e for s, e, _ in declared)
                if va in instructions:
                    assert instructions[va] == i['text']
                instructions[va] = i['text']
            chunks.update((f['va'], s, e) for s, e, _ in declared)
            tails.update((f['va'], s, e) for s, e, main in declared if not main)
            if db is not None:
                live = db.functions.get_at(int(f['va'], 16))
                assert live.start_ea == int(f['va'], 16)
                live_chunks = list(db.functions.get_chunks(live))
                assert {(c.start_ea, c.end_ea, c.is_main) for c in live_chunks} == declared
                assert {i.ea: db.instructions.get_disassembly(i) for c in live_chunks
                        for i in db.instructions.get_between(c.start_ea, c.end_ea)} == {
                            int(i['va'], 16): i['text'] for i in f['assembly']}
                calls = [dict(site=hex(i.ea), target=hex(x.to_ea)) for c in live_chunks
                         for i in db.instructions.get_between(c.start_ea, c.end_ea)
                         for x in db.xrefs.from_ea(i.ea) if x.type in (16, 17)]
                assert calls == [{k: c[k] for k in ('site', 'target')} for c in f['calls']]
        for row in source.get('thunks', []):
            check(row)
            va, code = int(row['va'], 16), bytes.fromhex(row['idb_hex'])
            assert len(code) == 5 and code[0] == 0xE9
            assert va+5+struct.unpack_from('<i', code, 1)[0] == int(row['target'], 16)
            if row['va'] in thunks:
                assert thunks[row['va']] == row
            thunks[row['va']] = row
        for row in source.get('windows', []):
            check(row)
            windows.append(row['va'])

    exact = {
        0x8BE029: 'mov     edx, [eax]', 0x8BE02B: 'cmp     edx, [ecx]',
        0x8BE02D: 'sbb     eax, eax', 0x8BE02F: 'neg     eax',
        0x8BC508: "push    64h ; 'd'; int", 0x8BC50A: "push    24h ; '$'; unsigned int",
        0x8BC518: 'mov     dword ptr [eax+0E10h], 0', 0x8BC573: "push    24h ; '$'; Size",
        0x8C03C6: 'mov     ecx, 385h', 0x8C03CB: 'rep movsd',
        0x8C6B13: 'add     edi, 0Ch', 0x8C6B16: 'mov     ecx, 386h',
        0x8C6B1B: 'rep movsd', 0x8C6B23: 'mov     [eax+0E24h], cl',
        0x8C6B2C: 'mov     byte ptr [eax+0E25h], 0',
        0x8C59F3: 'mov     [ebp+var_14], 122A01h', 0x8C6DF1: 'imul    eax, 0E28h',
        0x8C0A00: 'sub     eax, 1', 0x8C0A06: 'cmp     eax, [ecx+8]',
        0x8C0A09: 'ja      short loc_8C0A45',
        0x8CC76B: 'mov     eax, [eax]', 0x8CC770: 'push    4',
        0x8BAF96: 'mov     eax, [eax+4]', 0x8BA859: 'add     ecx, [ebp+arg_0]',
        0x8BA85F: 'mov     [edx+4], ecx',
        0x8BAC71: 'mov     ecx, offset unk_ACBD94', 0x8BAC7B: 'mov     [eax+0E10h], esi',
        0x8BACA4: 'cmp     ecx, [eax+0E10h]', 0x8BACAA: 'jnb     short loc_8BACEB',
        0x8BACCC: "imul    edx, 24h ; '$'", 0x8BACD1: 'mov     ecx, 9',
        0x8BACD8: 'rep movsd', 0x8BACDA: "push    24h ; '$'",
        0x8BACE9: 'jmp     short loc_8BAC8A',
        0x8C07B8: 'xor     eax, eax', 0x8C07BA: 'jz      short loc_8C07F6'}
    for va, expected in exact.items():
        assert instructions[va] == expected, (hex(va), instructions.get(va))
    # 对 cmp/sbb/neg 的 CF 与32位寄存器动作进行小域独立模拟。
    keys = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    comparator_cases = []
    for lhs in keys:
        for rhs in keys:
            cf = int(lhs < rhs)
            after_sbb = (-cf) & 0xFFFFFFFF
            result = (-after_sbb) & 0xFFFFFFFF
            assert result == int(lhs < rhs)
            comparator_cases.append([lhs, rhs, result])
    assert sorted(keys) == [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    assert 100*36+4 == 3604 == 0x385*4
    assert 4+3604 == 3608 == 0x386*4
    assert 12+3608+4 == 3624 == 0xE28
    pair_limit, node_limit = 0xFFFFFFFF//3608, 0xFFFFFFFF//3624
    assert pair_limit == 0x122A01 == 1190401 and node_limit == 1185145
    assert pair_limit*3624 > 0xFFFFFFFF
    assert ((pair_limit*3624) & 0xFFFFFFFF) == 19045928
    record100 = list(range(16+100*36, 16+101*36))
    assert record100[:4] == list(range(3616, 3620))
    assert record100[4:8] == list(range(3620, 3624))
    assert record100[8:] == list(range(3624, 3652))
    assert all(16+j*36+36 <= 3616 for j in range(100))
    # count101只有44+36*100字节正文时仍进入j100；原语不检剩余字节。
    packet_bytes, claimed_count = 44+36*100, 101
    assert packet_bytes == 3644 and 100 < claimed_count
    assert 44+36*claimed_count == 3680 > packet_bytes
    reader = 0xFFFFFFFE
    assert (reader+4) & 0xFFFFFFFF == 2
    for va in ['0x8baf70', '0x8ba830']:
        assert not any(i['text'].startswith(('cmp ', 'test ', 'j')) for i in functions[va]['assembly'])
    calls = {f['va']: {c['site']: c['implementation'] for c in f['calls']} for f in functions.values()}
    assert calls['0x8cc740']['0x8cc766'] == '0x8baf70'
    assert calls['0x8cc740']['0x8cc775'] == '0x8ba830'
    assert all(calls['0x8ba950'][site] == '0x8bc3a0' for site in ['0x8bac76', '0x8bac9c', '0x8bacc4'])
    review = json.loads((TOPIC/'函数审阅清单.json').read_text('utf-8'))
    assert {f['va'] for f in review['functions']} == set(functions)
    assert review['status_counts'] == {'仅桥接核对': 41, '局部语义审阅': 30, '仅导出': 6}
    for f in review['functions']:
        assert f['conclusion'] and f['unresolved']
        assert all((TOPIC/path).is_file() for path in f['review_sources'])
    for path in TOPIC.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    reproduced, validator = reproduce_author()
    return dict(ida_live=db is not None, disk_sha256=SHA, functions=len(functions), chunks=len(chunks),
                tail_chunks=len(tails), instruction_addresses=len(instructions), unique_thunks=len(thunks),
                byte_comparisons=comparisons, unique_verified_bytes=len(byte_map), distinct_ranges=len(ranges),
                windows=windows, comparator_cases=len(comparator_cases), record100_node_byte_range=[3616, 3651],
                record100_outside_allocation_bytes=28, pair_max_size=pair_limit, node_size_floor=node_limit,
                unchecked_node_multiply_wrap=19045928, author_outputs_reproduced=reproduced,
                author_validator=validator, mismatches=0,
                scope='静态声明块、观察窗口与明确局部契约；未执行畸形包，不证明实机可达性或全树异常安全。')


if __name__ == '__main__':
    result = audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
