"""独立核查当前 PE、静态契约及有限模型；不执行或补丁客户端。"""
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import re
import runpy
import struct
import sys

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = Path(r'F:\大富翁online\Richonline')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def reproduce():
    saved, search = Path.write_text, list(sys.path)
    captured = {}
    def capture(path, text, *args, **kwargs):
        captured[path.resolve()] = text
        return len(text)
    try:
        sys.path.insert(0, str(TOPIC))
        Path.write_text = capture
        with redirect_stdout(io.StringIO()):
            for name in ['build_review.py', 'validate_conversion.py']:
                runpy.run_path(str(TOPIC/name), run_name='review')['main']()
    finally:
        Path.write_text, sys.path[:] = saved, search
    assert len(captured) == 3
    for path, text in captured.items():
        if path.suffix == '.json':
            assert json.loads(text) == json.loads(path.read_text('utf-8')), str(path)
        else:
            assert text == path.read_text('utf-8')
    return len(captured)


def audit(db=None):
    raw = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    pe = struct.unpack_from('<I', raw, 60)[0]
    base = struct.unpack_from('<I', raw, pe+52)[0]
    opt = struct.unpack_from('<H', raw, pe+20)[0]
    sections = [struct.unpack_from('<IIII', raw, pe+24+opt+40*i+8)
                for i in range(struct.unpack_from('<H', raw, pe+6)[0])]
    def disk(va, size):
        for _, rva, raw_size, at in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw_size:
                return raw[at+delta:at+delta+size]
        raise AssertionError((hex(va), size))
    comparisons, byte_map, spans = 0, {}, set()
    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        expected = bytes.fromhex(row['idb_hex'])
        assert len(expected) == size and disk(va, size) == expected
        if 'disk_hex' in row:
            assert row['disk_hex'] == expected.hex() and row['matching'] is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == expected
        for i, value in enumerate(expected):
            assert byte_map.get(va+i, value) == value
            byte_map[va+i] = value
        comparisons += 1
        spans.add((va, size))
    functions, thunks, instructions, chunks = {}, {}, {}, set()
    def function(f):
        if f['va'] in functions:
            assert functions[f['va']] == f
            return
        functions[f['va']] = f
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert {(s, e) for s, e, _ in declared} == {
            (int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
        for r in f['byte_ranges']+f['chunk_byte_ranges']:
            check(r)
        assert f['bytes_match_disk'] is True
        chunks.update((f['va'], s, e) for s, e, _ in declared)
        for i in f['assembly']:
            va = int(i['va'], 16)
            assert any(s <= va < e for s, e, _ in declared)
            assert instructions.get(va, i['text']) == i['text']
            instructions[va] = i['text']
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
    for name in ['seeds.json', 'classification_helpers.json', 'locale_update.json']:
        source = json.loads((HERE/name).read_text('utf-8'))
        assert source['disk_sha256'] == SHA
        for f in source['functions']:
            function(f)
        for r in source['thunks']:
            check(r)
            va, code = int(r['va'], 16), bytes.fromhex(r['idb_hex'])
            assert len(code) == 5 and code[0] == 0xE9
            assert va+5+struct.unpack_from('<i', code, 1)[0] == int(r['target'], 16)
            assert thunks.get(r['va'], r) == r
            thunks[r['va']] = r
    local = len(functions)
    manifest = json.loads((TOPIC/'函数审阅清单.json').read_text('utf-8'))
    assert manifest['disk_sha256'] == SHA
    for row in manifest['functions']:
        assert row['status'] and row['conclusion'] and row['unknown']
        for ref in row['evidence']:
            path, pointer = ref.split('#')
            data = json.loads((TOPIC/path).read_text('utf-8'))
            assert data['disk_sha256'] == SHA
            f = data['functions'][int(pointer.rsplit('/', 1)[1])]
            assert f['va'] == row['va']
            function(f)
    assert local == 5 and len(functions) == 7
    assert Counter(r['status'] for r in manifest['functions']) == {
        '静态契约已审阅': 3, '局部消费契约已审阅': 2, '既有专题审阅复核': 2}
    nav = json.loads((HERE/'navigation.json').read_text('utf-8'))
    for row in nav['spans']:
        check(row)
    assert len(nav['references']) == 582
    assert Counter(r['kind'] for r in nav['references']) == {17: 580, 19: 2}
    targets = {r['target'] for r in nav['references']}
    for r in nav['references']:
        va, target = int(r['site'], 16), int(r['target'], 16)
        code = disk(va, 5)
        assert code[0] == (0xE8 if r['kind'] == 17 else 0xE9)
        assert va+5+struct.unpack_from('<i', code, 1)[0] == target
        if db is not None:
            assert db.bytes.get_bytes_at(va, 5) == code
            owner = db.functions.get_at(va)
            assert (hex(owner.start_ea) if owner else None) == r['function']
    if db is not None:
        for target in targets:
            assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(int(target, 16))} == {
                (r['site'], r['kind']) for r in nav['references'] if r['target'] == target}
    exact = {
        0x91F80B: 'mov     eax, [eax+64h]', 0x91F827: 'cmp     dword ptr [edx+28h], 1',
        0x91F82B: 'jle     short loc_91F847', 0x91F82D: 'push    8', 0x91F847: 'push    8',
        0x91F832: 'movzx   ecx, byte ptr [eax]', 0x91F84C: 'movzx   ecx, byte ptr [eax]',
        0x91F888: "cmp     [ebp+var_10], 2Dh ; '-'", 0x91F88E: "cmp     [ebp+var_10], 2Bh ; '+'",
        0x91F8AD: "cmp     [ebp+var_10], 30h ; '0'", 0x91F8B3: "cmp     [ebp+var_10], 39h ; '9'",
        0x91F8DA: 'imul    ecx, 0Ah', 0x91F8DD: 'add     ecx, [ebp+var_10]', 0x91F900: 'neg     eax',
        0x9305C6: 'add     eax, 1', 0x9305C9: 'cmp     eax, 100h', 0x9305CE: 'jbe     short loc_9305EE',
        0x9305EB: 'jnz     short loc_9305EE', 0x9305ED: 'int     3; Trap to Debugger',
        0x9305F7: 'movzx   eax, word ptr [eax+ecx*2]', 0x9305FB: 'and     eax, [ebp+arg_8]',
        0x930671: 'ja      short loc_930688', 0x93067C: 'movzx   eax, word ptr [edx+eax*2]',
        0x9306A1: 'and     edx, 8000h', 0x9306F9: 'call    j____crtGetStringTypeA',
        0x92DE93: 'push    0Ch', 0x92DEA4: 'call    ___updatetlocinfo_lk',
        0x92DEB3: 'call    loc_92DEBA', 0x92DEBA: 'push    0Ch',
        0x92DEBC: 'call    j___unlock', 0x92DEC5: 'mov     eax, [ebp+var_1C]'}
    for va, expected in exact.items():
        assert instructions[va] == expected, (hex(va), instructions.get(va))
    conversion = '\n'.join(i['text'] for i in functions['0x91f800']['assembly'])
    assert not re.search(r'\b(?:jo|jno)\s', conversion)
    calls = {va: {c['implementation'] for c in f['calls']} for va, f in functions.items()}
    assert calls['0x91f950'] == {'0x91f800'}
    assert sum(r['size'] for r in functions['0x91f950']['chunk_byte_ranges']) == 17
    assert calls['0x91f800'] >= {'0x930960', '0x92de70', '0x9305c0', '0x930660'}
    assert '0x91f950' in calls['0x6daa10']
    assert all(((c+1) & 0xFFFFFFFF) <= 256 for c in range(256))
    assert ((-1+1) & 0xFFFFFFFF) <= 256
    assert all(((c+1) & 0xFFFFFFFF) > 256 for c in [-2, 256, 257, 0x7FFFFFFF, -0x80000000])

    model = runpy.run_path(str(TOPIC/'model_conversion.py'))
    table = model['ascii_classification']()
    assert {i for i, value in enumerate(table) if value & 8} == {9, 10, 11, 12, 13, 32}
    def oracle(data, classes):
        at = 0
        while at < len(data) and classes[data[at]] & 8:
            at += 1
        if at == len(data):
            raise ValueError('模型内存边界')
        suffix = data[at:]
        match = re.match(rb'[+-]?[0-9]+', suffix)
        if match is None:
            if suffix in (b'+', b'-'):
                raise ValueError('模型内存边界')
            return 0
        if match.end() == len(suffix):
            raise ValueError('模型内存边界')
        value = int(match.group()) % (1 << 32)
        return value if value < 1 << 31 else value-(1 << 32)
    cases = [b'', b'0', b'123', b'  \t-42x', b'+ 7', b'--7', b'-', b'abc', b'12abc', b'0x10', b'1.5',
             b'2147483647', b'2147483648', b'4294967295', b'4294967296', b'-2147483648', b'-2147483649', b'\x8012', b'\xef\xbc\x91']
    named = 0
    for source in cases:
        assert model['convert'](source+b'\0', table) == oracle(source+b'\0', table)
        named += 1
    arbitrary = 0
    for length in range(1, 101):
        digits = bytes(48+((i*7+length) % 10) for i in range(length))
        for sign in [b'', b'+', b'-']:
            for tail in [b'\0', b'x\0', b' \0']:
                data = b' \t'+sign+digits+tail
                assert model['convert'](data, table) == oracle(data, table)
                arbitrary += 1
    byte_cases = 0
    for c in range(256):
        data = bytes([c])+b'12\0'
        assert model['convert'](data, table) == oracle(data, table)
        byte_cases += 1
    alternate = table.copy()
    alternate[0xA0] = 8
    for classes in [table, alternate]:
        assert model['convert'](b'\xA012\0', classes) == oracle(b'\xA012\0', classes)
    for data in [b'', b'+', b'123']:
        for algorithm in [model['convert'], oracle]:
            try:
                algorithm(data, table)
            except ValueError:
                pass
            else:
                raise AssertionError('模型边界未拒绝')
    for path in TOPIC.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    reproduced = reproduce()
    return dict(ida_live=db is not None, disk_sha256=SHA, local_functions=local, reused_functions=2,
                functions=len(functions), declared_chunks=len(chunks), instruction_addresses=len(instructions),
                byte_comparisons=comparisons, unique_verified_bytes=len(byte_map), unique_spans=len(spans),
                attached_thunks=len(thunks), navigation_records=len(nav['references']), navigation_calls=580,
                navigation_e9=2, navigation_targets=len(targets), named_models=named, arbitrary_precision_models=arbitrary,
                all_leading_byte_models=byte_cases, locale_models=2, bounded_input_rejections=3,
                author_outputs_reproduced=reproduced, mismatches=0,
                scope='有限表驱动模型与静态字节契约；不是原机器码执行，不证明运行locale、所有消费者或异常作用域闭合。')


if __name__ == '__main__':
    result = audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
