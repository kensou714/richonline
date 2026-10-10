"""独审只读核对函数、颜色上下文、资源及有限模型；audit(db)不写文件。"""
import hashlib
import importlib.util
import json
import struct
import sys
from collections import Counter
from decimal import Decimal
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = ['color_functions.json', 'color_narrow.json']
OWNERS = {'0x8e4ff0': 22, '0x8ee7b0': 12, '0x8f8080': 12,
          '0x900cd0': 1, '0x901d30': 1, '0x904480': 4, '0x90a8f0': 1, '0x90d9b0': 8}


def read(name):
    return json.loads((HERE / name).read_text(encoding='utf-8-sig'))


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    count, optional = struct.unpack_from('<H', blob, pe+6)[0], struct.unpack_from('<H', blob, pe+20)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8) for i in range(count)]
    ranges, comparisons = {}, 0

    def disk(va, size):
        for _, rva, length, offset in sections:
            d = va-base-rva
            if 0 <= d and d+size <= length:
                return blob[offset+d:offset+d+size]
        raise AssertionError(('无PE后备', hex(va), size))

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and raw == disk(va, size) == bytes.fromhex(row['disk_hex'])
        assert row['matching'] is True
        assert (va, size) not in ranges or ranges[(va, size)] == raw
        ranges[(va, size)] = raw
        comparisons += 1
        return raw

    thunks, functions = {}, {}
    for name in SOURCES:
        source = read(name)
        assert source['disk_sha256'] == SHA
        for f in source['functions']:
            assert f['va'] not in functions
            functions[f['va']] = f
        for row in source['thunks']:
            raw = check(row)
            assert raw[0] == 0xe9 and int(row['va'], 16)+5+struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
            assert row['va'] not in thunks or thunks[row['va']] == row['target']
            thunks[row['va']] = row['target']
    data = read('color_data.json')
    assert data['disk_sha256'] == SHA and 'disk_hex' not in data['runtime_flag']
    for row in data['ranges']:
        raw = check(row)
        if row['va'] == '0xa305a0':
            assert struct.unpack('<d', raw)[0] == 16.0
        else:
            assert raw[0] == 0xe9 and int(row['va'], 16)+5+struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
            thunks[row['va']] = row['target']
    instructions = chunks_total = tails = declared_bytes = narrow_calls = function_refs = 0
    for f in functions.values():
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert len(declared) == len(f['declared_chunks'])
        assert {(s, e) for s, e, _ in declared} == {(int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges']+f['chunk_byte_ranges']:
            check(row)
        assembly = {int(i['va'], 16): i['text'] for i in f['assembly']}
        assert len(assembly) == len(f['assembly'])
        assert all(any(s <= a < e for s, e, _ in declared) for a in assembly)
        if db is not None:
            live = db.functions.get_at(int(f['va'], 16))
            assert live.start_ea == int(f['va'], 16) and live.end_ea == int(f['end_va'], 16)
            chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in chunks} == declared
            actual = {i.ea: db.instructions.get_disassembly(i) for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
            assert actual == assembly, ('完整汇编', f['va'])
            assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(live.start_ea)} == {(r['source'], r['kind']) for r in f['references']}
        for call in f['calls']:
            va = int(call['site'], 16)
            raw = disk(va, 6)
            if raw[0] == 0xe8:
                target = va+5+struct.unpack_from('<i', raw, 1)[0]
            elif raw[:2] == b'\xff\xd6':
                assert f['va'] == '0x8e0450' and call['site'] in {'0x8e0465', '0x8e0487'}
                assert disk(0x8e045e, 2) == b'\x8b\x35'
                target = struct.unpack('<I', disk(0x8e0460, 4))[0]
            else:
                assert raw[:2] == b'\xff\x15'
                target = struct.unpack_from('<I', raw, 2)[0]
            assert hex(target) == call['target'] and va in assembly
            for bridge in call['thunks']:
                assert bridge == hex(target)
                target = int(thunks[bridge], 16)
            assert hex(target) == call['implementation']
            narrow_calls += 1
        instructions += len(assembly)
        chunks_total += len(declared)
        declared_bytes += sum(e-s for s, e, _ in declared)
        tails += sum(not main for _, _, main in declared)
        function_refs += len(f['references'])
    calls = read('color_calls.json')
    assert calls['disk_sha256'] == SHA
    check(calls['entry'])
    assert disk(0x60c9a3, 5) == b'\xe9\xa8\x3a\x2d\x00'
    assert Counter(s['owner_va'] for s in calls['sites']) == OWNERS
    expected_refs = {(r['source_va'], r['target_va'], r['kind']) for r in calls['references']}
    assert len(expected_refs) == 62
    if db is not None:
        actual_refs = {(hex(x.from_ea), hex(target), int(x.type)) for target in [0x60c9a3, 0x8e0450] for x in db.xrefs.to_ea(target)}
        assert actual_refs == expected_refs
    strings = {row['va']: row['text'] for row in calls['strings']}
    assert len(strings) == 53
    for row in calls['strings']:
        assert check(row) == row['text'].encode('ascii')+b'\0'
    contexts, string_refs = {}, set()
    for site in calls['sites']:
        va = int(site['site'], 16)
        raw = disk(va, 5)
        assert raw[0] == 0xe8 and va+5+struct.unpack_from('<i', raw, 1)[0] == 0x60c9a3
        if db is not None:
            assert db.functions.get_at(va).start_ea == int(site['owner_va'], 16)
        for row in site['context']:
            raw = check(row)
            assert row['va'] not in contexts or contexts[row['va']] == row
            contexts[row['va']] = row
            for ref in row['data_refs']:
                assert raw[0] == 0x68 and len(raw) == 5 and struct.unpack_from('<I', raw, 1)[0] == int(ref['target_va'], 16)
                assert strings[ref['target_va']] == ref['text']
                string_refs.add((row['va'], ref['target_va']))
    if db is not None:
        for va, row in contexts.items():
            address = int(va, 16)
            ins = list(db.instructions.get_between(address, address+row['size']))
            assert len(ins) == 1 and ins[0].ea == address and ins[0].size == row['size']
            assert db.instructions.get_disassembly(ins[0]) == row['text']
            actual = {(va, hex(x.to_ea)) for x in db.xrefs.from_ea(address) if hex(x.to_ea) in strings}
            assert actual == {(va, r['target_va']) for r in row['data_refs']}
        for (va, size), raw in ranges.items():
            assert db.bytes.get_bytes_at(va, size) == raw
    review = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8-sig'))['functions']
    levels = dict(Counter(r['status'] for r in review))
    assert {r['va'] for r in review} == set(functions) and levels == {'主体已审阅': 5, '局部已审阅': 3}
    assert all(r['scope'] and r['conclusion'] and r['unknown'] for r in review)
    call_reviews = json.loads((HERE.parent / '调用点审阅清单.json').read_text(encoding='utf-8-sig'))['sites']
    assert len(call_reviews) == 61 and {r['site'] for r in call_reviews} == {s['site'] for s in calls['sites']}
    assert all(r['status'] == '调用点局部已审阅' for r in call_reviews)
    assert Counter(r['kind'] for r in call_reviews) == {'direct': 33, 'style': 28}
    assert disk(0x8e1c40, 22).hex() == '8b4424088b5424048b4c240c8d0480894cc220c20c00'
    ordered = sorted(contexts.values(), key=lambda r: int(r['va'], 16))
    for reviewed in call_reviews:
        site = int(reviewed['site'], 16)
        after = [r for r in ordered if site < int(r['va'], 16) < site+40]
        if reviewed['kind'] == 'direct':
            stores = [bytes.fromhex(r['idb_hex']) for r in after
                      if bytes.fromhex(r['idb_hex'])[0] == 0x89]
            assert stores
            raw = stores[0]
            mod, source, base_register = raw[1] >> 6, (raw[1] >> 3) & 7, raw[1] & 7
            assert source == 0 and base_register != 4 and mod in (1, 2)
            offset = struct.unpack('<b' if mod == 1 else '<i', raw[2:])[0]
            assert offset == reviewed['offset'], reviewed['site']
        else:
            setters = [r for r in after if bytes.fromhex(r['idb_hex'])[0] == 0xe8
                       and int(r['va'], 16)+5+struct.unpack('<i', bytes.fromhex(r['idb_hex'])[1:])[0] == 0x610b6b]
            assert len(setters) == 1
            setter = int(setters[0]['va'], 16)
            previous = [r for r in ordered if site < int(r['va'], 16) < setter]
            pushes = [bytes.fromhex(r['idb_hex']) for r in previous
                      if bytes.fromhex(r['idb_hex'])[0] in range(0x50, 0x58)
                      or bytes.fromhex(r['idb_hex'])[0] == 0x6a]
            assert len(pushes) == 3 and pushes[0] == b'\x50'
            assert pushes[1] == bytes([0x6a, reviewed['state']])
            assert len(pushes[2]) == 1
            style_register = pushes[2][0]-0x50
            candidates = [bytes.fromhex(r['idb_hex']) for r in ordered
                          if int(r['va'], 16) < setter and bytes.fromhex(r['idb_hex'])[0] == 0x8d
                          and (bytes.fromhex(r['idb_hex'])[1] >> 3) & 7 == style_register]
            assert candidates
            raw = candidates[-1]
            mod, base_register = raw[1] >> 6, raw[1] & 7
            assert base_register != 4 and mod in (1, 2)
            offset = struct.unpack('<b' if mod == 1 else '<i', raw[2:])[0]
            assert offset == reviewed['base_offset'], reviewed['site']
            assert reviewed['offset'] == offset+40*reviewed['state']+32
    for path in HERE.parent.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    spec = importlib.util.spec_from_file_location('independent_color_model', HERE.parent / '颜色模型.py')
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    position_cases = 0
    for length in range(1, 33):
        for position in range(length):
            for byte in range(1, 128):
                text = '0x'+'0'*position+chr(byte)+'0'*(length-position-1)
                digit = int(chr(byte), 16) if chr(byte) in '0123456789abcdefABCDEF' else 0
                expected = digit << (28-4*position) if position < 8 else 0
                assert model.parse_hex(text) == expected
                position_cases += 1
    for text in ['0', '1.9', '-1.9', '2147483647', '-2147483648', '+12.25']:
        assert model.parse_decimal_subset(text) == int(Decimal(text)) & 0xffffffff
    assert model.parse_hex(b'0x1\0ffff') == 0x10000000
    assert model.parse_hex(b'0x1\0\xff') == 0x10000000
    assert model.parse_hex('0x1\0\u4e2d') == 0x10000000
    rejected_cases = 0
    for value in [b'0x\xff', b'0x1\x80', '0x\u4e2d']:
        try:
            model.parse_hex(value)
        except (ValueError, UnicodeEncodeError):
            rejected_cases += 1
        else:
            raise AssertionError(('模型域外非ASCII输入被接受', repr(value)))
    resource_items = 0
    for saved in read('resource_samples.json')['records']:
        raw = (ROOT / saved['source']).read_bytes()
        assert len(raw) == saved['source_bytes'] and hashlib.sha256(raw).hexdigest() == saved['source_sha256']
        plain = bytes((b-b'RichNet'[i%7]) & 255 for i, b in enumerate(raw))
        assert len(plain) == saved['decoded_bytes'] and hashlib.sha256(plain).hexdigest() == saved['decoded_sha256']
        found = []
        def display(raw):
            return raw.decode('ascii') if raw.isascii() else 'hex:'+raw.hex()
        section, fields = None, {}
        for line_no, line in enumerate(plain.split(b'\n'), 1):
            stripped = line.strip()
            if stripped.startswith(b'[') and stripped.endswith(b']'):
                section, fields = display(stripped[1:-1]), {}
            elif b'=' in line and not stripped.startswith((b'//', b';')):
                key, value = [display(p.strip()) for p in line.split(b'=', 1)]
                fields[key] = value
                if key.lower().endswith('color'):
                    found.append(dict(section=section, line=line_no, key=key, value=value,
                                      raw_line=display(line), raw_line_hex=line.hex(), prior_fields=dict(fields)))
        assert found == saved['colors']
        for row in found:
            assert len(row['value']) == 10 and row['value'].startswith('0x')
            assert model.parse_hex(row['value']) == int(row['value'], 16)
        resource_items += len(found)
    union = []
    for a, n in sorted(ranges):
        if union and a <= union[-1][1]:
            union[-1][1] = max(union[-1][1], a+n)
        else:
            union.append([a, a+n])
    return dict(exe_sha256=SHA, functions=len(functions), complete_chunks=chunks_total,
                non_main_chunks=tails, assembly_entries=instructions, declared_bytes=declared_bytes,
                unique_thunks=len(thunks), narrow_calls=narrow_calls, function_references=function_refs,
                color_calls=61, owner_contexts=8, context_instructions=len(contexts), strings=len(strings),
                string_references=len(string_refs), byte_comparisons=comparisons, unique_ranges=len(ranges),
                union_bytes=sum(b-a for a,b in union), review_levels=levels, position_cases=position_cases,
                resource_items=resource_items, live_ida_checked=db is not None, mismatches=0,
                storage_sites_checked=len(call_reviews),
                non_ascii_rejections=rejected_cases,
                scope='局部PE与保存原证/资源/有限模型核对；不执行EXE或宣称数学核心及UI owner完整闭合。')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    lines = []
    for name in SOURCES:
        for f in read(name)['functions']:
            lines.extend(['// '+f['va']+' '+f['name'], '// '+'-'*76])
            lines.extend('// '+i['va']+' '+i['text'] for i in f['assembly'])
    contexts = {}
    for site in read('color_calls.json')['sites']:
        for row in site['context']:
            contexts[row['va']] = row['text']
    lines.extend(['//', '// 全部颜色调用点上下文（按地址去重；不是完整owner）'])
    lines.extend('// '+va+' '+text for va, text in sorted(contexts.items(), key=lambda r: int(r[0], 16)))
    (HERE / 'independent_assembly.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))
