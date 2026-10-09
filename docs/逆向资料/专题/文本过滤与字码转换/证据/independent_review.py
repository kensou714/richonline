"""独立审阅保存原证、磁盘资源与可选实时 IDA；不写入作者证据或客户端。"""
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import runpy
import struct
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = Path(r'F:\大富翁online\Richonline')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def load(name):
    return json.loads((HERE/name).read_text('utf-8'))


def reproduce_outputs():
    saved_text, saved_bytes = Path.write_text, Path.write_bytes
    captured = {}

    def text(path, value, *args, **kwargs):
        captured[path.resolve()] = value
        return len(value)

    def binary(path, value):
        captured[path.resolve()] = bytes(value)
        return len(value)

    Path.write_text, Path.write_bytes = text, binary
    try:
        with redirect_stdout(io.StringIO()):
            for script in ['inspect_resources.py', 'simulate.py', 'build_review.py', 'validate.py']:
                runpy.run_path(str(HERE/script), run_name='__main__')
    finally:
        Path.write_text, Path.write_bytes = saved_text, saved_bytes
    for path, value in captured.items():
        if isinstance(value, bytes):
            assert value == path.read_bytes(), str(path)
        elif path.suffix == '.json':
            assert json.loads(value) == json.loads(path.read_text('utf-8')), str(path)
        else:
            assert value == path.read_text('utf-8'), str(path)
    return len(captured)


def audit(db=None):
    raw = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    optional = pe+24
    base = struct.unpack_from('<I', raw, optional+28)[0]
    headers = struct.unpack_from('<I', raw, optional+60)[0]
    section_at = optional+struct.unpack_from('<H', raw, pe+20)[0]
    sections = [struct.unpack_from('<IIII', raw, section_at+40*i+8)
                for i in range(struct.unpack_from('<H', raw, pe+6)[0])]

    def disk(va, size):
        if base <= va and va+size <= base+headers:
            return raw[va-base:va-base+size]
        for _, rva, raw_size, offset in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw_size:
                return raw[offset+delta:offset+delta+size]
        return None

    checks, address_ranges = Counter(), set()

    def check(row):
        va, size = int(row['va'], 16), row['size']
        expected = bytes.fromhex(row['idb_hex'])
        assert len(expected) == size
        actual = disk(va, size)
        if row['disk_hex'] is None:
            assert actual is None and row['matching'] is None
            checks['unbacked_comparisons'] += 1
        else:
            assert actual == expected == bytes.fromhex(row['disk_hex'])
            assert row['matching'] is True
            checks['disk_comparisons'] += 1
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == expected
        address_ranges.add((va, size))

    functions, instructions, chunks, thunks = {}, {}, set(), {}
    for filename in ['functions_raw.json', 'caller_functions.json']:
        source = load(filename)
        assert source['disk_sha256'] == SHA
        for f in source['functions']:
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main'])
                        for c in f['declared_chunks']}
            assert {(s, e) for s, e, _ in declared} == {
                (int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
            assert f['bytes_match_disk']
            for row in f['byte_ranges']+f['chunk_byte_ranges']:
                check(row)
            for i in f['assembly']:
                va = int(i['va'], 16)
                assert any(s <= va < e for s, e, _ in declared)
                assert any(int(r['va'], 16) <= va < int(r['va'], 16)+r['size'] for r in f['byte_ranges'])
                if va in instructions:
                    assert instructions[va] == i['text']
                instructions[va] = i['text']
            assert f['va'] not in functions
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
                calls = [{'site': hex(i.ea), 'target': hex(x.to_ea)}
                         for c in live_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)
                         for x in db.xrefs.from_ea(i.ea) if x.type in (16, 17)]
                assert calls == [{k: c[k] for k in ('site', 'target')} for c in f['calls']]
        for row in source['thunks']:
            check(row)
            va = int(row['va'], 16)
            code = bytes.fromhex(row['idb_hex'])
            assert len(code) == 5 and code[0] == 0xE9
            assert (va+5+struct.unpack_from('<i', code, 1)[0]) & 0xFFFFFFFF == int(row['target'], 16)
            if row['va'] in thunks:
                assert thunks[row['va']] == row
            thunks[row['va']] = row
    assert len(functions) == 31

    nav = load('navigation_data.json')
    assert nav['disk_sha256'] == SHA
    assert [len(t['references']) for t in nav['targets']] == [25, 5, 6, 48, 1, 1, 1]
    expected_implementations = [0x64C9E0, 0x64CAE0, 0x818FA0, 0x8190B0, 0x818D70, 0x64C510, 0x64C770]
    for target, implementation in zip(nav['targets'], expected_implementations):
        check(target['thunk'])
        va = int(target['target'], 16)
        assert va+5+struct.unpack_from('<i', disk(va, 5), 1)[0] == implementation
        if db is not None:
            assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(va)} == {
                (r['site'], r['kind']) for r in target['references']}
        for ref in target['references']:
            check(ref['bytes'])
            site = int(ref['site'], 16)
            code = disk(site, 5)
            assert ref['kind'] == 17 and code[0] == 0xE8
            assert site+5+struct.unpack_from('<i', code, 1)[0] == va
            assert any(c['va'] == ref['site'] and c['text'] == ref['disassembly'] for c in ref['context'])
            for context in ref['context']:
                check(context['bytes'])
            if db is not None:
                owner = db.functions.get_at(site)
                assert hex(owner.start_ea) == ref['function']
                arr = [i for c in db.functions.get_chunks(owner)
                       for i in db.instructions.get_between(c.start_ea, c.end_ea)]
                index = next(j for j, i in enumerate(arr) if i.ea == site)
                actual = [(hex(i.ea), db.instructions.get_disassembly(i)) for i in arr[max(0, index-10):index+5]]
                assert actual == [(c['va'], c['text']) for c in ref['context']]
            checks['navigation_calls'] += 1
    literals = {}
    for row in nav['data_records']:
        check(row)
        if 'ascii' in row:
            assert disk(int(row['va'], 16), row['size']) == row['ascii'].encode('ascii')+b'\0'
            literals[row['va']] = row['ascii']
    assert literals['0xa223dc'] == 'Data\\Filter.kpd'
    assert literals['0xa223ec'] == 'Data\\FilterN.kpd'
    assert 'Data\\FliterN.kpd' not in literals.values()
    startup = functions['0x623ee0']
    assert [c['implementation'] for c in startup['calls'] if c['target'] in ['0x603af6', '0x608a79']] == ['0x64c510', '0x64c770']

    resources, decoded = load('resources.json'), {}
    for row in resources:
        packed = (ROOT/row['path']).read_bytes()
        assert len(packed) == row['source_size'] and hashlib.sha256(packed).hexdigest() == row['source_sha256']
        key = packed[0]
        restored = bytes((byte-key) % 256 for byte in packed[1:])
        size, compressed = struct.unpack_from('<II', restored)
        assert key == row['key'] and compressed == row['compressed_size'] == len(restored)-8
        plain = lzokay.decompress(restored[8:], size)
        assert len(plain) == size == row['decoded_size']
        assert hashlib.sha256(plain).hexdigest() == row['decoded_sha256']
        name = Path(row['path']).name
        decoded[name] = plain
        assert plain == (HERE/(name+'.decoded.bin')).read_bytes()
        if 'entries' in row:
            parsed, at = [], 0
            for line in plain.splitlines(keepends=True):
                content = line.rstrip(b'\r\n')
                before, separator, after = content.partition(b'=')
                if separator and before.strip() == b'str':
                    trim = len(after)-len(after.lstrip(b' \t'))
                    parsed.append((at+len(before)+1+trim, after[trim:]))
                at += len(line)
            assert len(parsed) == len(row['entries']) == row['section_count']
            for (offset, value), entry in zip(parsed, row['entries']):
                assert offset == entry['offset'] and value.hex() == entry['bytes'] and len(value) == entry['length']
                for codec in ['cp950', 'gbk']:
                    try:
                        text = value.decode(codec)
                        assert text == entry[codec] and (text.encode(codec) == value) == entry[codec+'_roundtrip']
                    except UnicodeError:
                        assert entry[codec+'_roundtrip'] is False
                assert value.decode('cp950').encode('cp950') == value
                checks['filter_entries'] += 1
            assert max(len(v) for _, v in parsed) == row['max_entry_bytes']
        checks['resources'] += 1
    assert [r['section_count'] for r in resources[:3]] == [138, 467, 464]
    assert decoded['FilterN.kpd'] != decoded['FliterN.kpd']
    table = decoded['ChsTb.kpd']
    assert len(table) == 0x18964
    tables = resources[-1]['tables']
    surveys, boundary_results = [], []
    boundaries = load('mapping_boundary.json')
    parameters = [(0, 87, 94, 0xA1, 'gb2312', 'cp950', [(0xA1A1, 0xA9FE), (0xB0A1, 0xF7FE)]),
                  (0x7FC8, 89, 191, 0x40, 'cp950', 'gb2312', [(0xA140, 0xA3FE), (0xA440, 0xC67E), (0xC940, 0xF9FE)])]
    for index, (start, rows, cols, low, source_codec, target_codec, accepted_ranges) in enumerate(parameters):
        valid_source = valid_target = equal = 0
        t = tables[index]
        assert (t['offset'], t['rows'], t['cols'], len(t['entries'])) == (start, rows, cols, rows*cols)
        for record_index in range(rows*cols):
            hi, lo = 0xA1+record_index//cols, low+record_index % cols
            at = start+record_index*4
            source, target = table[at:at+2], table[at+2:at+4]
            r = t['entries'][record_index]
            assert source == bytes([hi, lo])
            assert (r['offset'], r['source'], r['grid_input'], r['target']) == (at, source.hex(), source.hex(), target.hex())
            checks['mapping_records'] += 1
            try:
                source.decode(source_codec)
            except UnicodeError:
                continue
            valid_source += 1
            try:
                target.decode(target_codec)
                valid_target += 1
            except UnicodeError:
                pass
            a, b = target
            back_at = 0x7FC8+(a-0xA1)*764+(b-0x40)*4 if index == 0 else (a-0xA1)*376+(b-0xA1)*4
            if min(target) >= 0x40 and 0 <= back_at and back_at+4 <= len(table):
                equal += table[back_at+2:back_at+4] == source
        surveys.append((valid_source, valid_target, equal))
        accepted = {v for lo_bound, hi_bound in accepted_ranges for v in range(lo_bound, hi_bound+1)}
        invalid = aliases = 0
        outside = []
        limit = start+rows*cols*4
        for v in sorted(accepted):
            hi, lo = divmod(v, 256)
            at = start+((hi-0xA1)*cols+lo-low)*4
            invalid += not low <= lo <= 0xFE
            if at < start or at+4 > limit:
                outside.append({'input': hex(v), 'offset': at})
            else:
                aliases += table[at:at+2] != bytes([hi, lo])
        row = boundaries[index]
        assert (len(accepted), invalid, aliases, outside) == (row['accepted'], row['invalid_tail_accepted'], row['source_grid_alias_count'], row['outside_region'])
        boundary_results.append((len(accepted), invalid, aliases, len(outside)))
    assert surveys == [(7445, 7385, 6988), (13752, 13752, 6929)]
    assert boundary_results == [(20412, 12798, 12731, 67), (21949, 5460, 5460, 0)]
    simulation = load('simulation.json')
    assert surveys == [(r['source_decode_success'], r['target_decode_success'], r['table_lookup_roundtrip_equal'])
                       for r in simulation['table_surveys']]
    for example in simulation['mapping_examples']:
        source = example['input'].encode('gb2312')
        mapped, returned = bytearray(), bytearray()
        assert source.hex() == example['source_hex']
        for hi, lo in zip(source[::2], source[1::2]):
            at = (hi-0xA1)*376+(lo-0xA1)*4
            mapped.extend(table[at+2:at+4])
        for hi, lo in zip(mapped[::2], mapped[1::2]):
            at = 0x7FC8+(hi-0xA1)*764+(lo-0x40)*4
            returned.extend(table[at+2:at+4])
        assert mapped.hex() == example['target_hex'] and mapped.decode('cp950') == example['target_cp950']
        assert returned == source and returned.hex() == example['back_hex'] and example['roundtrip'] is True
        checks['mapping_examples'] += 1

    def filter_model(data, words):
        buf, cursor, changed, steps = bytearray(data), 0, False, []
        while cursor < len(buf) and buf[cursor] != 0:
            advance, which = 1+(buf[cursor] >= 128), None
            for word_index, word in enumerate(words):
                # CRT scans Str1 through its first NUL or N bytes, then compares that span.
                span = 0
                while span < len(word):
                    assert cursor+span < len(buf)
                    span += 1
                    if buf[cursor+span-1] == 0:
                        break
                if bytes(buf[cursor:cursor+span]) == word[:span]:
                    buf[cursor:cursor+len(word)] = b'*'*len(word)
                    advance, which, changed = len(word), word_index, True
                    break
            steps.append(dict(offset=cursor, advance=advance, word=which))
            if advance == 0:
                return dict(output=buf.hex(), status='零长度命中导致不前进', steps=steps, changed=changed)
            cursor += advance
        return dict(output=buf.hex(), status='到达零终止' if cursor < len(buf) else '读过已提供缓冲区',
                    steps=steps, changed=changed)

    for case in simulation['filter_cases']:
        result = filter_model(bytes.fromhex(case['input_hex']), [bytes.fromhex(w) for w in case['words']])
        assert result == case['result']
        checks['filter_models'] += 1
    negative = boundaries[0]['outside_region']
    assert negative == [{'input': hex(v), 'offset': -268+4*(v-0xA200)} for v in range(0xA200, 0xA243)]
    addresses = [row['offset']+delta for row in negative for delta in [2, 3]]
    assert (min(addresses), max(addresses), len(addresses)) == (-266, -1, 134)
    expected_assembly = {
        0x819015: 'sub     eax, 0A1h', 0x819029: 'sub     edx, 0A1h',
        0x81903A: 'imul    eax, 178h', 0x819040: 'add     eax, [ebp+var_4]',
        0x81904F: 'mov     al, [eax+edx*4+2]', 0x81906F: 'mov     cl, [ecx+eax*4+3]',
        0x81914B: 'imul    eax, 2FCh', 0x819154: 'lea     edx, [ecx+eax+7FC8h]',
        0x819166: 'mov     dl, [edx+ecx*4+2]', 0x81918C: 'mov     dl, [edx+ecx*4+3]',
        0x9228E9: 'jecxz   short toend_0', 0x9228F4: 'repne scasb',
        0x9228F6: 'neg     ecx', 0x9228F8: 'add     ecx, ebx', 0x9228FF: 'repe cmpsb',
        0x6AABBB: 'push    1; BufferCount', 0x6AABC1: 'call    j___snprintf'}
    for va, text in expected_assembly.items():
        assert instructions[va] == text, (hex(va), instructions.get(va))
    for va, tokens in [(0x818EA0, ['0A1A1h', '0A9FEh', '0B0A1h', '0F7FEh', 'word_ABAA40']),
                       (0x818F10, ['0A140h', '0A3FEh', '0A440h', '0C67Eh', '0C940h', '0F9FEh', 'word_ABAA44'])]:
        assembly = '\n'.join(i['text'] for i in functions[hex(va)]['assembly'])
        assert all(token in assembly for token in tokens)
    review = load('function_review.json')
    assert review['counts'] == {'部分分析': 9, '局部语义已审阅': 22}
    assert {f['va'] for f in review['functions']} == set(functions)
    for f in review['functions']:
        assert f['status'] == f['review_status'] and f['full_dependency_closure'] is False
        assert f['conclusion'] and f['unknown'] and all((HERE/p).is_file() for p in f['evidence'])
    docs = list(HERE.parent.glob('*.txt'))
    for path in docs:
        assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    outputs = reproduce_outputs()
    return dict(ida_live=db is not None, exe_sha256=SHA, functions=len(functions), chunks=len(chunks),
                instruction_addresses=len(instructions), unique_thunks=len(thunks), checks=dict(checks),
                distinct_address_size_ranges=len(address_ranges), range_size_sum=sum(s for _, s in address_ranges),
                documents=len(docs), mapping_surveys=surveys, boundary_results=boundary_results,
                negative_target_relative_addresses=[min(addresses), max(addresses)], author_outputs_reproduced=outputs,
                mismatches=0, scope='保存声明块、调用点与局部字节算法；不证明网络可达性、异常资源实机表现或完整依赖闭合。')


if __name__ == '__main__':
    result = audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
