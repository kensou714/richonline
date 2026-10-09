"""独立从当前磁盘 PE、原资源和导出原证核对；不访问或改写 IDB。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
def load(name):
    return json.loads((BASE/name).read_text('utf-8'))
def digest(data):
    return hashlib.sha256(data).hexdigest()
pe = (ROOT/'RnClient.exe').read_bytes()
assert digest(pe) == SHA
nt = struct.unpack_from('<I', pe, 0x3C)[0]
optional = nt + 24
image_base = struct.unpack_from('<I', pe, optional + 28)[0]
headers_size = struct.unpack_from('<I', pe, optional + 60)[0]
section_at = optional + struct.unpack_from('<H', pe, nt + 20)[0]
sections = []
for i in range(struct.unpack_from('<H', pe, nt + 6)[0]):
    virtual_size, rva, raw_size, raw_at = struct.unpack_from('<IIII', pe, section_at + 40*i + 8)
    sections.append((image_base+rva, raw_size, raw_at))
def disk(va, size):
    if image_base <= va and va+size <= image_base+headers_size:
        return pe[va-image_base:va-image_base+size]
    for start, raw_size, raw_at in sections:
        if start <= va and va+size <= start+raw_size:
            return pe[raw_at+va-start:raw_at+va-start+size]
    return None
checks = Counter()
def check_bytes(r):
    blob = disk(int(r['va'], 16), r['size'])
    assert blob is not None
    assert blob.hex() == r['idb_hex'] == r['disk_hex']
    assert r['matching'] is True
    checks['byte_records'] += 1
    checks['byte_record_total_bytes'] += len(blob)

raw = [load('functions_raw.json'), load('caller_functions.json')]
functions = [f for source in raw for f in source['functions']]
assert len(functions) == len({f['va'] for f in functions}) == 31
for source in raw:
    assert source['disk_sha256'] == SHA
    for thunk in source['thunks']:
        check_bytes(thunk)
        a = int(thunk['va'], 16)
        b = disk(a, 5)
        assert b[0] == 0xE9 and (a+5+struct.unpack_from('<i', b, 1)[0]) & 0xFFFFFFFF == int(thunk['target'], 16)
for f in functions:
    assert f['bytes_match_disk'] is True
    for name in ['byte_ranges', 'chunk_byte_ranges']:
        for r in f[name]:
            check_bytes(r)
    for chunk, record in zip(f['declared_chunks'], f['chunk_byte_ranges']):
        assert chunk['start_va'] == record['va']
        assert int(chunk['end_va'], 16)-int(chunk['start_va'], 16) == record['size']
    for ins in f['assembly']:
        a = int(ins['va'], 16)
        assert any(int(c['start_va'], 16) <= a < int(c['end_va'], 16) for c in f['declared_chunks'])
    checks['instructions'] += len(f['assembly'])
    checks['chunks'] += len(f['declared_chunks'])
    checks['chunk_bytes'] += sum(r['size'] for r in f['chunk_byte_ranges'])

nav = load('navigation_data.json')
assert nav['disk_sha256'] == SHA
assert [len(t['references']) for t in nav['targets']] == [25, 5, 6, 48, 1, 1, 1]
for target in nav['targets']:
    check_bytes(target['thunk'])
    for ref in target['references']:
        check_bytes(ref['bytes'])
        a = int(ref['site'], 16)
        b = disk(a, 5)
        assert b[0] == 0xE8
        assert (a+5+struct.unpack_from('<i', b, 1)[0]) & 0xFFFFFFFF == int(target['target'], 16)
        assert ref['function'] is not None
        for context in ref['context']:
            check_bytes(context['bytes'])
        checks['navigation_calls'] += 1
for r in nav['data_records']:
    if r['disk_hex'] is None:
        assert disk(int(r['va'], 16), r['size']) is None and r['matching'] is None
        checks['unbacked_data'] += 1
    else:
        check_bytes(r)
        if 'ascii' in r:
            assert bytes.fromhex(r['disk_hex']) == r['ascii'].encode('ascii') + b'\0'

resources = load('resources.json')
decoded = {}
for r in resources:
    original = (ROOT/r['path']).read_bytes()
    assert len(original) == r['source_size'] and digest(original) == r['source_sha256']
    key, packed = original[0], original[1:]
    packed = bytes((v-key) & 255 for v in packed)
    output_size, compressed_size = struct.unpack_from('<II', packed)
    assert key == r['key'] and compressed_size == r['compressed_size'] == len(packed)-8
    plain = lzokay.decompress(packed[8:], output_size)
    assert output_size == r['decoded_size'] == len(plain)
    assert digest(plain) == r['decoded_sha256']
    assert plain == (BASE/(Path(r['path']).name+'.decoded.bin')).read_bytes()
    decoded[Path(r['path']).name] = plain
    if 'entries' in r:
        values = [(m.start(1), m.group(1).removesuffix(b'\r')) for m in re.finditer(rb'(?m)^str[ \t]*=[ \t]*(.*)\r?$', plain)]
        assert len(values) == r['section_count'] == len(r['entries'])
        for (at, value), entry in zip(values, r['entries']):
            assert at == entry['offset'] and value.hex() == entry['bytes'] and len(value) == entry['length']
        assert r['empty_entries'] == 0 and r['over_slot_entries'] == 0
        assert r['cp950_roundtrip'] == sum(v.decode('cp950').encode('cp950') == v for _, v in values)
        checks['filter_entries'] += len(values)
    checks['resources'] += 1
table = decoded['ChsTb.kpd']
assert len(table) == 0x18964
tables = resources[-1]['tables']
assert [(t['rows'], t['cols']) for t in tables] == [(87, 94), (89, 191)]
for t, low in zip(tables, [0xA1, 0x40]):
    for index, record in enumerate(t['entries']):
        row, col = divmod(index, t['cols'])
        at = t['offset']+4*index
        source = bytes([0xA1+row, low+col])
        assert record['offset'] == at and record['source'] == source.hex() == record['grid_input']
        assert table[at:at+2] == source and table[at+2:at+4].hex() == record['target']
        checks['mapping_records'] += 1

# 以连续整数区间集合独立生成接受域，再通过行列坐标检查索引和真实源记录。
boundaries = load('mapping_boundary.json')
expected = [(20412, 12798, 12731), (21949, 5460, 5460)]
for index, (ranges, start, cols, low, limit) in enumerate([
    ([(0xA1A1, 0xA9FE), (0xB0A1, 0xF7FE)], 0, 94, 0xA1, 0x7FC8),
    ([(0xA140, 0xA3FE), (0xA440, 0xC67E), (0xC940, 0xF9FE)], 0x7FC8, 191, 0x40, 0x18964)]):
    accepted = set().union(*(set(range(a, b+1)) for a, b in ranges))
    invalid, aliases, outside = 0, 0, []
    for value in sorted(accepted):
        hi, lo = value >> 8, value & 255
        slot = (hi-0xA1)*cols+(lo-low)
        at = start+slot*4
        invalid += not (low <= lo <= 0xFE)
        if at < start or at+4 > limit:
            outside.append(dict(input=hex(value), offset=at))
        else:
            aliases += table[at:at+2] != bytes([hi, lo])
    b = boundaries[index]
    assert (len(accepted), invalid, aliases) == expected[index]
    assert (len(accepted), invalid, aliases) == (b['accepted'], b['invalid_tail_accepted'], b['source_grid_alias_count'])
    assert outside == b['outside_region']
assert boundaries[0]['outside_region'] == [dict(input=hex(v), offset=-268+4*(v-0xA200)) for v in range(0xA200, 0xA243)]
assert boundaries[1]['outside_region'] == []

simulation = load('simulation.json')
assert [r['result']['output'] for r in simulation['filter_cases']] == ['2a2a6300', '2a2a2a00', '41626300', '7800', '8100', '81616200', '616200']
assert simulation['filter_cases'][3]['result']['steps'][0]['advance'] == 0
assert simulation['filter_cases'][4]['result']['steps'][0]['advance'] == 2
assert [(r['source_decode_success'], r['target_decode_success'], r['table_lookup_roundtrip_equal']) for r in simulation['table_surveys']] == [(7445, 7385, 6988), (13752, 13752, 6929)]
for index, (t, source_codec, target_codec) in enumerate(zip(tables, ['gb2312', 'cp950'], ['cp950', 'gb2312'])):
    valid_source = valid_target = roundtrip = 0
    for record in t['entries']:
        source, target = bytes.fromhex(record['source']), bytes.fromhex(record['target'])
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
        hi, lo = target
        at = (0x7FC8+(hi-0xA1)*764+(lo-0x40)*4) if index == 0 else ((hi-0xA1)*376+(lo-0xA1)*4)
        if hi >= 0x40 and lo >= 0x40 and 0 <= at and at+4 <= len(table):
            roundtrip += table[at+2:at+4] == source
    survey = simulation['table_surveys'][index]
    assert (valid_source, valid_target, roundtrip) == (survey['source_decode_success'], survey['target_decode_success'], survey['table_lookup_roundtrip_equal'])
assert table[2::4].count(0) == 0 and table[3::4].count(0) == 0
assert sum(r['target'] == 'a140' for r in tables[0]['entries']) == 1136
assert sum(r['target'] == 'a1a1' for r in tables[1]['entries']) == 6548
for example in simulation['mapping_examples']:
    source = bytes.fromhex(example['source_hex'])
    assert source == example['input'].encode('gb2312')
    mapped = bytearray()
    for hi, lo in zip(source[0::2], source[1::2]):
        row, col = hi-0xA1, lo-0xA1
        mapped.extend(table[(row*94+col)*4+2:(row*94+col)*4+4])
    assert mapped.hex() == example['target_hex'] and mapped.decode('cp950') == example['target_cp950']

assembly = {int(f['va'], 16): '\n'.join(i['text'] for i in f['assembly']) for f in functions}
for va, required in {
    0x818EA0: ['0A1A1h', '0A9FEh', '0B0A1h', '0F7FEh'],
    0x818F10: ['0A140h', '0A3FEh', '0A440h', '0C67Eh', '0C940h', '0F9FEh'],
    0x818FA0: ['178h'], 0x8190B0: ['2FCh'],
    0x818D70: ['7FC8h', '1099Ch', '18964h'],
    0x64C510: ['shl', '6', '40h'], 0x64C770: ['shl', '6', '40h'],
}.items():
    for token in required:
        assert token in assembly[va], (hex(va), token)
parser_ins = {i['va']: i['text'] for f in functions if f['va'] == '0x8198e0' for i in f['assembly']}
assert 'byte ptr [edx], 0' in parser_ins['0x819988']
assert '[ebp+arg_4]' in parser_ins['0x8199f4']
assert int('819988', 16) < int('8199f4', 16)
review = load('function_review.json')
assert review['counts'] == {'部分分析': 9, '局部语义已审阅': 22}
assert {f['va'] for f in review['functions']} == {f['va'] for f in functions}
for f in review['functions']:
    assert f['status'] == f['review_status'] and f['full_dependency_closure'] is False
    assert f['conclusion'] and f['unknown'] and all((BASE/p).exists() for p in f['evidence'])
    assert bool(f['reviewed_chunks']) == (f['review_status'] == '局部语义已审阅')
docs = sorted(BASE.parent.glob('*.txt'))
for path in docs:
    assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
result = dict(status='通过', disk_sha256=SHA, functions=31, review_counts=review['counts'],
    documents=len(docs), checks=dict(checks), forward_negative_inputs=67,
    boundary_expected=expected, caveat='字节和离线条件校验；不证明网络可达性或实机异常资源表现')
(BASE/'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=True))
