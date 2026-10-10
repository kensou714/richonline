"""独立核对 A6779C 专题原证；不写入原证或索引。"""
import collections
import hashlib
import json
import re
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
RAW = json.loads((HERE / 'global_refs_raw.json').read_text(encoding='utf-8'))
INDEX = json.loads((HERE / 'event_index.json').read_text(encoding='utf-8'))
IMAGE = (ROOT / 'RnClient.exe').read_bytes()
PE = struct.unpack_from('<I', IMAGE, 0x3C)[0]
assert IMAGE[:2] == b'MZ' and IMAGE[PE:PE + 4] == b'PE\0\0'
assert struct.unpack_from('<H', IMAGE, PE + 24)[0] == 0x10B
BASE = struct.unpack_from('<I', IMAGE, PE + 52)[0]
TABLE = PE + 24 + struct.unpack_from('<H', IMAGE, PE + 20)[0]
SECTIONS = []
for n in range(struct.unpack_from('<H', IMAGE, PE + 6)[0]):
    at = TABLE + n * 40
    name = IMAGE[at:at + 8].rstrip(b'\0').decode('ascii')
    virtual, rva, raw_size, file_off = struct.unpack_from('<4I', IMAGE, at + 8)
    SECTIONS.append((name, virtual, rva, raw_size, file_off))


def disk(ea, size):
    matches = [(name, file_off + ea - BASE - rva) for name, _, rva, raw_size, file_off in SECTIONS
               if BASE + rva <= ea and ea + size <= BASE + rva + raw_size]
    assert len(matches) == 1, (hex(ea), size, matches)
    name, offset = matches[0]
    return name, IMAGE[offset:offset + size]


def block(row):
    ea = int(row['va'], 16)
    size = row['size']
    assert int(row['end'], 16) == ea + size
    name, data = disk(ea, size)
    assert data.hex() == row['ida_hex'] == row['disk_hex']
    assert hashlib.sha256(data).hexdigest() == row['sha256']
    return name


def main():
    digest = hashlib.sha256(IMAGE).hexdigest()
    assert digest == RAW['disk_sha256'] == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    for row in RAW['globals'][:3]:
        assert disk(int(row['target'], 16), 2)[1] == b'\xff\xff'
        block(row['bytes'])
    for row in RAW['refs']:
        assert row['site_is_instruction'] and not row['iscode']
        assert block(row['bytes']) == '.text'
        assert row['bytes']['ida_hex'] == row['instruction']['hex']
        assert row['site'] == row['instruction']['va']
    for row in RAW['windows']:
        assert block(row['block']) == '.text'
        lo, hi = int(row['block']['va'], 16), int(row['block']['end'], 16)
        assert lo <= int(row['site'], 16) < hi
        for ins in row['instructions']:
            ea = int(ins['va'], 16)
            assert lo <= ea and ea + ins['size'] <= hi
            assert disk(ea, ins['size'])[1].hex() == ins['hex']

    refs = RAW['refs']
    by_site_target = {(r['site'], r['target']): r for r in refs}
    assert len(by_site_target) == len(refs)
    counts = collections.Counter((r['target'], r['xref_type']) for r in refs)
    calls = [r for r in refs if r['target'] in ('0xacb864', '0xacb868') and r['xref_type'] == 3]
    assert len(calls) == 131
    assert collections.Counter(r['target'] for r in calls) == {'0xacb864': 93, '0xacb868': 38}
    assert len({r['owner'] for r in refs if r['owner']}) == 122
    assert len(RAW['windows']) == 135
    by_window = {w['site']: w for w in RAW['windows']}
    assert len(by_window) == 135
    events = {e['site']: e for e in INDEX['events']}
    assert len(events) == len(calls)
    assert set(events) == {r['site'] for r in calls}
    group_counts = collections.Counter()
    order_failures = []
    for call in calls:
        site, event = call['site'], events[call['site']]
        assert event['owner'] == call['owner'] and event['callback'] == call['target']
        data = bytes.fromhex(call['instruction']['hex'])
        assert data == b'\xff\x15' + struct.pack('<I', int(call['target'], 16)), site
        window = by_window[site]
        positions = [i for i, ins in enumerate(window['instructions']) if ins['va'] == site]
        assert len(positions) == 1 and positions[0] > 0
        push = window['instructions'][positions[0] - 1]
        assert push['va'] == event['category_push']
        encoded = bytes.fromhex(push['hex'])
        if len(encoded) == 2 and encoded[0] == 0x6A:
            category = struct.unpack('<b', encoded[1:])[0]
        elif len(encoded) == 5 and encoded[0] == 0x68:
            category = struct.unpack('<i', encoded[1:])[0]
        else:
            raise AssertionError((site, encoded.hex()))
        assert category == event['category'], (site, category, event['category'])
        if not event['payload_read']:
            assert site == '0x829faa' and event['fields'] == {}
            continue
        fields = event['fields']
        assert set(fields) == {'0xa6779c', '0xa6779e', '0xa677a0'}
        starts = []
        for target in ('0xa6779c', '0xa6779e', '0xa677a0'):
            field = fields[target]
            ref = by_site_target[(field['site'], target)]
            assert ref['xref_type'] == 2 and ref['owner'] == call['owner']
            assert ref['instruction']['text'] == field['text']
            starts.append(int(field['site'], 16))
        payload = by_site_target[(event['payload_read'], '0xa677a0')]
        assert payload['xref_type'] == 3 and payload['owner'] == call['owner']
        prior_first_reads = [r for r in refs if r['target'] == '0xa6779c'
                             and r['xref_type'] == 3 and r['owner'] == call['owner']
                             and starts[2] < int(r['site'], 16) < int(event['payload_read'], 16)]
        assert prior_first_reads, site
        if not (starts[0] < starts[1] < starts[2] < int(event['payload_read'], 16) < int(site, 16)):
            order_failures.append(site)
        values = []
        for target in ('0xa6779c', '0xa6779e', '0xa677a0'):
            text = fields[target]['text']
            match = re.search(r',\s*(0FFFFh|0FFFEh|1|ax)$', text, re.IGNORECASE)
            assert match, (site, target, text)
            values.append(match.group(1).upper().removeprefix('0'))
        group_counts['/'.join(values)] += 1
    assert not order_failures, order_failures
    assert sum(group_counts.values()) == 130
    assert len({e['category'] for e in events.values()}) == 73
    undeclared = sorted(site for site, e in events.items() if e['owner'] is None)
    assert len(undeclared) == 8
    assert undeclared == sorted(['0x82d892', '0x840bd1', '0x8485fe', '0x8486ae',
                                 '0x84946e', '0x85494e', '0x855be5', '0x855c2f'])

    pointers = {}
    for target in ('0xacb864', '0xacb868'):
        ptr_refs = [r for r in refs if r['target'] == target and r['xref_type'] == 2]
        assert len(ptr_refs) == 2
        for r in ptr_refs:
            data = bytes.fromhex(r['instruction']['hex'])
            assert len(data) == 10 and data[:2] == b'\xc7\x05'
            assert struct.unpack_from('<I', data, 2)[0] == int(target, 16)
            pointers[r['site']] = hex(struct.unpack_from('<I', data, 6)[0])
    assert pointers == {'0x6be0e8': '0x60c5e3', '0x6be0f2': '0x61029c',
                        '0x6be210': '0x0', '0x6be21a': '0x0'}
    thunks = {}
    for ea in (0x60C5E3, 0x61029C):
        _, data = disk(ea, 5)
        assert data[0] == 0xE9
        thunks[hex(ea)] = hex(ea + 5 + struct.unpack_from('<i', data, 1)[0])
    assert thunks == {'0x60c5e3': '0x6be2e0', '0x61029c': '0x6be8d0'}

    checklist = (HERE.parent / '03_逐函数分级清单.txt').read_text(encoding='utf-8')
    declared_section = checklist.split('// 无 IDA 函数 owner：', 1)[0]
    listed = {int(m.group(1), 16): m.group(2)
              for m in re.finditer(r'^// ([0-9A-F]{6}) / (.*?) / ', declared_section, re.MULTILINE)}
    owners = {int(r['owner'], 16) for r in refs if r['owner'] and r['owner'] not in ('0x6be090', '0x6be1c0')}
    assert set(listed) == owners
    reviews = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert reviews['pe_sha256'] == digest and reviews['declared_functions'] == 122
    assert len(reviews['functions']) == 122
    all_owners = {r['owner'] for r in refs if r['owner']}
    assert {row['va'] for row in reviews['functions']} == all_owners
    referenced_events = set()
    for row in reviews['functions']:
        assert row['status'] and row['conclusion'] and row['boundary']
        assert 'wire_type' in row['boundary'] or row['va'] in ('0x6be090', '0x6be1c0')
        for ref in row['evidence']:
            if ref == '证据/validation.json':
                continue
            match = re.fullmatch(r'证据/(global_refs_raw|event_index).json/(windows|events)/(\d+)', ref)
            assert match, ref
            source, kind, number = match.groups()
            assert (source, kind) in (('global_refs_raw', 'windows'), ('event_index', 'events'))
            item = RAW['windows'][int(number)] if kind == 'windows' else INDEX['events'][int(number)]
            assert item['owner'] == row['va'], (row['va'], ref)
            if kind == 'events':
                assert item['site'][2:].upper() in row['conclusion']
                assert str(item['category']) in row['conclusion']
                referenced_events.add(item['site'])
    assert referenced_events == {e['site'] for e in INDEX['events'] if e['owner']}
    undeclared_rows = reviews['undeclared_call_sites']
    assert len(undeclared_rows) == 8
    assert {row['site'] for row in undeclared_rows} == set(undeclared)
    for row in undeclared_rows:
        event = events[row['site']]
        assert event['owner'] is None and event['category'] == row['category']
        assert event['callback'] == row['callback']
        number = int(row['evidence'].rsplit('/', 1)[1])
        assert RAW['windows'][number]['site'] == row['site']
        assert 'status' not in row and 'conclusion' not in row
    report = {
        'status': 'PASS', 'disk_sha256': digest, 'ref_count': len(refs),
        'xref_counts': {f'{target}:{kind}': count for (target, kind), count in sorted(counts.items())},
        'callback_calls': dict(collections.Counter(r['target'] for r in calls)),
        'callback_category_count': len({e['category'] for e in events.values()}),
        'payload_groups_ordered': sum(group_counts.values()),
        'payload_shapes': dict(sorted(group_counts.items())),
        'declared_owner_count': len({r['owner'] for r in refs if r['owner']}),
        'review_manifest_functions': len(reviews['functions']),
        'review_manifest_events': len(referenced_events),
        'undeclared_calls': undeclared, 'pointer_writes': pointers, 'thunk_targets': thunks,
        'note': '离线静态复核；不证明控制流可达、线程安全或网络协议类别',
    }
    (HERE / 'independent_audit.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
