"""离线检查证据一致性与审阅边界；不访问 IDA、不运行客户端。"""
import hashlib
import importlib.util
import json
import re
import struct
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def run():
    spec = importlib.util.spec_from_file_location('stock_export', BASE / 'export_ida.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == module.ST_SHA256
    read = module.disk_view(blob)
    review = json.loads((BASE / 'function_review.json').read_text('utf-8'))
    rows = review['functions']
    assert len(rows) == len({r['va'] for r in rows}) == 41
    assert all(r['full_dependency_closure'] is False for r in rows)
    assert sum(r['evidence_reused'] for r in rows) == 8
    assert Counter(r['status'] for r in rows) == {
        '局部语义已审阅': 30, '部分分析': 10, '复用已审阅': 1}
    selected = {}
    for row in rows:
        path = ROOT / 'docs/逆向资料' / row['evidence'][0]
        selected.setdefault(path, set()).add(int(row['va'], 16))
    data_count = 0
    checked_bytes = 0
    unmapped = []

    def check_identity(node):
        nonlocal data_count, checked_bytes
        if isinstance(node, list):
            for child in node:
                check_identity(child)
        elif isinstance(node, dict):
            if all(k in node for k in ('va', 'size', 'idb_hex', 'disk_hex', 'matching')):
                va, size = int(node['va'], 16), node['size']
                disk = read(va, size)
                live = bytes.fromhex(node['idb_hex'])
                assert len(live) == size
                if disk is None:
                    assert node['disk_hex'] is None and node['matching'] is None
                    unmapped.append(hex(va))
                else:
                    assert node['matching'] is True
                    assert live == disk == bytes.fromhex(node['disk_hex'])
                    checked_bytes += size
                data_count += 1
            for child in node.values():
                check_identity(child)

    functions = {}
    unique_thunks = set()
    hashes = {}
    for path, addresses in selected.items():
        data = json.loads(path.read_text('utf-8'))
        found = {int(f['va'], 16): f for f in data['functions']
                 if int(f['va'], 16) in addresses}
        assert set(found) == addresses
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        for va, f in found.items():
            assert f['bytes_match_disk'] is True
            check_identity(f['byte_ranges'])
            check_identity(f.get('chunk_byte_ranges', []))
            if 'declared_chunks' in f:
                actual = {(int(r['va'], 16), int(r['va'], 16) + r['size'])
                          for r in f['chunk_byte_ranges']}
                declared = {(int(c['start_va'], 16), int(c['end_va'], 16))
                            for c in f['declared_chunks']}
                assert actual == declared
            row = next(r for r in rows if int(r['va'], 16) == va)
            if row['status'] == '部分分析':
                assert row['reviewed_chunks'] == []
            elif 'declared_chunks' in f:
                assert row['reviewed_chunks'] == f['declared_chunks']
            else:
                assert row['reviewed_chunks'] == [] and 'declared_chunk_boundary' in row
            functions[va] = f
        needed = {bridge for f in found.values() for c in f['calls'] for bridge in c['thunks']}
        bridges = {t['va']: t for t in data['thunks']}
        assert needed <= set(bridges)
        for bridge in needed:
            t = bridges[bridge]
            check_identity(t)
            raw = bytes.fromhex(t['idb_hex'])
            assert raw[0] == 0xE9
            assert hex(int(bridge, 16) + 5 + struct.unpack('<i', raw[1:5])[0]) == t['target']
            unique_thunks.add(bridge)

    metadata = json.loads((BASE / 'supplement_data.json').read_text('utf-8'))
    navigation = json.loads((BASE / 'navigation_raw.json').read_text('utf-8'))
    check_identity(metadata)
    check_identity(navigation)
    assert set(unmapped) == {'0xacb970'}
    assert [s['ascii'] for s in metadata['strings']] == ['URL', 'bbs']
    rtc_maps = [{v['name']['ascii']: (v['offset'], v['size']) for v in rtc['variables']}
                for rtc in metadata['rtc']]
    assert rtc_maps[0]['buf'] == (-348, 128)
    assert rtc_maps[0]['code'] == (-360, 4)
    assert rtc_maps[0]['name'] == (-432, 64)
    assert rtc_maps[1]['buf'] == (-348, 128)
    assert rtc_maps[1]['info'] == (-1516, 0x484)
    for rtc in metadata['rtc']:
        count, array = struct.unpack('<II', bytes.fromhex(rtc['header']['idb_hex']))
        assert count == len(rtc['variables'])
        for index, variable in enumerate(rtc['variables']):
            assert int(variable['descriptor']['va'], 16) == array + index * 12
            offset, size, name = struct.unpack('<iII', bytes.fromhex(variable['descriptor']['idb_hex']))
            assert (offset, size) == (variable['offset'], variable['size'])
            assert name == int(variable['name']['va'], 16)
            assert bytes.fromhex(variable['name']['idb_hex']) == variable['name']['ascii'].encode() + b'\0'

    callback_writes = []
    for instruction in functions[0x6C0E50]['assembly']:
        match = re.search(r'mov\s+dword ptr \[(?:eax|ecx|edx)\+([0-9A-F]+)h\], offset sub_([0-9A-F]+)',
                          instruction['text'])
        if match:
            callback_writes.append((int(match[1], 16), int(match[2], 16)))
    metadata_writes = [(int(c['offset'], 16), int(c['bridge']['va'], 16))
                       for c in metadata['callbacks']]
    assert callback_writes == metadata_writes
    assert len(callback_writes) == 74
    assert {c['slot'] for c in metadata['callbacks']} == set(range(730, 808)) - {746, 761, 776, 793}
    assert all(int(c['offset'], 16) == c['slot'] * 4 for c in metadata['callbacks'])
    for bridge in [c['bridge'] for c in metadata['callbacks']] + [metadata['registered_callback']]:
        raw = bytes.fromhex(bridge['idb_hex'])
        assert raw[0] == 0xE9
        assert int(bridge['va'], 16) + 5 + struct.unpack('<i', raw[1:])[0] == int(bridge['target'], 16)
    assert metadata['registered_callback']['target'] == '0x6c2530'
    for path in BASE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    for name in ('supplement_data.json', 'navigation_raw.json', 'function_review.json'):
        hashes[(BASE / name).relative_to(ROOT).as_posix()] = hashlib.sha256((BASE / name).read_bytes()).hexdigest()
    result = dict(status='PASS', disk_sha256=module.ST_SHA256, unique_functions=41,
                  review_counts=review['counts'], previously_unreviewed_entries=33,
                  reused_evidence_entries=8, this_batch_exported_bodies=34,
                  bridge_navigation_only=74, callback_semantic_review_count=0,
                  unique_selected_direct_call_thunks=len(unique_thunks),
                  identity_records_checked=data_count, checked_bytes_with_repeated_ranges=checked_bytes,
                  unmapped_idb_observations=unmapped, rtc_capacities=rtc_maps,
                  real_client_execution=False, full_dependency_closure=False,
                  hashes=hashes,
                  boundary='PASS限于离线原证一致性；不代表客户端实机、库依赖和业务消费者全闭合')
    (BASE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'hashes'}, ensure_ascii=True))


if __name__ == '__main__':
    run()
