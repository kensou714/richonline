"""独立读取 PE，核对本专题导出和复用主尾块，不以验证代替语义审阅。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[5]
BASE = Path(__file__).resolve().parent
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def validate():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, raw_size, raw_offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((image_base + rva, raw_size, raw_offset))

    def check(record):
        va = int(record['va'], 16)
        size = record['size']
        disk = None
        for start, length, offset in sections:
            if start <= va and va + size <= start + length:
                disk = blob[offset + va - start:offset + va - start + size]
                break
        assert disk is not None, hex(va)
        assert record['disk_hex'] == disk.hex(), hex(va)
        assert record['idb_hex'] == disk.hex() and record['matching'], hex(va)
        return size

    bundles = [json.loads((BASE / name).read_text('utf-8'))
               for name in ('functions_raw.json', 'closure_raw.json', 'leaf_raw.json')]
    functions = bundles[0]
    navigation = json.loads((BASE / 'seed_navigation.json').read_text('utf-8'))
    closure = json.loads((BASE / 'closure_navigation.json').read_text('utf-8'))
    leaf = json.loads((BASE / 'leaf_navigation.json').read_text('utf-8'))
    assert functions['disk_sha256'] == navigation['disk_sha256'] == EXPECTED_SHA
    assert all(item['disk_sha256'] == EXPECTED_SHA for item in bundles + [closure, leaf])
    source_bytes = (ROOT / navigation['source_path']).read_bytes()
    assert hashlib.sha256(source_bytes).hexdigest() == navigation['source_sha256']
    source = json.loads(source_bytes.decode('utf-8'))
    source_functions = {item['va']: item for item in source['functions']}
    ranges = 0
    bridges = 0
    declared_bytes = 0
    new_functions = [function for bundle in bundles for function in bundle['functions']]
    assert len({item['va'] for item in new_functions}) == len(new_functions) == 16
    for function in new_functions + navigation['reused_functions']:
        for record in function['byte_ranges'] + function['chunk_byte_ranges']:
            check(record)
            ranges += 1
        declared_bytes += sum(record['size'] for record in function['chunk_byte_ranges'])
        if function in navigation['reused_functions']:
            assert function['declared_chunks'] == source_functions[function['va']]['declared_chunks']
            assert function['chunk_byte_ranges'] == source_functions[function['va']]['chunk_byte_ranges']
    all_bridges = {item['va']: item for bundle in bundles for item in bundle['thunks']}
    for entry in closure['vtable_entries']:
        all_bridges[entry['bridge']['va']] = entry['bridge']
    for record in all_bridges.values():
        check(record)
        raw = bytes.fromhex(record['disk_hex'])
        assert len(raw) == 5 and raw[0] == 0xE9
        assert int(record['target'], 16) == int(record['va'], 16) + 5 + struct.unpack('<i', raw[1:])[0]
        bridges += 1
    incoming = 0
    for target in [target for item in (navigation, closure, leaf) for target in item['incoming']]:
        for reference in target['references']:
            if reference['bytes'] is not None:
                check(reference['bytes'])
                incoming += 1
    window_bytes = sum(check(record) for record in navigation['windows'])
    window_bytes += check(closure['table'])
    table = bytes.fromhex(closure['table']['disk_hex'])
    assert len(closure['vtable_entries']) == 13 and len(table) == 52
    for entry in closure['vtable_entries']:
        assert struct.unpack_from('<I', table, entry['offset'])[0] == int(entry['bridge']['va'], 16)
    review = json.loads((BASE.parent / '函数审阅清单.json').read_text('utf-8'))
    reviewed = {item['va'] for item in review['functions']}
    assert reviewed == {item['va'] for item in new_functions + navigation['reused_functions']}
    assert all(item['status'] and item['conclusion'] and item['evidence'] for item in review['functions'])
    result = dict(status='PASS', disk_sha256=EXPECTED_SHA,
                  new_functions=len(new_functions),
                  reused_functions=len(navigation['reused_functions']),
                  checked_ranges=ranges, declared_bytes=declared_bytes,
                  bridges=bridges, incoming_records=incoming, window_bytes=window_bytes,
                  scope='局部原证与复用来源完整性；不证明未知虚调、对象容量或实机行为')
    (BASE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                         encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    validate()
