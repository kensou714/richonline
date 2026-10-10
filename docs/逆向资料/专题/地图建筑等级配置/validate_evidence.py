"""离线复核地图建筑等级专题的 IDA 原证和当前客户端磁盘字节。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EVIDENCE = HERE / '证据'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW = ('functions_raw.json', 'dependencies_raw.json', 'accessors_raw.json',
       'closure_raw.json', 'implementations_raw.json')


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        mapped = [(rva, offset) for _, rva, raw_size, offset in sections
                  if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(mapped) == 1, hex(ea)
        rva, offset = mapped[0]
        start = offset + ea - base - rva
        return image[start:start + size]

    seen = set()
    blocks = 0
    bridges = 0
    for name in RAW:
        raw = json.loads((EVIDENCE / name).read_text(encoding='utf-8'))
        assert raw['disk_sha256'] == digest
        for function in raw['functions']:
            va = int(function['va'], 16)
            seen.add(va)
            assert function['bytes_match_disk'] is True
            for block in function['byte_ranges'] + function['chunk_byte_ranges']:
                assert block['matching'] is True
                assert disk(int(block['va'], 16), block['size']).hex() == block['idb_hex'] == block['disk_hex']
                blocks += 1
        for bridge in raw['thunks']:
            assert bridge['matching'] is True
            ea = int(bridge['va'], 16)
            content = disk(ea, 5)
            assert content.hex() == bridge['idb_hex'] == bridge['disk_hex']
            assert content[0] == 0xE9
            assert ea + 5 + struct.unpack_from('<i', content, 1)[0] == int(bridge['target'], 16)
            bridges += 1
    required = {0x8056C0, 0x8053C0, 0x8054A0, 0x807BD0, 0x67B890, 0x63F2D0, 0x807C40}
    assert required <= seen

    token_file = EVIDENCE / 'build_tokens.json'
    tokens = None
    if token_file.exists():
        tokens = json.loads(token_file.read_text(encoding='utf-8'))
        table = int(tokens['table_va'], 16)
        assert table == 0xA676DC and disk(table, 40).hex() == tokens['table_hex']
        assert len(tokens['records']) == 10
        for i, row in enumerate(tokens['records']):
            va = int(row['va'], 16)
            assert row['index'] == i and row['result'] == i + 11
            assert struct.unpack('<I', disk(table + 4 * i, 4))[0] == va
            assert disk(va, len(bytes.fromhex(row['raw_hex']))).hex() == row['raw_hex']
            assert bytes.fromhex(row['raw_hex']) == row['token'].encode('ascii') + b'\0'

    resources = json.loads((EVIDENCE / 'resources.json').read_text(encoding='utf-8'))
    for record in resources['records']:
        blob = (ROOT / record['source']).read_bytes()
        assert len(blob) == record['size']
        assert hashlib.sha256(blob).hexdigest() == record['sha256']
    result = dict(status='PASS', disk_sha256=digest, unique_exported_functions=len(seen),
                  checked_ranges=blocks, checked_bridges=bridges,
                  token_table_checked=tokens is not None, resource_files=len(resources['records']))
    (EVIDENCE / 'validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
