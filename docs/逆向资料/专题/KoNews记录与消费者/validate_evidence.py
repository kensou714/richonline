"""离线比对 PE、摘取原证来源、sscanf 字符串和当前 KoNews 解包行。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = HERE / '证据'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


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
        matches = [(rva, offset) for _, rva, raw_size, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(matches) == 1, hex(ea)
        rva, offset = matches[0]
        start = offset + ea - base - rva
        return image[start:start + size]

    seen, ranges, bridges = set(), 0, 0
    for name in ('reused_raw.json', 'closure_raw.json', 'consumer_raw.json', 'helpers_raw.json', 'leaves_raw.json'):
        raw = json.loads((BASE / name).read_text('utf-8'))
        assert raw['disk_sha256'] == digest
        for function in raw['functions']:
            seen.add(function['va'])
            assert function['bytes_match_disk'] is True
            for item in function['byte_ranges'] + function['chunk_byte_ranges']:
                assert item['matching'] is True
                assert disk(int(item['va'], 16), item['size']).hex() == item['idb_hex'] == item['disk_hex']
                ranges += 1
        for item in raw['thunks']:
            data = disk(int(item['va'], 16), 5)
            assert item['matching'] is True and data.hex() == item['idb_hex'] == item['disk_hex']
            assert data[0] == 0xE9
            assert int(item['va'], 16) + 5 + struct.unpack_from('<i', data, 1)[0] == int(item['target'], 16)
            bridges += 1
    reused = json.loads((BASE / 'reused_raw.json').read_text('utf-8'))
    for provenance in reused['provenance']:
        source = (HERE / provenance['source']).resolve()
        blob = source.read_bytes()
        assert hashlib.sha256(blob).hexdigest() == provenance['source_sha256']
        originals = {item['va']: item for item in json.loads(blob)['functions']}
        assert all(item == originals[item['va']] for item in reused['functions'] if item['va'] in provenance['functions'])

    formats = json.loads((BASE / 'formats.json').read_text('utf-8'))
    accepted = [item for item in formats if item['va'] == '0xa2e5cc']
    assert len(accepted) == 1
    format_bytes = b'%[^\t]%d%*d%*d%*d%*d%*d\t%*[^\t]\t%[^\t]\t%[^\t]\0'
    assert bytes.fromhex(accepted[0]['raw_hex']) == format_bytes
    assert disk(0xA2E5CC, len(format_bytes)) == format_bytes
    assert disk(0x806811, 5) == b'\x68' + struct.pack('<I', 0xA2E5CC)

    resource = json.loads((BASE / 'resource_rows.json').read_text('utf-8'))
    blob = (ROOT / resource['source']).read_bytes()
    assert len(blob) == resource['size'] and hashlib.sha256(blob).hexdigest() == resource['sha256']
    key = blob[0]
    size, packed = struct.unpack('<II', bytes((value - key) & 255 for value in blob[1:9]))
    decoded = lzokay.decompress(bytes((value - key) & 255 for value in blob[9:9 + packed]), size)
    assert decoded.hex() == resource['decoded_hex'] and size == len(decoded)
    assert hashlib.sha256(decoded).hexdigest() == resource['decoded_sha256']
    rows = decoded.splitlines()
    assert len(rows) == len(resource['rows']) == 198
    maps, types, animations = Counter(), Counter(), Counter()
    maxima = [0] * 10
    for number, (line, item) in enumerate(zip(rows, resource['rows']), 1):
        fields = line.split(b'\t')
        assert number == item['line'] and line.hex() == item['raw_hex']
        assert len(fields) == item['field_count'] == 10
        assert [field.hex() for field in fields] == item['fields_hex']
        text = [field.decode('big5', errors='strict') for field in fields]
        assert text == item['big5_candidate'] and all(a.encode('big5') == b for a, b in zip(text, fields))
        maps[text[0]] += 1
        types[int(text[1])] += 1
        animations[text[8]] += 1
        assert text[8] == 'other_10_' + str(int(text[1]) + 64)
        maxima = [max(prior, len(field)) for prior, field in zip(maxima, fields)]
    assert maxima[0] < 32 and maxima[8] < 32 and maxima[9] < 128
    result = dict(status='PASS', disk_sha256=digest, unique_functions=len(seen),
                  checked_ranges=ranges, checked_bridges=bridges,
                  accepted_format_va='0xa2e5cc', rejected_format_candidates=[item['va'] for item in formats if item not in accepted],
                  resource_rows=len(rows), maps=dict(maps), types=dict(sorted(types.items())),
                  animations=dict(animations), max_field_bytes=maxima,
                  boundary='字节/资源一致性通过不代表容错、服务端权重或动态行为已验证。')
    (BASE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
