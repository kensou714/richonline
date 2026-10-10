"""离线核原证范围、指令头、直接桥、机械适配和逐函数语义锚点。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def validate(require_review=True):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, at + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    ranges, sites, bridges, records = set(), set(), set(), {}

    def disk(va, size):
        match = [(rva, off) for _, rva, length, off in sections
                 if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(match) == 1, (hex(va), size)
        rva, off = match[0]
        return image[off + va - base - rva:off + va - base - rva + size]

    def scan(value):
        if isinstance(value, dict):
            if 'idb_hex' in value and 'size' in value:
                va = int(value.get('start_va', value.get('va')), 16)
                if value.get('disk_hex') is not None:
                    raw = disk(va, value['size'])
                    assert raw.hex() == value['idb_hex'] == value['disk_hex']
                    if value.get('sha256'):
                        assert hashlib.sha256(raw).hexdigest() == value['sha256']
                    ranges.add((va, len(raw)))
                    target = value.get('target_va', value.get('target'))
                    if target:
                        assert len(raw) == 5 and raw[0] == 0xE9
                        assert va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(target, 16)
                        bridges.add(va)
                else:
                    assert value.get('matching') is None
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    paths = ['bounded_raw.json', 'formal_functions.json', 'dependency_raw.json']
    paths += ['dependency_helpers_raw.json', 'dependency_leaf_raw.json']
    for name in paths:
        raw = json.loads((HERE / name).read_bytes())
        assert raw['disk_sha256'] == EXPECTED
        scan(raw)
        for row in raw.get('functions', []):
            key = row.get('va', row.get('seed_va'))
            records[key] = row
            chunks = row['chunk_byte_ranges']
            known = set()
            for chunk in chunks:
                lo = int(chunk.get('va', chunk.get('start_va')), 16)
                data = disk(lo, chunk['size'])
                decoded = list(decoder.disasm(data, lo))
                assert sum(i.size for i in decoded) == len(data), (key, hex(lo))
                known.update(i.address for i in decoded)
            for ins in row['assembly']:
                va = int(ins.get('va', ins.get('site_va')), 16)
                if ins.get('is_code', True):
                    assert va in known, (key, hex(va))
                    sites.add(va)
            for chunk in row.get('declared_chunks', []):
                lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                assert any(int(c.get('va', c.get('start_va')), 16) == lo and
                           c['size'] == hi - lo for c in chunks)
    original_bytes = (HERE / 'bounded_raw.json').read_bytes()
    original = json.loads(original_bytes)
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    assert formal['source_sha256'] == hashlib.sha256(original_bytes).hexdigest()
    for row in formal['functions']:
        ref = row['source']
        assert ref['sha256'] == formal['source_sha256']
        old = original['functions'][int(ref['json_pointer'].rsplit('/', 1)[1])]
        assert row['va'] == old['seed_va'] and row['end_va'] == old['end_va']
        assert row['pseudocode'] == old['pseudocode']
        assert row['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code'])
                                   for i in old['assembly']]
        assert row['chunk_byte_ranges'] == [dict(va=c['start_va'], **{k: v for k, v in c.items()
                                            if k != 'start_va'}) for c in old['chunk_byte_ranges']]
    review_path = HERE.parent / 'function_review.json'
    if require_review:
        review = json.loads(review_path.read_bytes())
        for row in review['functions']:
            assert {'va', 'status', 'conclusion', 'unknown', 'evidence', 'anchors'} <= row.keys()
            assert row['unknown'] and row['evidence']
            assert row['va'] in records
            assert row['anchors'], row['va']
            for ref in row['source_records']:
                payload = (HERE.parent / ref['path']).read_bytes()
                assert hashlib.sha256(payload).hexdigest() == ref['sha256']
                source = json.loads(payload)
                for part in ref['pointer'].strip('/').split('/'):
                    source = source[int(part)] if isinstance(source, list) else source[part]
                assert source['va'] == row['va']
                assert source['declared_chunks'] == row['declared_chunks']
                assert source['chunk_byte_ranges'] == row['original_byte_ranges']
            for anchor in row['anchors']:
                source = json.loads((HERE.parent / anchor['path']).read_bytes())
                for part in anchor['pointer'].strip('/').split('/'):
                    source = source[int(part)] if isinstance(source, list) else source[part]
                assert source == anchor['value'], (row['va'], anchor)
    docs = list(HERE.parent.glob('*.txt'))
    assert all(not line.strip() or line.startswith('//') for p in docs
               for line in p.read_text(encoding='utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=EXPECTED, unique_saved_ranges=len(ranges),
                  instruction_sites=len(sites), unique_e9_bridges=len(bridges),
                  formal_functions=len(formal['functions']), fresh_functions=len(records),
                  review_checked=require_review,
                  limitation='静态原证与语义锚点，不代表动态网络/线程/游戏实机验证')
    (HERE / 'author_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True))
