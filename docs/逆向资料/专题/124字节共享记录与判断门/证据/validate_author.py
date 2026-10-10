"""离线核当前PE、保存原块、旧逐指令字节、来源、语义锚点与机械适配。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def at_pointer(raw, pointer):
    for part in pointer.strip('/').split('/'):
        raw = raw[int(part)] if isinstance(raw, list) else raw[part]
    return raw


def validate():
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe+52)[0]
    at = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, at+i*40+8) for i in range(struct.unpack_from('<H', image, pe+6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    ranges, sites, bridges, records = set(), set(), set(), {}

    def disk(va, size):
        matches = [(rva, off) for _, rva, length, off in sections if 0 <= va-base-rva and va-base-rva+size <= length]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        return image[off+va-base-rva:off+va-base-rva+size]

    def scan(value):
        if isinstance(value, dict):
            if 'idb_hex' in value and 'size' in value:
                va = int(value.get('start_va', value.get('va')), 16)
                if value.get('disk_hex') is not None:
                    data = disk(va, value['size'])
                    assert data.hex() == value['idb_hex'] == value['disk_hex']
                    if value.get('sha256'):
                        assert hashlib.sha256(data).hexdigest() == value['sha256']
                    ranges.add((va, len(data)))
                    target = value.get('target_va', value.get('target'))
                    if target:
                        assert data[0] == 0xE9 and len(data) == 5
                        assert va+5+struct.unpack_from('<i', data, 1)[0] == int(target, 16)
                        bridges.add(va)
                else:
                    assert value.get('matching') is None
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    names = ['bounded_raw.json', 'formal_functions.json', 'dependency_raw.json']
    for name in names:
        raw = json.loads((HERE/name).read_bytes())
        assert raw['disk_sha256'] == EXPECTED
        scan(raw)
        for row in raw['functions']:
            va = row.get('va', row.get('seed_va'))
            records[va] = row
            known = set()
            for chunk in row['chunk_byte_ranges']:
                lo = int(chunk.get('va', chunk.get('start_va')), 16)
                data = disk(lo, chunk['size'])
                decoded = list(decoder.disasm(data, lo))
                assert sum(i.size for i in decoded) == len(data), (va, hex(lo))
                known.update(i.address for i in decoded)
            for ins in row['assembly']:
                address = int(ins.get('va', ins.get('site_va')), 16)
                if ins.get('is_code', True):
                    assert address in known, (va, ins)
                    sites.add(address)
            for chunk in row.get('declared_chunks', []):
                lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                assert any(int(c.get('va', c.get('start_va')), 16) == lo and c['size'] == hi-lo for c in row['chunk_byte_ranges'])
    original_bytes = (HERE/'bounded_raw.json').read_bytes()
    original = json.loads(original_bytes)
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    assert formal['source_sha256'] == hashlib.sha256(original_bytes).hexdigest()
    for row in formal['functions']:
        old = at_pointer(original, row['source']['json_pointer'])
        assert row['source']['sha256'] == formal['source_sha256']
        assert row['va'] == old['seed_va'] and row['end_va'] == old['end_va']
        assert row['pseudocode'] == old['pseudocode']
        assert row['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code']) for i in old['assembly']]
        assert row['chunk_byte_ranges'] == [dict(va=c['start_va'], **{k:v for k,v in c.items() if k != 'start_va'}) for c in old['chunk_byte_ranges']]
    reused = json.loads((HERE/'reused_raw.json').read_bytes())
    weak_reused = []
    for row in reused['records']:
        ref = row['source']
        payload = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == ref['sha256']
        assert at_pointer(json.loads(payload), ref['pointer']) == row['original_record']
        scan(row['original_record'])
        old = row['original_record']
        chunks = old.get('chunk_byte_ranges', old.get('byte_ranges', old.get('chunks', [])))
        if not chunks:
            instructions = old.get('assembly', old.get('instructions', []))
            if instructions and all(i.get('bytes') for i in instructions):
                for ins in instructions:
                    address = int(ins['va'], 16)
                    data = bytes.fromhex(ins['bytes'])
                    assert disk(address,len(data)) == data
                    decoded = list(decoder.disasm(data,address))
                    assert len(decoded)==1 and decoded[0].size==len(data)
                continue
            weak_reused.append(row['va'])
            continue
        known = set()
        for chunk in chunks:
            lo = int(chunk.get('va', chunk.get('start_va')), 16)
            data = disk(lo, chunk['size'])
            decoded = list(decoder.disasm(data, lo))
            assert sum(i.size for i in decoded) == len(data)
            known.update(i.address for i in decoded)
        for ins in old.get('assembly', old.get('instructions', [])):
            if ins.get('is_code', True):
                assert int(ins['va'], 16) in known
    review = json.loads((HERE.parent/'function_review.json').read_bytes())
    for row in review['functions']:
        assert row['va'] in records and row['unknown'] and row['anchors']
        for ref in row['source_records']:
            payload = (HERE.parent/ref['path']).read_bytes()
            assert hashlib.sha256(payload).hexdigest() == ref['sha256']
            source = at_pointer(json.loads(payload), ref['pointer'])
            assert source['va'] == row['va'] and source['declared_chunks'] == row['declared_chunks']
            assert source['chunk_byte_ranges'] == row['original_byte_ranges']
        for anchor in row['anchors']:
            source = json.loads((HERE.parent/anchor['path']).read_bytes())
            assert at_pointer(source, anchor['pointer']) == anchor['value']
    navigation = json.loads((HERE/'source_navigation.json').read_bytes())
    for row in navigation['records']:
        ref = row['source']
        payload = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == ref['sha256']
        source = json.loads(payload)
        original_row = at_pointer(source, ref['pointer'])
        assert original_row['va'] == row['va']
        assert original_row['chunk_byte_ranges'] == row['original_byte_ranges']
        scan(row['original_byte_ranges'])
        for anchor in row['anchors']:
            assert at_pointer(source, anchor['pointer']) == anchor['value']
    docs = list(HERE.parent.glob('*.txt'))
    assert all(not line.strip() or line.startswith('//') for p in docs for line in p.read_text(encoding='utf-8').splitlines())
    assert not weak_reused, weak_reused
    result = dict(status='PASS', disk_sha256=EXPECTED, unique_saved_ranges=len(ranges), instruction_sites=len(sites), unique_e9_bridges=len(bridges), declared_records=len(records), fresh_functions=len(review['functions']), reused_records=len(reused['records']), source_navigation_records=len(navigation['records']), reused_without_saved_bytes=weak_reused, review_checked=True, documents={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in docs}, limitation='静态局部语义；未运行游戏；旧逐指令原证不补造声明块；来源导航不计新增审阅')
    (HERE/'author_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True))
