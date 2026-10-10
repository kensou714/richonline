"""第25批离线验证：当前PE、全部保存块、桥、原样旧来源与逐指令锚点。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
WRAPPER_SHA = 'a96a6be3766ed319c59c5657ecb89c4f3bcf1a162abab6c57bf01e20e66362bb'


def pointer(raw, path):
    for part in path.strip('/').split('/'):
        raw = raw[int(part)] if isinstance(raw, list) else raw[part]
    return raw


def validate():
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe+52)[0]
    table = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, table+i*40+8) for i in range(struct.unpack_from('<H', image, pe+6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    ranges, bridges, heads = set(), set(), set()

    def disk(va, size):
        matches = [(rva, off) for _, rva, length, off in sections if 0 <= va-base-rva and va-base-rva+size <= length]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        return image[off+va-base-rva:off+va-base-rva+size]

    def scan(value):
        if isinstance(value, dict):
            saved = value.get('idb_hex', value.get('ida_hex'))
            if saved is not None and 'size' in value:
                va = int(value.get('start_va', value.get('va')), 16)
                if value.get('disk_hex') is not None:
                    data = disk(va, value['size'])
                    assert data.hex() == saved == value['disk_hex'], hex(va)
                    if value.get('sha256'):
                        assert hashlib.sha256(data).hexdigest() == value['sha256']
                    ranges.add((va, len(data)))
                    target = value.get('target_va', value.get('target'))
                    if target:
                        assert len(data) == 5 and data[0] == 0xE9
                        assert va+5+struct.unpack_from('<i', data, 1)[0] == int(target, 16)
                        bridges.add(va)
                else:
                    assert value.get('matching') is None
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    def declared(row):
        chunks = row.get('chunk_byte_ranges', row.get('byte_ranges', row.get('chunks', [])))
        known = set()
        for chunk in chunks:
            lo = int(chunk.get('va', chunk.get('start_va')), 16)
            data = disk(lo, chunk['size'])
            decoded = list(decoder.disasm(data, lo))
            assert sum(x.size for x in decoded) == len(data), (row.get('va', row.get('seed_va')), hex(lo))
            known.update(x.address for x in decoded)
        for ins in row.get('assembly', row.get('instructions', [])):
            if isinstance(ins, dict) and ins.get('is_code', True):
                va = int(ins.get('va', ins.get('site_va')), 16)
                assert va in known, (row.get('va'), ins)
                if ins.get('hex'):
                    assert disk(va, ins['size']).hex() == ins['hex']
                heads.add(va)
        for chunk in row.get('declared_chunks', []):
            lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
            assert any(int(c.get('va', c.get('start_va')), 16) == lo and c['size'] == hi-lo for c in chunks)
        if row.get('seed_va', row.get('va')) in {'0x6a4a80', '0x6a4860', '0x6b7cb0'}:
            saved_heads = {int(i.get('va', i.get('site_va')), 16) for i in row['assembly'] if i.get('is_code', True)}
            assert saved_heads == known, ('新主体声明块指令不得缺漏', row.get('seed_va', row.get('va')))
        return bool(chunks)

    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    raw = json.loads(raw_bytes)
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    assert raw['disk_sha256'] == formal['disk_sha256'] == EXPECTED
    scan(raw)
    scan(formal)
    for row in raw['functions']+formal['functions']:
        assert declared(row)
    direct_bridges = {r['start_va']: r for r in raw['verified_direct_bridges']}
    direct_calls, indirect_slots = 0, 0
    for call in raw['calls']:
        va = int(call['site_va'], 16)
        data = disk(va, 5)
        if data[0] == 0xE8:
            assert va+5+struct.unpack_from('<i', data, 1)[0] == int(call['target_va'], 16)
            direct_calls += 1
        else:
            # 原导出器按xref保存FF15槽位，槽地址不是运行时callee端点。
            data = disk(va, 6)
            assert data[:2] == b'\xff\x15' and not call['bridges']
            assert struct.unpack_from('<I', data, 2)[0] == int(call['target_va'], 16)
            indirect_slots += 1
        endpoint = call['target_va']
        for bridge in call['bridges']:
            assert bridge == endpoint
            endpoint = direct_bridges[bridge]['target_va']
        assert endpoint == call['implementation_va']
    assert formal['source_sha256'] == hashlib.sha256(raw_bytes).hexdigest()
    assert len(raw['functions']) == len(formal['functions']) == 3
    for row in formal['functions']:
        old = pointer(raw, row['source']['json_pointer'])
        assert row['source']['sha256'] == formal['source_sha256']
        assert row['va'] == old['seed_va'] and row['end_va'] == old['end_va']
        assert row['pseudocode'] == old['pseudocode'] and row['decompile_error'] == old['decompile_error']
        assert row['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code']) for i in old['assembly']]
        assert row['chunk_byte_ranges'] == [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'}) for c in old['chunk_byte_ranges']]
    callback = json.loads((HERE/'callback_bridge.json').read_bytes())
    assert callback['disk_sha256'] == EXPECTED
    assert callback['seed_va'] == '0x60d34e' and callback['endpoint_seed_va'] == '0x6b7c60'
    assert len(callback['bridges']) == 1
    scan(callback)
    wrapper = HERE/'export_bounded.py'
    assert hashlib.sha256(wrapper.read_bytes()).hexdigest() == WRAPPER_SHA
    for name, ref, seed, sha in runpy.run_path(str(wrapper))['FIXED_SOURCES']:
        payload = (HERE.parents[1]/name).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == sha
        assert pointer(json.loads(payload), ref)['va'] == seed
    reused = json.loads((HERE/'reused_raw.json').read_bytes())
    weak = []
    for record in reused['records']:
        ref = record['source']
        payload = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == ref['sha256']
        old = record['original_record']
        assert pointer(json.loads(payload), ref['pointer']) == old
        scan(old)
        if not declared(old):
            weak.append(record['va'])
    assert len(reused['records']) == 14 and weak == ['0x6a1190'], weak
    auxiliary = json.loads((HERE/'reused_auxiliary.json').read_bytes())
    assert len(auxiliary['records']) == 1
    for record in auxiliary['records']:
        ref = record['source']
        payload = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == ref['sha256']
        assert pointer(json.loads(payload), ref['pointer']) == record['original_record']
        assert record['original_record']['va'] == '0x601274' and record['original_record']['target'] == '0x91bd30'
        scan(record['original_record'])
    for audit in raw['current_chunk_audits']:
        candidates = [r['original_record'] for r in reused['records'] if r['va'] == audit['seed_va']]
        if candidates:
            current = audit['chunk_byte_ranges']
            saved = candidates[0]['chunk_byte_ranges']
            assert [(c['start_va'], c['size'], c['idb_hex']) for c in current] == [(c['va'], c['size'], c['idb_hex']) for c in saved]
    review = json.loads((HERE.parent/'function_review.json').read_bytes())
    assert len(review['functions']) == 3 and len(review['reused_reviews']) == 2 and len(review['dependency_reviews']) == 5
    reviews = review['functions']+review['reused_reviews']+review['dependency_reviews']
    for row in reviews:
        assert row['unknown'] and row['anchors']
        for ref in row['source_records']:
            payload = (HERE.parent/ref['path']).read_bytes()
            assert hashlib.sha256(payload).hexdigest() == ref['sha256']
            original = pointer(json.loads(payload), ref['pointer'])
            assert original['va'] == row['va']
            assert original.get('declared_chunks', original.get('chunks', [])) == row['declared_chunks']
            assert original.get('chunk_byte_ranges', original.get('byte_ranges', original.get('chunks', []))) == row['original_byte_ranges']
            asm_key = 'assembly' if 'assembly' in original else 'instructions'
            assert len(row['anchors']) == sum(bool(i.get('is_code', True)) for i in original[asm_key])
        for anchor in row['anchors']:
            assert pointer(json.loads((HERE.parent/anchor['path']).read_bytes()), anchor['pointer']) == anchor['value']
            assert int(anchor['site_va'], 16) in heads
    docs = list(HERE.parent.glob('*.txt'))
    assert len(docs) == 7
    assert all(not line.strip() or line.startswith('//') for p in docs for line in p.read_text(encoding='utf-8').splitlines())
    fresh_bytes = sum(c['size'] for row in formal['functions'] for c in row['chunk_byte_ranges'])
    fresh_instructions = sum(len(row['assembly']) for row in formal['functions'])
    assert (fresh_bytes, fresh_instructions) == (1411, 370)
    result = dict(status='PASS', disk_sha256=EXPECTED, prepared_wrapper_sha256=WRAPPER_SHA,
        fresh_functions=3, fresh_declared_bytes=fresh_bytes, fresh_instruction_entries=fresh_instructions,
        reused_subject_reviews=2, finite_dependency_reviews=5, reused_records=len(reused['records']),
        reviewed_instruction_anchors=sum(len(row['anchors']) for row in reviews),
        reused_auxiliary_records=len(auxiliary['records']),
        unique_saved_ranges=len(ranges), unique_verified_e9_bridges=len(bridges), instruction_heads=len(heads),
        verified_direct_call_records=direct_calls, verified_indirect_call_slots=indirect_slots,
        weak_original_navigation=weak, callback_bridge_endpoint='0x6b7c60',
        documents={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in docs},
        limitation='静态局部生命周期及有限ABI；6A1190旧弱源只导航，callback端点及深释放未由本基批强闭合。')
    (HERE/'author_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True))
