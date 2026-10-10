"""离线核当前 PE、逐块字节、无损适配、来源散列及中文文档格式。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'da3aa15cabf76aa2ee3a30600dca3691491d1dedd57b62c23398e3fdf5fc3fd2'


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def pointer(node, path):
    for part in path.strip('/').split('/'):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def validate():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert sha(image) == EXPECTED
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    ranges, bridges, heads = set(), set(), set()

    def read(va, size):
        matches = [(rva, off) for _, rva, count, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= count]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        return image[off + va - base - rva:off + va - base - rva + size]

    def scan(node):
        if isinstance(node, dict):
            payload = node.get('idb_hex', node.get('ida_hex'))
            if payload is not None and node.get('disk_hex') is not None:
                va = int(node.get('start_va', node.get('va')), 16)
                blob = bytes.fromhex(payload)
                assert len(blob) == node['size']
                assert read(va, len(blob)) == blob == bytes.fromhex(node['disk_hex'])
                assert node.get('matching', node.get('equal')) is True
                if node.get('sha256'):
                    assert sha(blob) == node['sha256']
                ranges.add((va, len(blob)))
                if node.get('target_va'):
                    assert len(blob) == 5 and blob[0] == 0xE9
                    assert va + 5 + struct.unpack_from('<i', blob, 1)[0] == int(node['target_va'], 16)
                    bridges.add(va)
            for child in node.values():
                scan(child)
        elif isinstance(node, list):
            for child in node:
                scan(child)

    def declared(row):
        chunks = row.get('chunk_byte_ranges', row.get('byte_ranges', row.get('chunks', [])))
        found = set()
        for chunk in chunks:
            va = int(chunk.get('va', chunk.get('start_va')), 16)
            blob = read(va, chunk['size'])
            decoded = list(decoder.disasm(blob, va))
            assert sum(i.size for i in decoded) == len(blob)
            found.update(i.address for i in decoded)
        rows = row.get('assembly', row.get('instructions', []))
        actual = {int(i.get('va', i.get('site_va')), 16) for i in rows if i.get('is_code', True)}
        assert actual == found, (row.get('va', row.get('seed_va')), len(actual), len(found))
        heads.update(found)
        for chunk in row.get('declared_chunks', []):
            lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
            assert any(int(c.get('va', c.get('start_va')), 16) == lo and c['size'] == hi - lo for c in chunks)

    raw_bytes = (HERE / 'bounded_raw.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == EXPECTED
    scan(raw)
    for row in raw['functions']:
        declared(row)
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    assert formal['source_sha256'] == RAW_SHA and len(formal['functions']) == 4
    for row in formal['functions']:
        source = pointer(raw, row['source']['json_pointer'])
        assert row['source']['sha256'] == RAW_SHA
        assert row['va'] == source['seed_va'] and row['end_va'] == source['end_va']
        assert row['pseudocode'] == source['pseudocode'] and row['decompile_error'] == source['decompile_error']
        assert row['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code']) for i in source['assembly']]
        assert row['chunk_byte_ranges'] == [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'})
                                            for c in source['chunk_byte_ranges']]
        assert row['bytes_match_disk'] is True
        scan(row)
        declared(row)
    reused = json.loads((HERE / 'reused_raw.json').read_bytes())
    assert len(reused['records']) == 3
    for item in reused['records']:
        ref = item['source']
        source_bytes = (HERE / ref['path']).read_bytes()
        assert sha(source_bytes) == ref['sha256']
        original = pointer(json.loads(source_bytes), ref['pointer'])
        assert original == item['original_record'] and original['va'] == item['va']
        scan(original)
        declared(original)
    old = reused['records'][0]['original_record']
    current = raw['current_chunk_audits'][4]
    assert old['va'] == current['seed_va'] == '0x8e46e0'
    assert [(c['va'], c['size'], c['disk_hex']) for c in old['byte_ranges']] == [
        (c['start_va'], c['size'], c['disk_hex']) for c in current['chunk_byte_ranges']]
    for ref in raw['reuse_sources']:
        source_bytes = (ROOT / 'docs/逆向资料' / ref['path']).read_bytes()
        assert sha(source_bytes) == ref['source_sha256']
    slot, = raw['data_windows']
    assert slot['start_va'] == '0xacc3c8' and slot['size'] == 4 and slot['idb_hex'] == 'ffffffff'
    assert slot['disk_hex'] is None and slot['matching'] is None
    assert sha(bytes.fromhex(slot['idb_hex'])) == slot['sha256']
    assert not [s for s in sections if 0 <= 0xACC3C8 - base - s[1] and 0xACC3CC - base - s[1] <= s[2]]
    assert len([s for s in sections if 0 <= 0xACC3C8 - base - s[1] and 0xACC3CC - base - s[1] <= s[0]]) == 1
    review = json.loads((HERE.parent / 'function_review.json').read_bytes())
    assert len(review['functions']) == 4 and len(review['reused_reviews']) == 1
    assert review['reused_reviews'][0]['status'] == '部分分析'
    for row in review['functions'] + review['reused_reviews']:
        assert row['unknown'] and not row['full_dependency_closure'] and row['anchors']
        for ref in row['source_records']:
            source_bytes = (HERE.parent / ref['path']).read_bytes()
            assert sha(source_bytes) == ref['sha256']
            original = pointer(json.loads(source_bytes), ref['pointer'])
            assert original['va'] == row['va']
        for anchor in row['anchors']:
            source = json.loads((HERE.parent / anchor['path']).read_bytes())
            assert pointer(source, anchor['pointer']) == anchor['value']
            assert int(anchor['site_va'], 16) in heads
    # 独审另锁其06文件；作者只冻结本人的00至05，避免把独审草稿当终稿。
    docs = sorted(p for p in HERE.parent.glob('*.txt') if p.name[:2] in ('00', '01', '02', '03', '04', '05'))
    assert len(docs) == 6
    assert all(not line.strip() or line.startswith('//') for path in docs for line in path.read_text(encoding='utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=EXPECTED, bounded_raw_sha256=RAW_SHA,
                  fresh_functions=4, fresh_declared_bytes=4459, fresh_instruction_entries=1422,
                  reused_subject_reviews=1, reused_records=3, unique_saved_ranges=len(ranges),
                  unique_verified_e9_bridges=len(bridges), instruction_heads=len(heads),
                  virtual_pointer_slot='ACC3C8只有IDB四字节快照，无PE磁盘raw支持，不作相等声明',
                  documents={p.name: sha(p.read_bytes()) for p in docs},
                  limitation='静态局部契约；回调目标、文本暂存所有权/容量、控件类型和动态效果未闭合。')
    (HERE / 'author_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True))
