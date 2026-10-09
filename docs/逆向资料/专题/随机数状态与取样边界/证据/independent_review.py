"""独审只读核验：完整函数块、反向引用归属与当前PE/IDA字节。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/大富翁online/Richonline')
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def audit(db=None):
    blob = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', blob, 60)[0]
    count, opt = struct.unpack_from('<H', blob, pe+6)[0], struct.unpack_from('<H', blob, pe+20)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+opt+40*i+8) for i in range(count)]

    def disk(va, size):
        for _, rva, raw, off in sections:
            d = va-base-rva
            if 0 <= d and d+size <= raw:
                return blob[off+d:off+d+size]
        raise AssertionError(('无PE后备', hex(va), size))

    comparisons, ranges = 0, {}
    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and raw == disk(va, size) == bytes.fromhex(row['disk_hex'])
        assert row['matching'] is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == raw, ('IDA字节', row['va'])
        if 'target' in row:
            assert size == 5 and raw[0] == 0xe9
            assert va+5+int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
        if (va, size) in ranges:
            assert ranges[(va, size)] == raw
        ranges[(va, size)] = raw
        comparisons += 1

    data = json.loads((HERE/'functions_raw.json').read_text(encoding='utf-8'))
    nav = json.loads((HERE/'reverse_navigation.json').read_text(encoding='utf-8'))
    review = json.loads((HERE/'function_review.json').read_text(encoding='utf-8'))
    assert data['disk_sha256'] == nav['disk_sha256'] == EXPECTED
    functions = {f['va']: f for f in data['functions']}
    assert len(functions) == len(data['functions'])
    chunks_total = entries = directives = declared_bytes = 0
    for va, f in functions.items():
        start = int(va, 16)
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert len(declared) == len(f['declared_chunks'])
        assert {(s, e) for s, e, _ in declared} == {(int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges']+f['chunk_byte_ranges']:
            check(row)
        assembly = {int(i['va'], 16): i['text'] for i in f['assembly']}
        assert len(assembly) == len(f['assembly'])
        assert all(any(s <= a < e for s, e, _ in declared) for a in assembly)
        if db is not None:
            live = db.functions.get_at(start)
            assert live is not None and live.start_ea == start and live.end_ea == int(f['end_va'], 16)
            chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in chunks} == declared
            actual = {i.ea: db.instructions.get_disassembly(i)
                      for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
            assert actual == assembly, ('完整块内汇编', va)
        chunks_total += len(declared)
        entries += len(assembly)
        directives += sum(t.lstrip().startswith(('align', 'db ', 'dw ', 'dd ')) for t in assembly.values())
        declared_bytes += sum(e-s for s, e, _ in declared)
    thunks = data['thunks']+nav['address_taken_thunks']
    for row in thunks:
        check(row)
    references = 0
    for target in nav['targets']:
        address = int(target['target'], 16)
        if db is not None:
            assert {(x.from_ea, int(x.type)) for x in db.xrefs.to_ea(address)} == {
                (int(r['site'], 16), r['kind']) for r in target['references']}, ('引用集合', target['target'])
        for r in target['references']:
            check(r['bytes'])
            site = int(r['site'], 16)
            raw = disk(site, r['size'])
            assert len(raw) == 5 and raw[0] in (0xe8, 0xe9)
            assert site+5+int.from_bytes(raw[1:], 'little', signed=True) == address
            assert r['kind'] == (17 if raw[0] == 0xe8 else 19)
            if db is not None:
                owner = db.functions.get_at(site)
                assert (hex(owner.start_ea) if owner else None) == r['function']
                instruction = db.instructions.get_at(site)
                assert instruction.size == r['size']
                assert db.instructions.get_disassembly(instruction) == r['disassembly']
            references += 1
    for row in nav['data_records']:
        check(row)
    assert {r['va'] for r in review['functions']} == set(functions)
    assert len(review['functions']) == len(functions)
    for row in review['functions']:
        assert row['conclusion'] and row['unknown']
        if row['review_status'] == '局部语义已审阅':
            assert row['reviewed_chunks'] == functions[row['va']]['declared_chunks']
        else:
            assert row['reviewed_chunks'] == []
    rand = next(t for t in nav['targets'] if t['target'] == '0x60ae14')['references']
    owners = {r['function'] for r in rand if r['function'] is not None}
    return dict(exe_sha256=EXPECTED, functions=len(functions), complete_chunks=chunks_total,
                assembly_entries=entries, decoded_entries=entries-directives, alignment_or_data_entries=directives,
                declared_bytes=declared_bytes, unique_thunks=len({r['va'] for r in thunks}),
                navigation_references=references, data_records=len(nav['data_records']),
                rand_call_sites=len(rand), rand_declared_function_owners=len(owners),
                rand_undeclared_call_sites=sum(r['function'] is None for r in rand),
                byte_comparisons=comparisons, unique_ranges=len(ranges), range_byte_sum=sum(len(v) for v in ranges.values()),
                manual_levels=dict(Counter(r['review_status'] for r in review['functions'])),
                live_ida_checked=db is not None, mismatches=0,
                scope='完整块和当前引用归属核验；范围长度和未合并重叠，不扩大人工语义级别。',
                provenance='ida_patch_docs编写独审脚本；若父代理代跑IDA，则在独审记录披露。')


if __name__ == '__main__':
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
