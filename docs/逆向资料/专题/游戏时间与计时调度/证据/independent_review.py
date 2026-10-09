"""独立审阅的只读验证；可从普通Python或父代理IDA-MCP lease调用audit。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOP = HERE.parent
ROOT = Path('F:/大富翁online/Richonline')
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def audit(db=None):
    blob = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', blob, 60)[0]
    count = struct.unpack_from('<H', blob, pe+6)[0]
    opt = struct.unpack_from('<H', blob, pe+20)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+opt+40*i+8) for i in range(count)]

    def disk(va, size):
        for _, rva, raw, off in sections:
            d = va-base-rva
            if 0 <= d and d+size <= raw:
                return blob[off+d:off+d+size]
        raise AssertionError(('无磁盘范围', hex(va), size))

    comparisons, ranges = 0, {}
    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and disk(va, size) == raw, ('磁盘字节', row['va'])
        if 'disk_hex' in row:
            assert bytes.fromhex(row['disk_hex']) == raw
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == raw, ('IDA字节', row['va'])
        if 'target' in row:
            assert size == 5 and raw[0] == 0xe9
            assert va+5+int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
        key = (va, size)
        if key in ranges:
            assert ranges[key] == raw
        ranges[key] = raw
        comparisons += 1

    data = json.loads((HERE/'functions.json').read_text(encoding='utf-8'))
    assert data['disk_sha256'] == EXPECTED
    functions = {f['va']: f for f in data['functions']}
    assert len(functions) == len(data['functions'])
    chunk_count = insn_count = insn_bytes = block_bytes = 0
    for va, f in functions.items():
        start = int(va, 16)
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert len(declared) == len(f['declared_chunks'])
        assert {(s, e) for s, e, _ in declared} == {(int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
        spans = []
        for i in f['assembly']:
            a, size = int(i['va'], 16), i['size']
            assert size > 0 and any(s <= a and a+size <= e for s, e, _ in declared)
            if spans and spans[-1][1] == a:
                spans[-1][1] = a+size
            else:
                assert not spans or spans[-1][1] <= a
                spans.append([a, a+size])
        assert spans == [[int(r['va'], 16), int(r['va'], 16)+r['size']] for r in f['byte_ranges']]
        for row in f['byte_ranges']+f['chunk_byte_ranges']:
            check(row)
        if db is not None:
            live = db.functions.get_at(start)
            assert live is not None and live.start_ea == start and live.end_ea == int(f['end_va'], 16)
            chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in chunks} == declared
            actual = {i.ea: (i.size, db.instructions.get_disassembly(i))
                      for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
            assert actual == {int(i['va'], 16): (i['size'], i['text']) for i in f['assembly']}, ('指令', va)
        chunk_count += len(declared)
        insn_count += len(f['assembly'])
        insn_bytes += sum(i['size'] for i in f['assembly'])
        block_bytes += sum(r['size'] for r in f['chunk_byte_ranges'])
    thunks = set()
    for row in data['thunks']:
        check(row)
        thunks.add(row['va'])
    contract = json.loads((HERE/'回调与常量.json').read_text(encoding='utf-8'))
    for row in contract['callbacks']+contract['constants']:
        check(row)
    all_thunks = thunks | {r['va'] for r in contract['callbacks']}
    edges = json.loads((HERE/'引用闭合.json').read_text(encoding='utf-8'))
    for row in edges:
        if row['e9_bridge']:
            check(dict(va=row['source'], size=5, idb_hex=row['idb_hex'], target=row['target']))
        if db is not None:
            target, source = int(row['target'], 16), int(row['source'], 16)
            assert any(x.from_ea == source and int(x.type) == row['kind'] for x in db.xrefs.to_ea(target))
            parent = db.functions.get_at(source)
            assert (hex(parent.start_ea) if parent else None) == row['function']
    review = json.loads((TOP/'函数审阅清单.json').read_text(encoding='utf-8'))
    assert {r['va'] for r in review['functions']} == set(functions)
    assert len(review['functions']) == len(functions)
    for row in review['functions']:
        assert all(row.get(k) for k in ('status', 'conclusion', 'unknown', 'evidence'))
    return dict(exe_sha256=EXPECTED, functions=len(functions), complete_chunks=chunk_count,
                instruction_addresses=insn_count, instruction_bytes=insn_bytes,
                declared_chunk_bytes=block_bytes, direct_thunks=len(thunks),
                callback_thunks=len(contract['callbacks']), unique_all_thunks=len(all_thunks),
                constants=len(contract['constants']), reference_edges=len(edges),
                byte_comparisons=comparisons, unique_ranges=len(ranges),
                range_byte_sum=sum(len(v) for v in ranges.values()),
                manual_levels=dict(Counter(r['status'] for r in review['functions'])),
                live_ida_checked=db is not None, mismatches=0,
                scope='范围长度和未合并重叠；原证完整与人工语义等级分别记录。',
                provenance='ida_patch_docs编写独立验证脚本；父代理代跑IDA时另在审阅记录披露。')


if __name__ == '__main__':
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
