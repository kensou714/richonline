"""独立复核：重算 PE 映射与清理统计；可选使用 IDA 只读数据库核对边界。"""
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def run(db=None):
    image = (ROOT / 'RnClient.exe').read_bytes()
    nt = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, nt + 24 + 28)[0]
    section_count = struct.unpack_from('<H', image, nt + 6)[0]
    optional_size = struct.unpack_from('<H', image, nt + 20)[0]
    sections = []
    for index in range(section_count):
        at = nt + 24 + optional_size + 40 * index
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<4I', image, at + 8)
        sections.append((base + rva, raw_size, raw_offset))
    hashes = {}
    spans = []

    def load(name):
        raw = (HERE / name).read_bytes()
        hashes[name] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def check(span):
        address = int(span.get('va', span.get('start_va', '0')), 16)
        count = span['size']
        candidates = [(start, raw_size, raw_offset) for start, raw_size, raw_offset in sections
                      if start <= address and address + count <= start + raw_size]
        assert len(candidates) == 1, hex(address)
        start, _, offset = candidates[0]
        disk = image[offset + address - start:offset + address - start + count]
        assert len(disk) == count
        assert disk.hex() == span['disk_hex'] == span['idb_hex'], hex(address)
        if db is not None:
            assert db.bytes.get_bytes_at(address, count) == disk, hex(address)
        spans.append((address, count))

    evidence = load('cleanup_evidence.json')
    contracts = load('cleanup_contracts.json')
    assert evidence['disk_sha256'] == hashlib.sha256(image).hexdigest()
    central = ROOT / 'docs/逆向资料/全量分析/尾块完整性审计/current_tail_supplements.json'
    assert evidence['central_source_sha256'] == hashlib.sha256(central.read_bytes()).hexdigest()
    records = evidence['records']
    assert len(records) == len({r['function_va'] for r in records}) == 239
    state_items = []
    factory_proofs = []
    for record in records:
        check(record['main_bytes'])
        check(record['tail'])
        assert record['chunk_parents'] == [record['function_va']]
        if db is not None:
            function = db.functions.get_at(int(record['function_va'], 16))
            assert function.start_ea == int(record['function_va'], 16)
            actual = {(chunk.start_ea, chunk.end_ea) for chunk in db.functions.get_chunks(function)}
            expected = {(int(record['main_bytes']['va'], 16), int(record['main_bytes']['va'], 16) + record['main_bytes']['size']),
                        (int(record['tail']['va'], 16), int(record['tail']['end_va'], 16))}
            assert actual == expected, (record['function_va'], actual, expected)
        fi = record['func_info']
        if fi:
            check(fi['bytes'])
            check(fi['unwind_bytes'])
            raw = bytes.fromhex(fi['unwind_bytes']['disk_hex'])
            for index, state in enumerate(fi['unwind_entries']):
                to_state, action = struct.unpack_from('<iI', raw, index * 8)
                assert (index, to_state, hex(action)) == (state['state'], state['to_state'], state['action'])
                state_items.append((record['function_va'], index, action))
        contract = next(r for r in contracts['records'] if r['function_va'] == record['function_va'])
        if 'construction_failure_proof' in contract:
            proof = contract['construction_failure_proof']
            text = [i['text'] for i in proof]
            find = lambda pattern: next(n for n, line in enumerate(text) if re.search(pattern, line))
            allocation = find(r'call\s+operator new\(uint\)')
            save = find(r'mov\s+\[ebp\+var_14\], eax')
            enter = find(r'mov\s+\[ebp\+var_4\], 0$')
            null_check = find(r'cmp\s+\[ebp\+var_14\], 0$')
            branch = find(r'jz\s+')
            constructor = next(n for n in range(branch + 1, len(text)) if text[n].strip().startswith('call '))
            leave = find(r'mov\s+\[ebp\+var_4\], 0FFFFFFFFh$')
            assert allocation < save < enter < null_check < branch < constructor < leave
            original = {i['va']: i for i in record['main_assembly']}
            assert all(original[i['va']] == i for i in proof)
            assert fi['unwind_entries'] == [dict(state=0, to_state=-1, action=record['tail']['va'])]
            factory_proofs.append(record['function_va'])
    check(evidence['seh_scope']['bytes'])
    group_counts = {}
    group_local_gaps = []
    for name in ['cleanup_targets_full.json', 'unwind_runtime.json']:
        group = load(name)
        group_counts[name] = dict(functions=len(group['functions']), thunks=len(group['thunks']))
        for function in group['functions']:
            coverage = set()
            for span in function['byte_ranges']:
                check(span)
                start = int(span['va'], 16)
                coverage.update(range(start, start + span['size']))
            for chunk in function['declared_chunks']:
                missing = set(range(int(chunk['start_va'], 16), int(chunk['end_va'], 16))) - coverage
                if missing:
                    group_local_gaps.append(dict(source=name, function_va=function['va'],
                                                 first=hex(min(missing)), last=hex(max(missing)), count=len(missing)))
                    all_coverage = set()
                    for start, count in spans:
                        all_coverage.update(range(start, start + count))
                    assert missing <= all_coverage, (name, function['va'], '跨文件原证仍未覆盖')
            if db is not None:
                live = db.functions.get_at(int(function['va'], 16))
                assert live.start_ea == int(function['va'], 16)
                actual = {(c.start_ea, c.end_ea) for c in db.functions.get_chunks(live)}
                expected = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']}
                assert actual == expected
        for thunk in group['thunks']:
            check(thunk)
    assert len(state_items) == 376
    assert len({s[2] for s in state_items}) == 375
    assert len(factory_proofs) == 136
    result = dict(mode='当前IDA与磁盘复核' if db is not None else '磁盘及已有原证独立复核',
                  pe_sha256=hashlib.sha256(image).hexdigest(), source_hashes=hashes,
                  span_records=len(spans), span_bytes_including_repeats=sum(n for _, n in spans),
                  unique_spans=len(set(spans)), functions=239, state_items=376, unique_action_entries=375,
                  construction_failure_proofs=len(factory_proofs), target_groups=group_counts,
                  group_local_gaps_covered_by_other_evidence=group_local_gaps,
                  mismatches=0)
    destination = HERE / ('independent_review_ida.json' if db is not None else 'independent_review_disk.json')
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False))
