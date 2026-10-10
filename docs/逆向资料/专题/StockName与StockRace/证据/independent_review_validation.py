"""独立 PE 解码与契约核验；不调用作者校验器、IDA 或游戏。"""
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
REVERSE = TOPIC.parents[1]
ROOT = TOPIC.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    optional = pe + 24
    assert struct.unpack_from('<H', blob, optional)[0] == 0x10B
    base = struct.unpack_from('<I', blob, optional + 28)[0]
    table = optional + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(ea, size):
        mappings = [(rva, offset) for _, rva, raw_size, offset in sections
                    if base + rva <= ea and ea + size <= base + rva + raw_size]
        if not mappings:
            return None
        assert len(mappings) == 1, (hex(ea), size)
        rva, offset = mappings[0]
        start = offset + ea - base - rva
        result = blob[start:start + size]
        assert len(result) == size
        return result

    identity_records, identity_bytes, unmapped = 0, 0, []

    def check_range(row):
        nonlocal identity_records, identity_bytes
        ea, size = int(row['va'], 16), row['size']
        actual = disk(ea, size)
        assert len(bytes.fromhex(row['idb_hex'])) == size
        if actual is None:
            assert ea == 0xACB970 and row['disk_hex'] is None and row['matching'] is None
            assert any(base + rva <= ea and ea + size <= base + rva + virtual_size
                       and ea >= base + rva + raw_size
                       for virtual_size, rva, raw_size, _ in sections)
            unmapped.append(hex(ea))
        else:
            assert row['matching'] is True
            assert actual == bytes.fromhex(row['disk_hex']) == bytes.fromhex(row['idb_hex'])
            identity_bytes += size
        identity_records += 1

    def walk_ranges(node):
        if isinstance(node, list):
            for child in node:
                walk_ranges(child)
        elif isinstance(node, dict):
            if {'va', 'size', 'idb_hex', 'disk_hex', 'matching'} <= node.keys():
                check_range(node)
            for child in node.values():
                walk_ranges(child)

    source_hashes = {}

    def load(path):
        source_hashes[path.relative_to(REVERSE).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text('utf-8'))

    review = load(HERE / 'function_review.json')
    rows = review['functions']
    assert len(rows) == len({r['va'] for r in rows}) == 41
    assert Counter(r['status'] for r in rows) == {'局部语义已审阅': 30, '部分分析': 10, '复用已审阅': 1}
    assert all(r['full_dependency_closure'] is False for r in rows)
    assert sum(r['evidence_reused'] for r in rows) == 8
    selected = {}
    for row in rows:
        selected.setdefault(REVERSE / row['evidence'][0], {})[row['va']] = row

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoded, functions, bridges = {}, {}, {}
    chunks, legacy_ranges, instruction_count = 0, 0, 0

    def check_bridge(row):
        check_range(row)
        ea = int(row['va'], 16)
        raw = disk(ea, 5)
        assert raw[0] == 0xE9
        target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == int(row['target'], 16)
        assert ea not in bridges or bridges[ea] == target
        bridges[ea] = target

    for path, wanted in selected.items():
        data = load(path)
        assert data['disk_sha256'] == EXPECTED_SHA
        found = {f['va']: f for f in data['functions'] if f['va'] in wanted}
        assert set(found) == set(wanted)
        for va, function in found.items():
            assert function['bytes_match_disk'] is True
            functions[va] = function
            ranges = function.get('chunk_byte_ranges', function['byte_ranges'])
            if 'declared_chunks' in function:
                declared = function['declared_chunks']
                assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in declared] == [
                    (int(r['va'], 16), int(r['va'], 16) + r['size']) for r in ranges]
                chunks += len(declared)
                expected = [] if wanted[va]['status'] == '部分分析' else declared
                assert wanted[va]['reviewed_chunks'] == expected
            else:
                assert wanted[va]['reviewed_chunks'] == [] and 'declared_chunk_boundary' in wanted[va]
                legacy_ranges += len(ranges)
            sites = []
            for row in ranges:
                check_range(row)
                ea = int(row['va'], 16)
                instructions = list(decoder.disasm(disk(ea, row['size']), ea))
                assert sum(i.size for i in instructions) == row['size'], va
                for instruction in instructions:
                    assert instruction.address not in decoded, hex(instruction.address)
                    decoded[instruction.address] = instruction
                    sites.append(instruction.address)
                instruction_count += len(instructions)
            assert sites == [int(r['va'], 16) for r in function['assembly']], va
            for row in function['byte_ranges']:
                check_range(row)
        needed = {t for f in found.values() for c in f['calls'] for t in c['thunks']}
        thunk_rows = {t['va']: t for t in data['thunks']}
        assert needed <= thunk_rows.keys()
        for va in sorted(needed):
            check_bridge(thunk_rows[va])
    call_bridge_count = len(bridges)
    checked_calls = 0
    for function in functions.values():
        for call in function['calls']:
            instruction = decoded[int(call['site'], 16)]
            assert instruction.mnemonic in ('call', 'jmp')
            assert instruction.op_str == call['target']
            target = int(call['target'], 16)
            for thunk in call['thunks']:
                assert int(thunk, 16) == target
                target = bridges[target]
            assert target == int(call['implementation'], 16)
            checked_calls += 1

    metadata = load(HERE / 'supplement_data.json')
    navigation = load(HERE / 'navigation_raw.json')
    assert metadata['disk_sha256'] == navigation['disk_sha256'] == EXPECTED_SHA
    walk_ranges(metadata)
    walk_ranges(navigation)
    assert set(unmapped) == {'0xacb970'}
    assert disk(0xA23C44, 4) == b'URL\0' and disk(0xA23C48, 4) == b'bbs\0'
    assert struct.unpack('<2I', disk(0xA22600, 8)) == (0x604BF4, 0x60B166)
    rtc_maps = []
    for rtc in metadata['rtc']:
        header = rtc['header']
        count, array = struct.unpack('<II', disk(int(header['va'], 16), 8))
        assert count == len(rtc['variables'])
        values = {}
        for index, variable in enumerate(rtc['variables']):
            assert int(variable['descriptor']['va'], 16) == array + index * 12
            offset, size, name = struct.unpack('<iII', disk(array + index * 12, 12))
            assert (offset, size) == (variable['offset'], variable['size'])
            assert name == int(variable['name']['va'], 16)
            text = variable['name']['ascii']
            assert disk(name, len(text) + 1) == text.encode('ascii') + b'\0'
            values[text] = (offset, size)
        rtc_maps.append(values)
    assert rtc_maps[0]['buf'] == (-348, 128) and rtc_maps[0]['code'] == (-360, 4)
    assert rtc_maps[0]['name'] == (-432, 64)
    assert rtc_maps[1]['buf'] == (-348, 128) and rtc_maps[1]['info'] == (-1516, 1156)

    callback_writes = []
    for row in functions['0x6c0e50']['assembly']:
        instruction = decoded[int(row['va'], 16)]
        match = re.fullmatch(r'dword ptr \[(?:eax|ecx|edx) \+ (0x[0-9a-f]+)\], (0x[0-9a-f]+)', instruction.op_str)
        if instruction.mnemonic == 'mov' and match:
            callback_writes.append((int(match[1], 16), int(match[2], 16)))
    assert callback_writes == [(int(c['offset'], 16), int(c['bridge']['va'], 16)) for c in metadata['callbacks']]
    assert len(callback_writes) == 74
    assert {c['slot'] for c in metadata['callbacks']} == set(range(730, 808)) - {746, 761, 776, 793}
    assert all(int(c['offset'], 16) == c['slot'] * 4 for c in metadata['callbacks'])
    for row in [c['bridge'] for c in metadata['callbacks']] + [metadata['registered_callback']]:
        check_bridge(row)
    assert bridges[0x606643] == 0x6C2530
    for target in navigation['targets'][:5]:
        assert len(target['references']) == 1
        ref = target['references'][0]
        raw = disk(int(ref['site'], 16), 5)
        assert raw[0] == 0xE9
        assert int(ref['site'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == int(target['target'], 16)

    anchors = {
        0x6284E5: ('mov', 'dword ptr [eax], 0xa22600'),
        0x6284EE: ('add', 'ecx, 8'), 0x6284FD: ('add', 'ecx, 0x324'),
        0x62850F: ('add', 'ecx, 0x35c'), 0x628521: ('add', 'ecx, 0x36c'),
        0x628533: ('add', 'ecx, 0x37c'), 0x628541: ('add', 'ecx, 0x74c'),
        0x62854F: ('add', 'ecx, 0xb1c'), 0x62855D: ('add', 'ecx, 0xb2c'),
        0x62856F: ('add', 'ecx, 0xb40'), 0x628581: ('add', 'ecx, 0xb54'),
        0x6285FE: ('push', '0x3d0'), 0x62863E: ('push', '0xc'),
        0x6C1331: ('lea', 'eax, [ebp - 0x1b0]'),
        0x6C1338: ('lea', 'ecx, [ebp - 0x168]'),
        0x6C1344: ('lea', 'edx, [ebp - 0x15c]'),
        0x6C13E5: ('add', 'ecx, 8'),
        0x6C1AB3: ('cmp', 'ecx, 0x36'), 0x6C1AD7: ('cmp', 'dword ptr [ebp - 0x14], 6'),
        0x6C1ADB: ('jbe', '0x6c1af1'),
        0x6C1AF1: ('push', '0x30'), 0x6C1AF3: ('mov', 'edx, 6'),
        0x6C1B40: ('imul', 'edx, edx, 0xa'),
        0x6C1B4E: ('lea', 'edx, [ecx + eax - 1]'),
        0x6C1B92: ('add', 'edx, 1'), 0x6C1C0D: ('cmp', 'eax, 0xa'),
        0x6C1C4E: ('ret', '0x20'),
        0x6C15D2: ('mov', 'dword ptr [ecx + 0x14], eax'),
        0x6C15F5: ('push', '0x104'), 0x6C15FD: ('add', 'edx, 0x18'),
        0x6C161C: ('push', '0x104'), 0x6C1624: ('add', 'eax, 0x11c'),
        0x6C1645: ('push', '0x104'), 0x6C164D: ('add', 'ecx, 0x220'),
        0x6C1680: ('add', 'eax, 1'),
        0x6C170A: ('push', '0x80'), 0x6C1731: ('push', '0x400'),
        0x6C178B: ('add', 'ecx, 0x324'),
        0x6C558E: ('push', '0x484'), 0x6C5CF9: ('push', '1'),
        0x6C5DA6: ('mov', 'ecx, 0x484'), 0x6C5DAB: ('idiv', 'ecx'),
        0x6C7A26: ('cmp', 'edx, dword ptr [ecx]'),
        0x6C7A28: ('sbb', 'eax, eax'), 0x6C7A2A: ('neg', 'eax'),
        0x6C7A76: ('mov', 'ecx, 0x484'), 0x6C7A7B: ('idiv', 'ecx'),
        0x6C7B6D: ('ret', '0xc'),
        0x6C7C09: ('imul', 'eax, eax, 0x484'),
        0x6C8270: ('mov', 'byte ptr [eax + 4], dl'),
        0x6C88D6: ('add', 'eax, 0xc'),
    }
    anchor_results = []
    for ea, expected in anchors.items():
        instruction = decoded[ea]
        actual = (instruction.mnemonic, instruction.op_str)
        assert actual == expected, (hex(ea), actual, expected)
        anchor_results.append({'va': hex(ea), 'bytes': instruction.bytes.hex(), 'decoded': ' '.join(actual)})

    documents = {}
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
        documents[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    resource_observation = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / 'Data').rglob('*')
                                  if p.is_file() and 'stock' in p.name.casefold())
    result = {
        'status': 'PASS', 'disk_sha256': EXPECTED_SHA, 'decoder': 'Capstone x86 32-bit',
        'functions': len(functions), 'declared_chunk_records': chunks,
        'legacy_instruction_ranges_without_chunk_declaration': legacy_ranges,
        'decoded_instructions': instruction_count, 'selected_call_bridges': call_bridge_count,
        'checked_direct_call_records': checked_calls,
        'unique_bridges_including_callback_navigation': len(bridges),
        'callback_navigation_count': 74, 'callback_body_reviews': 0,
        'identity_records': identity_records, 'identity_bytes_with_repeated_ranges': identity_bytes,
        'bss_only_observations': sorted(set(unmapped)), 'rtc_maps': rtc_maps,
        'semantic_anchor_checks': len(anchors), 'anchors': anchor_results,
        'stock_resource_observation': resource_observation,
        'source_sha256': source_hashes, 'document_sha256': documents, 'blocking_findings': [],
        'scope': '离线磁盘字节、独立指令边界、桥及局部关键契约；未运行客户端，不证明全部依赖或业务消费者',
    }
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('anchors', 'source_sha256', 'document_sha256')}, ensure_ascii=True))


if __name__ == '__main__':
    main()
