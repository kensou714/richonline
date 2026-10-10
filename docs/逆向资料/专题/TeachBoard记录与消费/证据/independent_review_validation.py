"""独立 PE/Capstone/TeachBoard 资源核验；仅写本专题独审产物。"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

import lzokay
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--show', nargs=2, metavar=('START_VA', 'END_VA'))
    parser.add_argument('--resource-only', action='store_true')
    args = parser.parse_args()
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    imports = pefile.PE(data=blob)
    imported_tick = [(entry.dll, item.name) for entry in imports.DIRECTORY_ENTRY_IMPORT
                     for item in entry.imports if item.address == 0xAD3CBC]
    assert imported_tick == [(b'KERNEL32.dll', b'GetTickCount')]
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
        assert len(mappings) <= 1, (hex(ea), size)
        if not mappings:
            return None
        rva, offset = mappings[0]
        start = offset + ea - base - rva
        result = blob[start:start + size]
        assert len(result) == size
        return result

    assert disk(0xA839A4, 32) is None
    assert any(base + rva + raw_size <= 0xA839A4 and 0xA839A4 + 32 <= base + rva + virtual_size
               for virtual_size, rva, raw_size, _ in sections)
    hashes = {}

    def load(path):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text('utf-8'))

    resource = load(HERE / 'resource_rows.json')
    packed_blob = (ROOT / resource['source']).read_bytes()
    assert len(packed_blob) == resource['size'] == 64
    assert hashlib.sha256(packed_blob).hexdigest() == resource['sha256']
    key = packed_blob[0]
    size, packed_size = struct.unpack('<II', bytes((v - key) & 255 for v in packed_blob[1:9]))
    data = lzokay.decompress(bytes((v - key) & 255 for v in packed_blob[9:9 + packed_size]), size)
    assert (key, size, packed_size, len(packed_blob) - 9 - packed_size) == (90, 82, 55, 0)
    assert data.hex() == resource['decoded_hex']
    assert hashlib.sha256(data).hexdigest() == resource['decoded_sha256']
    expected_rows = [
        [b'other_49_17', b',', b',', b','],
        [b'other_49_18', b'other_49_19', b',', b','],
        [b'other_49_20', b',', b',', b','],
        [b'other_49_21', b',', b',', b','],
    ]
    assert data == b''.join(b'\t'.join(row) + b'\n' for row in expected_rows)
    assert len(resource['rows']) == 4
    for number, (raw, expected, row) in enumerate(zip(data.splitlines(), expected_rows, resource['rows']), 1):
        assert row['line'] == number and raw.hex() == row['raw_hex']
        assert raw.split(b'\t') == expected and row['field_count'] == 4
        assert row['fields_hex'] == [field.hex() for field in expected]
        assert row['gbk_candidate'] == row['big5_candidate'] == [v.decode('ascii') for v in expected]
    if args.resource_only:
        print(json.dumps(dict(status='RESOURCE_CHECKED', rows=4, decoded_size=82,
                              virtual_global='0xa839a4', disk_backed=False)))
        return

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    functions, decoded, bridges = {}, {}, {}
    counters = dict(chunks=0, instructions=0, calls=0, indirect_pointer_records=0,
                    ranges=0, bytes_with_repeated_ranges=0)

    def check_range(row):
        actual = disk(int(row['va'], 16), row['size'])
        assert actual is not None, row['va']
        assert row.get('matching', row.get('equal')) is True
        assert actual == bytes.fromhex(row['disk_hex']) == bytes.fromhex(row['idb_hex'])
        if 'sha256' in row:
            assert hashlib.sha256(actual).hexdigest() == row['sha256']
        counters['ranges'] += 1
        counters['bytes_with_repeated_ranges'] += len(actual)

    def check_bridge(ea, expected):
        raw = disk(ea, 5)
        assert raw is not None and raw[0] == 0xE9
        target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == expected
        assert ea not in bridges or bridges[ea] == expected
        bridges[ea] = expected

    paths = [HERE / name for name in ('functions_raw.json', 'consumers_raw.json', 'helpers_raw.json',
                                     'closure_raw.json', 'reused_raw.json')
             if (HERE / name).is_file()]
    assert (HERE / 'functions_raw.json') in paths and (HERE / 'consumers_raw.json') in paths
    for path in paths:
        payload = load(path)
        if 'disk_sha256' in payload:
            assert payload['disk_sha256'] == EXPECTED_SHA
        for function in payload['functions']:
            va = function.get('va', function.get('address'))
            assert va not in functions
            functions[va] = function
            chunks = function.get('chunk_byte_ranges', function.get('chunks', function.get('byte_ranges')))
            assert chunks
            if 'declared_chunks' in function:
                assert function['bytes_match_disk'] is True
                assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']] == [
                    (int(r['va'], 16), int(r['va'], 16) + r['size']) for r in chunks]
            sites = []
            for row in chunks:
                if 'bytes_hex' in row:
                    ea = int(row['start'], 16)
                    size = int(row['end'], 16) - ea
                    actual = disk(ea, size)
                    assert actual == bytes.fromhex(row['bytes_hex'])
                    assert hashlib.sha256(actual).hexdigest() == row['sha256'].lower()
                    counters['ranges'] += 1
                    counters['bytes_with_repeated_ranges'] += size
                else:
                    check_range(row)
                    ea, size = int(row['va'], 16), row['size']
                instructions = list(decoder.disasm(disk(ea, size), ea))
                assert sum(i.size for i in instructions) == size, va
                for instruction in instructions:
                    assert instruction.address not in decoded
                    decoded[instruction.address] = instruction
                    sites.append(instruction.address)
                counters['chunks'] += 1
                counters['instructions'] += len(instructions)
            assert sites == [int(r.get('va', r.get('ea')), 16)
                             for r in function.get('assembly', function.get('instructions'))], va
            for row in function.get('byte_ranges', []):
                check_range(row)
            for row in function.get('instructions', []):
                instruction = decoded[int(row['va'], 16)]
                assert instruction.size == row['size'] and instruction.bytes.hex() == row['hex']
        for row in payload.get('thunks', []):
            check_range(row)
            check_bridge(int(row['va'], 16), int(row['target'], 16))
        for provenance in payload.get('provenance', []):
            original_path = ROOT / provenance['source']
            original = load(original_path)
            assert hashes[original_path.relative_to(ROOT).as_posix()] == provenance['source_sha256']
            by_va = {f.get('va', f.get('address')): f for f in original['functions']}
            for va in provenance['functions']:
                assert functions[va] == by_va[va]
    for function in functions.values():
        calls = function.get('calls', [c for c in function.get('outgoing', []) if c['iscode'] and c['kind'] == 17])
        for call in calls:
            instruction = decoded[int(call['site'], 16)]
            if instruction.mnemonic == 'call' and instruction.op_str == f"dword ptr [{call['target']}]":
                assert not call.get('thunks', call.get('chain', []))
                assert call['target'] == call['implementation']
                counters['indirect_pointer_records'] += 1
                continue
            assert instruction.mnemonic in ('call', 'jmp') and instruction.op_str == call['target'], (call, instruction.mnemonic, instruction.op_str)
            target = int(call['target'], 16)
            chain = call.get('thunks', call.get('chain', []))
            for index, thunk in enumerate(chain):
                assert int(thunk, 16) == target
                destination = int(chain[index + 1] if index + 1 < len(chain) else call['implementation'], 16)
                check_bridge(target, destination)
                target = destination
            assert target == int(call['implementation'], 16)
            counters['calls'] += 1
    constants = load(HERE / 'constants_raw.json')
    assert constants['disk_sha256'] == EXPECTED_SHA
    for row in constants['constant_windows']:
        check_range(row)
    for row in constants['globals']:
        assert disk(int(row['va'], 16), row['size']) is None and row['disk_hex'] is None
        assert row['matching'] is False
    scan_format = b'%[^\t]\t%[^\t]\t%[^\t]\t%[^\t]\0'
    assert disk(0xA24088, len(scan_format)) == scan_format
    assert disk(0xA2ABA0, 6) == b'%d/%d\0'
    anchors = {
        0x6DFDD4: ('test', 'eax, eax'),
        0x6DFDD6: ('jne', '0x6dfdf9'),
        0x6DFE10: ('push', '0'),
        0x6DFE24: ('push', '2'),
        0x6DFE4E: ('mov', 'ecx, 0x7f'),
        0x6DFE88: ('mov', 'ecx, 0x1f'),
        0x6DFE9A: ('lea', 'eax, [ebp - 0x318]'),
        0x6DFEA1: ('lea', 'ecx, [ebp - 0x338]'),
        0x6DFEA8: ('lea', 'edx, [ebp - 0x358]'),
        0x6DFEAF: ('lea', 'eax, [ebp - 0x378]'),
        0x6DFEC7: ('add', 'esp, 0x18'),
        0x6DFECA: ('mov', 'dword ptr [ebp - 0x380], 0'),
        0x6DFEE5: ('cmp', 'dword ptr [ebp - 0x380], 4'),
        0x6DFEF4: ('shl', 'eax, 5'),
        0x6DFF07: ('cmp', 'eax, 1'),
        0x6DFF0A: ('jne', '0x6dff0e'),
        0x6DFF31: ('cmp', 'dword ptr [ebp - 0x388], -1'),
        0x6DFF55: ('mov', 'ecx, 0xa839a4'),
        0x6E0133: ('jae', '0x6e0152'),
        0x6E014D: ('mov', 'dword ptr [ecx + 8], eax'),
        0x6E01DF: ('mov', 'eax, dword ptr [ecx + 0xc]'),
        0x6E01E5: ('sar', 'eax, 4'),
        0x6E0221: ('mov', 'ecx, dword ptr [eax + 8]'),
        0x6E027F: ('mov', 'eax, dword ptr [ecx + 8]'),
        0x6E0285: ('sar', 'eax, 4'),
        0x6E0381: ('mov', 'ecx, dword ptr [eax + 4]'),
        0x6E03D9: ('shl', 'eax, 4'),
        0x6E052C: ('shr', 'esi, 1'),
        0x6E0549: ('shr', 'ecx, 1'),
        0x6E054B: ('add', 'ecx, dword ptr [ebp - 0x30]'),
        0x6E066C: ('mov', 'dword ptr [eax + 0xc], edx'),
        0x6E067B: ('mov', 'dword ptr [edx + 8], ecx'),
        0x6E0684: ('mov', 'dword ptr [eax + 4], ecx'),
        0x6E0AD1: ('shl', 'eax, 4'),
        0x6E0AD7: ('add', 'eax, dword ptr [ecx]'),
        0x6E0CF4: ('mov', 'dword ptr [eax], ecx'),
        0x6E0D26: ('sub', 'eax, dword ptr [ecx]'),
        0x6E0D28: ('sar', 'eax, 4'),
        0x6E12D2: ('add', 'edx, 0x10'),
        0x646971: ('mov', 'dword ptr [eax + 4], 0'),
        0x64697B: ('mov', 'dword ptr [ecx + 8], 0'),
        0x646985: ('mov', 'dword ptr [edx + 0xc], 0'),
        0x63F8A5: ('sar', 'eax, 2'),
        0x6DAA39: ('cmp', 'dword ptr [ebp + 8], 0'),
        0x6DAA49: ('or', 'eax, 0xffffffff'),
        0x7684AC: ('mov', 'eax, dword ptr [edx + 0x4c]'),
        0x7684B3: ('mov', 'edx, dword ptr [ecx + 0x48]'),
        0x7684E5: ('cmp', 'eax, 1'),
        0x768508: ('call', 'dword ptr [edx + 0xc8]'),
        0x768560: ('call', 'dword ptr [edx + 0xc4]'),
        0x7685C3: ('push', '-1'),
        0x768607: ('add', 'edx, 1'),
        0x76863C: ('call', 'dword ptr [edx + 0x90]'),
        0x79C861: ('mov', 'eax, dword ptr [eax]'),
        0x81A2FA: ('cmp', 'edx, 0xa'),
        0x81A30D: ('mov', 'byte ptr [edx], al'),
        0x81A332: ('mov', 'byte ptr [edx], 0'),
        0x81A359: ('mov', 'dword ptr [edx + 0x9c], ecx'),
    }
    for ea, expected in anchors.items():
        instruction = decoded[ea]
        assert (instruction.mnemonic, instruction.op_str) == expected, hex(ea)
    semantic_targets = {
        0x6DFE2C: 0x819250, 0x6DFE37: 0x6C5510, 0x6DFE6D: 0x81A2E0,
        0x6DFE78: 0x6466C0, 0x6DFEC2: 0x920600, 0x6DFEFF: 0x91FB00,
        0x6DFF26: 0x6DAA10, 0x6DFF47: 0x646750, 0x6DFF5A: 0x6E0100,
        0x6DFF69: 0x646720, 0x6E0122: 0x6E0250, 0x6E012C: 0x6E01B0,
        0x6E0145: 0x6E03B0, 0x6E016C: 0x6E02B0, 0x6E030D: 0x6E0490,
        0x6E0429: 0x6E0AC0, 0x6E0A95: 0x6E0CE0, 0x6E0B16: 0x6E0D10,
        0x6E0DF2: 0x6E1290, 0x7684B7: 0x798D80, 0x7684DD: 0x798CE0,
        0x7685F8: 0x798CE0, 0x79B031: 0x79C850,
    }
    for ea, expected in semantic_targets.items():
        instruction = decoded[ea]
        assert instruction.mnemonic == 'call'
        target = int(instruction.op_str, 16)
        while disk(target, 5)[0] == 0xE9:
            raw = disk(target, 5)
            destination = target + 5 + struct.unpack_from('<i', raw, 1)[0]
            check_bridge(target, destination)
            target = destination
        assert target == expected, hex(ea)
    if args.show:
        start, end = (int(value, 16) for value in args.show)
        for ea, instruction in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X}  {instruction.mnemonic:8} {instruction.op_str}')
        return
    ledger_path = TOPIC / '函数审阅清单.json'
    ledger = load(ledger_path)['functions']
    assert len(functions) == len(ledger) == 35
    assert {row['va'] for row in ledger} == set(functions)
    status_counts = dict(Counter(row['status'] for row in ledger))
    assert status_counts == {'完成': 24, '局部完成': 2, '复用局部完成': 6, '复用完成': 3}
    for row in ledger:
        assert all(row.get(key) for key in ('status', 'conclusion', 'unknown', 'evidence'))
        assert all((TOPIC / evidence).is_file() for evidence in row['evidence'])
    documents = sorted(TOPIC.glob('*.txt'))
    assert len(documents) >= 6
    for path in documents:
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in path.read_text('utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=EXPECTED_SHA, functions=len(functions),
                  **counters, unique_bridges=len(bridges), constant_windows=len(constants['constant_windows']),
                  semantic_anchors=len(anchors), semantic_call_targets=len(semantic_targets),
                  resource_rows=4, virtual_global='0xa839a4', virtual_global_disk_backed=False,
                  imported_pointer='0xad3cbc=KERNEL32.dll!GetTickCount',
                  new_functions=26, reused_functions=9, semantic_status=status_counts,
                  source_sha256=hashes,
                  boundary='正文与分级清单独审通过；深层容器、扫描器、控件虚槽和运行测试未闭合。')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
