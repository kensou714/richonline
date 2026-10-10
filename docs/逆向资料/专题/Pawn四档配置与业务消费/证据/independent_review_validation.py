"""独立 PE/Capstone 与 Pawn 资源检查；仅写本专题独审证据。"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

import lzokay
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--show', nargs=2, metavar=('START_VA', 'END_VA'))
    args = parser.parse_args()
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
        assert len(mappings) == 1, (hex(ea), size)
        rva, offset = mappings[0]
        start = offset + ea - base - rva
        result = blob[start:start + size]
        assert len(result) == size
        return result

    def check_range(row):
        actual = disk(int(row['va'], 16), row['size'])
        assert row.get('matching', row.get('equal')) is True
        assert actual == bytes.fromhex(row['disk_hex']) == bytes.fromhex(row['idb_hex'])
        if 'sha256' in row:
            assert hashlib.sha256(actual).hexdigest() == row['sha256']

    hashes = {}

    def load(path):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text('utf-8'))

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoded, functions, bridges = {}, {}, {}
    chunk_count, instruction_count, call_count = 0, 0, 0

    def check_bridge(ea, expected):
        raw = disk(ea, 5)
        assert raw[0] == 0xE9
        target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == expected
        assert ea not in bridges or bridges[ea] == expected
        bridges[ea] = expected

    inputs = {name: load(HERE / name) for name in ('functions_raw.json', 'helpers_raw.json', 'reused_raw.json')}
    for name, data in inputs.items():
        if 'disk_sha256' in data:
            assert data['disk_sha256'] == EXPECTED_SHA
        for function in data['functions']:
            va = function['va']
            assert va not in functions
            functions[va] = function
            ranges = function.get('chunk_byte_ranges', function.get('chunks'))
            assert ranges
            if 'declared_chunks' in function:
                assert function['bytes_match_disk'] is True
                assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']] == [
                    (int(r['va'], 16), int(r['va'], 16) + r['size']) for r in ranges]
            sites = []
            for row in ranges:
                check_range(row)
                ea = int(row['va'], 16)
                instructions = list(decoder.disasm(disk(ea, row['size']), ea))
                assert sum(i.size for i in instructions) == row['size'], va
                for instruction in instructions:
                    assert instruction.address not in decoded
                    decoded[instruction.address] = instruction
                    sites.append(instruction.address)
                chunk_count += 1
                instruction_count += len(instructions)
            original = function.get('assembly', function.get('instructions'))
            assert sites == [int(r['va'], 16) for r in original], va
            for row in function.get('byte_ranges', []):
                check_range(row)
            for row in function.get('instructions', []):
                instruction = decoded[int(row['va'], 16)]
                assert instruction.size == row['size'] and instruction.bytes.hex() == row['hex']
        for row in data.get('thunks', []):
            check_range(row)
            check_bridge(int(row['va'], 16), int(row['target'], 16))

    for function in functions.values():
        calls = function.get('calls', [c for c in function.get('outgoing', []) if c['iscode'] and c['kind'] == 17])
        for call in calls:
            instruction = decoded[int(call['site'], 16)]
            assert instruction.mnemonic in ('call', 'jmp')
            assert instruction.op_str == call['target'], call
            target = int(call['target'], 16)
            chain = call.get('thunks', call.get('chain', []))
            for index, thunk in enumerate(chain):
                assert int(thunk, 16) == target
                destination = int(chain[index + 1] if index + 1 < len(chain) else call['implementation'], 16)
                check_bridge(target, destination)
                target = destination
            assert target == int(call['implementation'], 16)
            call_count += 1
    for provenance in inputs['reused_raw.json']['provenance']:
        path = ROOT / provenance['source']
        original = load(path)
        assert hashes[path.relative_to(ROOT).as_posix()] == provenance['source_sha256']
        by_va = {f['va']: f for f in original['functions']}
        for va in provenance['functions']:
            assert functions[va] == by_va[va]

    constants = load(HERE / 'bridges_constants_raw.json')
    assert constants['disk_sha256'] == EXPECTED_SHA
    for row in constants['bridges']:
        check_range(row)
        check_bridge(int(row['va'], 16), int(row['target'], 16))
    for row in constants['constant_windows']:
        check_range(row)
    assert disk(0xA76700, 4) == bytes(4)
    assert constants['singleton_storage']['storage'] == 'raw-backed .data'
    assert constants['singleton_storage']['disk_hex'] == disk(0xA76700, 4).hex()

    tables = load(HERE / 'jump_tables_raw.json')
    expected_tables = {
        0x7F265D: (0x7F26CF, [0x7F2664, 0x7F2673, 0x7F2682, 0x7F2694]),
        0x7F270D: (0x7F277E, [0x7F2714, 0x7F2723, 0x7F2732, 0x7F2744]),
        0x7F27EE: (0x7F28E7, [0x7F27F5, 0x7F282F, 0x7F2863, 0x7F289D]),
    }
    assert len(tables) == len(expected_tables)
    for row in tables:
        check_range(row)
        site = int(row['site'], 16)
        ea, targets = expected_tables[site]
        assert int(row['va'], 16) == ea
        assert list(struct.unpack('<4I', disk(ea, 16))) == targets
        assert row['targets'] == [hex(v) for v in targets]
        assert decoded[site].mnemonic == 'jmp' and hex(ea) in decoded[site].op_str
        assert all(v in decoded for v in targets)

    anchors = {
        0x628C1B: ('cmp', 'dword ptr [0xa76700], 0'),
        0x628C24: ('push', '0xd0'), 0x628C37: ('mov', 'dword ptr [0xa76700], eax'),
        0x64F211: ('add', 'eax, 0x64'),
        0x623F99: ('jne', '0x623fa2'), 0x623F9B: ('xor', 'eax, eax'),
        0x7F1DDA: ('jne', '0x7f1e0f'),
        0x7F1DDC: ('mov', 'dword ptr [ebp - 0x168], 0'),
        0x7F1E17: ('push', '0'), 0x7F1E2B: ('push', '2'),
        0x7F1E81: ('fstp', 'qword ptr [eax]'),
        0x7F1EBC: ('fstp', 'qword ptr [eax + 8]'),
        0x7F1F08: ('fstp', 'qword ptr [eax + 0x10]'),
        0x7F1F44: ('fstp', 'qword ptr [eax + 0x18]'),
        0x7F1F90: ('fstp', 'qword ptr [eax + 0x20]'),
        0x7F1FCC: ('fstp', 'qword ptr [eax + 0x28]'),
        0x7F2018: ('fstp', 'qword ptr [eax + 0x30]'),
        0x7F2054: ('fstp', 'qword ptr [eax + 0x38]'),
        0x7F20A0: ('mov', 'dword ptr [ecx + 0x40], eax'),
        0x7F2165: ('mov', 'dword ptr [edx + 0x64], eax'),
        0x7F222A: ('mov', 'dword ptr [ecx + 0x88], eax'),
        0x7F22F8: ('mov', 'dword ptr [edx + 0xac], eax'),
        0x7F20BE: ('jge', '0x7f211c'), 0x7F2183: ('jge', '0x7f21e1'),
        0x7F224E: ('jge', '0x7f22af'), 0x7F231C: ('jge', '0x7f237d'),
        0x7F2116: ('mov', 'dword ptr [edx + ecx*4 + 0x44], eax'),
        0x7F21DB: ('mov', 'dword ptr [ecx + edx*4 + 0x68], eax'),
        0x7F22A6: ('mov', 'dword ptr [edx + ecx*4 + 0x8c], eax'),
        0x7F2374: ('mov', 'dword ptr [ecx + edx*4 + 0xb0], eax'),
        0x7F237D: ('mov', 'dword ptr [ebp - 0x16c], 1'),
        0x7F2658: ('ja', '0x7f26a4'), 0x7F2708: ('ja', '0x7f2754'),
        0x7F27D4: ('mov', 'al, 1'), 0x7F27E5: ('ja', '0x7f28d5'),
        0x7F2810: ('jge', '0x7f282a'), 0x7F284A: ('jge', '0x7f2861'),
        0x7F2881: ('jge', '0x7f289b'), 0x7F28BB: ('jge', '0x7f28d5'),
        0x7F28D5: ('xor', 'al, al'), 0x7F28E4: ('ret', '0xc'),
        0x7B9F07: ('cmp', 'dword ptr [ebp + 0xc], 1'),
        0x7B9F4D: ('jae', '0x7b9f67'), 0x7B9FAD: ('jae', '0x7b9fc7'),
        0x7B9FFD: ('jae', '0x7ba017'),
        0x7B9F55: ('mov', 'ecx, dword ptr [eax + edx*4 + 0x228]'),
        0x7B9FB5: ('mov', 'eax, dword ptr [edx + ecx*4 + 0x3b4]'),
        0x7BA005: ('mov', 'eax, dword ptr [edx + ecx*4 + 0x6cc]'),
        0x7BA0C1: ('mov', 'ecx, dword ptr [eax + 0x34]'),
        0x7BA0C8: ('mov', 'eax, dword ptr [edx + 0x30]'),
        0x7BA0DE: ('mov', 'eax, dword ptr [edx + 0x38]'),
        0x7BA0F4: ('mov', 'eax, dword ptr [edx + 0x3c]'),
        0x7BA127: ('mov', 'edx, dword ptr [ecx + 0x40]'),
        0x7BA12E: ('mov', 'ecx, dword ptr [eax + 0x44]'),
        0x7BA145: ('mov', 'al, 1'), 0x7BA149: ('xor', 'al, al'),
        0x7BA158: ('ret', '4'),
        0x75D05F: ('mov', 'ecx, dword ptr [eax]'),
        0x75D0EB: ('jge', '0x75d12b'),
        0x75D0F3: ('mov', 'eax, dword ptr [edx + ecx*4]'),
        0x75D0F7: ('push', '0x50'),
        0x75D138: ('call', '0x602ffc'),
        0x75ECDA: ('mov', 'ecx, dword ptr [eax + 0x98]'),
        0x75ED21: ('mov', 'edx, dword ptr [ecx + eax*4]'),
        0x75ED35: ('mov', 'dword ptr [ecx + 0x60], eax'),
    }
    for ea, expected in anchors.items():
        instruction = decoded[ea]
        assert (instruction.mnemonic, instruction.op_str) == expected, hex(ea)
    for ea, value in ((0x629DD5, 0), (0x629DF5, 1), (0x63EDD5, 2),
                      (0x63E1A5, 3), (0x629E15, 4)):
        assert decoded[ea].mnemonic == 'cmp'
        assert decoded[ea].op_str == f'dword ptr [ebp + 8], {value}'
    expected_calls = {
        0x7F1E76: 0x924720, 0x7F2095: 0x91F950,
        0x7F27B2: 0x63EDD0, 0x7F27C5: 0x63E1A0,
        0x7BA032: 0x629DD0, 0x7BA045: 0x629DF0, 0x7BA058: 0x63EDD0,
        0x7BA06B: 0x63E1A0, 0x7BA07E: 0x629E10,
        0x7BA0CF: 0x7B9EF0, 0x7BA0E5: 0x7B9F80, 0x7BA0FB: 0x7B9FD0,
        0x7BA111: 0x7BA020, 0x7BA132: 0x628C10, 0x7BA139: 0x7F2790,
        0x75D06F: 0x7F2630, 0x75D082: 0x7F26E0, 0x75ED08: 0x7F26E0,
        0x75D138: 0x8F3FD0,
    }
    for site, expected in expected_calls.items():
        target = int(decoded[site].op_str, 16)
        visited = set()
        while target in bridges:
            assert target not in visited
            visited.add(target)
            target = bridges[target]
        assert target == expected, hex(site)
    ledger = load(TOPIC / '函数审阅清单.json')['functions']
    assert len(ledger) == len(functions) == 19
    assert {r['va'] for r in ledger} == set(functions)
    status_counts = Counter(r['status'] for r in ledger)
    assert status_counts == {'完成': 9, '局部完成': 1, '复用局部完成': 2, '复用完成': 7}
    for row in ledger:
        assert all(row.get(key) for key in ('conclusion', 'unknown', 'evidence'))
        assert all((TOPIC / path).is_file() for path in row['evidence'])

    resource = load(HERE / 'resource_rows.json')
    packed_blob = (ROOT / resource['source']).read_bytes()
    assert len(packed_blob) == resource['size']
    assert hashlib.sha256(packed_blob).hexdigest() == resource['sha256']
    key = packed_blob[0]
    size, packed_size = struct.unpack('<II', bytes((v - key) & 255 for v in packed_blob[1:9]))
    decoded_resource = lzokay.decompress(bytes((v - key) & 255 for v in packed_blob[9:9 + packed_size]), size)
    assert (key, size, packed_size, len(packed_blob) - 9 - packed_size) == (
        resource['key'], resource['decoded_size'], resource['packed_size'], resource['tail_size'])
    assert decoded_resource.hex() == resource['decoded_hex']
    assert hashlib.sha256(decoded_resource).hexdigest() == resource['decoded_sha256']
    assert len(decoded_resource.splitlines()) == len(resource['rows'])
    for line, row in zip(decoded_resource.splitlines(), resource['rows']):
        fields = line.split(b'\t')
        assert line.hex() == row['raw_hex']
        assert [v.hex() for v in fields] == row['fields_hex'] and len(fields) == row['field_count']
        assert [v.decode('gbk', errors='backslashreplace') for v in fields] == row['gbk_candidate']
        assert [v.decode('big5', errors='backslashreplace') for v in fields] == row['big5_candidate']
    assert decoded_resource.splitlines()[1].decode('gbk') == '// 各类频道金豆限制'
    assert decoded_resource.splitlines()[18].decode('gbk') == '// 各类频道押金数值'
    for doc in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in doc.read_text('utf-8').splitlines())

    if args.show:
        start, end = (int(v, 16) for v in args.show)
        for ea, instruction in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X}  {instruction.mnemonic:8} {instruction.op_str}')
        return
    documents = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in TOPIC.glob('*.txt')}
    result = dict(status='PASS', disk_sha256=EXPECTED_SHA, functions=len(functions),
                  declared_or_legacy_chunks=chunk_count, decoded_instructions=instruction_count,
                  checked_call_records=call_count, unique_bridges=len(bridges),
                  constant_windows=len(constants['constant_windows']), resource_rows=len(resource['rows']),
                  resource_sha256=resource['sha256'], decoded_resource_sha256=resource['decoded_sha256'],
                  singleton_storage=dict(va='0xa76700', classification='raw-backed .data', disk_hex='00000000'),
                  jump_tables=len(tables), semantic_anchors=len(anchors) + 5,
                  semantic_call_targets=len(expected_calls), semantic_status=dict(status_counts),
                  source_sha256=hashes, document_sha256=documents,
                  boundary='全部声明块字节与指令独立核验；16完整及3局部语义已核；未动态验收、未认领LMT消费与资金网络语义')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('source_sha256', 'document_sha256')}, ensure_ascii=True))


if __name__ == '__main__':
    main()
