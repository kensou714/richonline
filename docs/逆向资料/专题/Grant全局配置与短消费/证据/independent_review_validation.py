"""Grant 独立磁盘/Capstone 核验；不调用 IDA 或作者验证器。"""
import argparse
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--show', nargs=2)
    parser.add_argument('--evidence-only', action='store_true')
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
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    hashes, functions, decoded, bridges = {}, {}, {}, {}
    counters = dict(chunks=0, instructions=0, calls=0, ranges=0,
                    bytes_with_repeated_ranges=0, window_items=0,
                    legacy_instructions=0, consumer_window_instructions=0)

    def load(path):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text('utf-8'))

    def disk(ea, size):
        mappings = [(rva, offset) for _, rva, raw_size, offset in sections
                    if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(mappings) <= 1
        if not mappings:
            return None
        rva, offset = mappings[0]
        start = offset + ea - base - rva
        actual = blob[start:start + size]
        assert len(actual) == size
        return actual

    def check_range(row):
        ea, size = int(row['va'], 16), row['size']
        actual = disk(ea, size)
        assert actual is not None and row.get('matching', row.get('equal')) is True, row
        assert actual == bytes.fromhex(row['disk_hex']) == bytes.fromhex(row['idb_hex']), hex(ea)
        if 'sha256' in row:
            assert hashlib.sha256(actual).hexdigest() == row['sha256']
        counters['ranges'] += 1
        counters['bytes_with_repeated_ranges'] += size
        return actual

    def decode(ea, raw):
        instructions = list(decoder.disasm(raw, ea))
        assert sum(row.size for row in instructions) == len(raw), hex(ea)
        for instruction in instructions:
            prior = decoded.get(instruction.address)
            assert prior is None or prior.bytes == instruction.bytes
            decoded[instruction.address] = instruction
        return instructions

    def check_bridge(ea, expected):
        raw = disk(ea, 5)
        assert raw is not None and raw[0] == 0xE9
        assert ea + 5 + struct.unpack_from('<i', raw, 1)[0] == expected
        assert ea not in bridges or bridges[ea] == expected
        bridges[ea] = expected

    def check_call(row):
        instruction = decoded[int(row['site'], 16)]
        assert instruction.mnemonic in ('call', 'jmp')
        assert instruction.op_str == row['target'], (row, instruction.op_str)
        target = int(row['target'], 16)
        chain = row.get('thunks', row.get('chain', []))
        for index, thunk in enumerate(chain):
            assert target == int(thunk, 16)
            destination = int(chain[index + 1] if index + 1 < len(chain)
                              else row['implementation'], 16)
            check_bridge(target, destination)
            target = destination
        assert target == int(row['implementation'], 16)
        counters['calls'] += 1

    for name in ('grant_core_raw.json', 'grant_supplement_raw.json', 'grant_reused_raw.json'):
        path = HERE / name
        if not path.is_file():
            assert name != 'grant_core_raw.json'
            continue
        payload = load(path)
        assert payload.get('disk_sha256', EXPECTED_SHA) == EXPECTED_SHA
        for function in payload.get('functions', []):
            va = function.get('va', function.get('address'))
            assert va not in functions
            functions[va] = function
            chunks = function.get('chunk_byte_ranges', function.get('chunks', function.get('byte_ranges')))
            assert chunks
            if 'declared_chunks' in function:
                assert function['bytes_match_disk'] is True
                assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']] == [
                    (int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks]
            sites = []
            for row in chunks:
                if 'bytes_hex' in row:
                    ea, end = int(row['start'], 16), int(row['end'], 16)
                    raw = disk(ea, end - ea)
                    assert raw == bytes.fromhex(row['bytes_hex'])
                    assert hashlib.sha256(raw).hexdigest() == row['sha256'].lower()
                    counters['ranges'] += 1
                    counters['bytes_with_repeated_ranges'] += len(raw)
                else:
                    raw = check_range(row)
                    ea = int(row['va'], 16)
                instructions = decode(ea, raw)
                sites.extend(instruction.address for instruction in instructions)
                counters['chunks'] += 1
                counters['instructions'] += len(instructions)
            assert sites == [int(r.get('va', r.get('ea')), 16)
                             for r in function.get('assembly', function.get('instructions'))], va
            for row in function.get('byte_ranges', []):
                check_range(row)
            for row in function.get('instructions', []):
                if 'hex' in row:
                    instruction = decoded[int(row['va'], 16)]
                    assert instruction.size == row['size'] and instruction.bytes.hex() == row['hex']
        for row in payload.get('thunks', []):
            check_range(row)
            check_bridge(int(row['va'], 16), int(row['target'], 16))
        for provenance in payload.get('provenance', []):
            original_path = ROOT / provenance['source']
            original = load(original_path)
            assert hashes[original_path.relative_to(ROOT).as_posix()] == provenance['source_sha256']
            original_functions = {f.get('va', f.get('address')): f for f in original['functions']}
            for va in provenance['functions']:
                assert functions[va] == original_functions[va]
    for function in functions.values():
        for row in function.get('calls', [r for r in function.get('outgoing', [])
                                         if r.get('iscode') and r['kind'] == 17]):
            check_call(row)
    reused = load(HERE / 'grant_reused_raw.json')
    limited_entries = set()
    for row in reused['legacy_rechecked_functions']:
        assert row['va'] not in functions
        limited_entries.add(row['va'])
        source = load(ROOT / row['source'])
        assert hashes[row['source']] == row['source_sha256']
        assert row['source_binary_sha256'] == source['sha256']
        old = next(f for f in source['functions'] if f['ea'] == row['va'])
        assert old['assembly'] == row['old_assembly']
        declarations_path = HERE / row['declaration_source']
        declarations_source = load(declarations_path)
        assert hashes[declarations_path.relative_to(ROOT).as_posix()] == row['declaration_source_sha256']
        declaration = next(r for r in declarations_source['reused_declarations'] if r['va'] == row['va'])
        assert declaration['declared_chunks'] == row['declared_chunks']
        assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in row['declared_chunks']] == [
            (int(c['va'], 16), int(c['va'], 16) + c['size']) for c in row['disk_ranges']]
        new = []
        for span in row['disk_ranges']:
            ea, size = int(span['va'], 16), span['size']
            raw = disk(ea, size)
            assert raw == bytes.fromhex(span['disk_hex'])
            assert hashlib.sha256(raw).hexdigest() == span['sha256']
            counters['ranges'] += 1
            counters['bytes_with_repeated_ranges'] += size
            new.extend(decode(ea, raw))
        assert [i.address for i in new] == [int(r['ea'], 16) for r in old['assembly']]
        assert len(new) == len(row['instructions'])
        counters['legacy_instructions'] += len(new)
        for instruction, provided, old_row in zip(new, row['instructions'], old['assembly']):
            assert instruction.bytes.hex() == provided['hex'] and instruction.size == provided['size']
            assert (instruction.mnemonic, instruction.op_str) == (provided['mnemonic'], provided['operands'])
            def normalized(text):
                text = text.split(';', 1)[0].lower()
                text = re.sub(r'\bshort\s+', '', text)
                for symbolic, numeric in [('var_4', '-4'), ('arg_0', '8'), ('arg_4', '12')]:
                    text = text.replace(symbolic, numeric)
                text = re.sub(r'loc_([0-9a-f]+)', r'0x\1', text)
                text = re.sub(r'\b([0-9a-f]+)h\b', lambda m: str(int(m[1], 16)), text)
                text = re.sub(r'0x([0-9a-f]+)', lambda m: str(int(m[1], 16)), text)
                text = text.replace('dword ptr', '').replace('jnz', 'jne').replace('retn', 'ret')
                return re.sub(r'\s+', '', text).replace('+-', '-')
            assert normalized(old_row['text']) == normalized(instruction.mnemonic + ' ' + instruction.op_str)
    for window in reused['consumer_windows']:
        limited_entries.add(window['owner'])
        source = load(ROOT / window['source'])
        assert hashes[window['source']] == window['source_sha256']
        old_format = isinstance(source['functions'], dict)
        old = source['functions'][window['owner']] if old_format else next(
            f for f in source['functions'] if f['va'] == window['owner'])
        start, end = int(window['start_va'], 16), int(window['end_va'], 16)
        source_rows = old['instructions'] if old_format else old['assembly']
        assert window['assembly'] == [r for r in source_rows if start <= int(r.get('va', r.get('ea')), 16) < end]
        source_ranges = old['ranges'] if old_format else old['byte_ranges']
        span = next(r for r in source_ranges if int(r.get('va', r.get('start')), 16) <= start and
                    (int(r['end'], 16) if 'end' in r else int(r['va'], 16) + r['size']) >= end)
        source_start = int(span.get('va', span.get('start')), 16)
        original = bytes.fromhex(span.get('idb_hex', span.get('idb_bytes_hex')))
        assert disk(source_start, len(original)) == original
        raw = check_range(window['raw_range'])
        assert raw == original[start - source_start:end - source_start]
        new = decode(start, raw)
        assert [i.address for i in new] == [int(r.get('va', r.get('ea')), 16) for r in window['assembly']]
        assert len(new) == len(window['instructions'])
        counters['consumer_window_instructions'] += len(new)
        for instruction, provided in zip(new, window['instructions']):
            assert instruction.bytes.hex() == provided['hex'] and instruction.size == provided['size']
            assert (instruction.mnemonic, instruction.op_str) == (provided['mnemonic'], provided['operands'])
        for row in window['calls']:
            check_call(row)
    for row in reused['reference_sources']:
        source = load(ROOT / row['source'])
        assert hashes[row['source']] == row['source_sha256'] and source['disk_sha256'] == EXPECTED_SHA
        assert set(row['functions']) <= {f['va'] for f in source['functions']}
    navigation = load(HERE / 'grant_navigation_raw.json')
    assert navigation['disk_sha256'] == EXPECTED_SHA
    for window in navigation['windows']:
        raw = check_range(window['raw_range'])
        instructions = decode(int(window['start_va'], 16), raw)
        assert [r.address for r in instructions] == [int(r['va'], 16) for r in window['items']]
        assert int(window['end_va'], 16) - int(window['start_va'], 16) == len(raw)
        for row in window['items']:
            actual = check_range(row)
            assert row['declared_owner'] == window['expected_owner']
            assert row['is_code'] is True
            assert decoded[int(row['va'], 16)].bytes == actual
        counters['window_items'] += len(window['items'])
        for row in window['calls']:
            check_call(row)
    for row in navigation['bridges']:
        check_range(row)
        check_bridge(int(row['va'], 16), int(row['target'], 16))
    confirmed_strings = []
    for row in navigation['data_refs']:
        raw = row['raw']
        if raw['disk_hex'] is not None:
            actual = check_range(raw)
        else:
            assert disk(int(raw['va'], 16), raw['size']) is None
            assert raw['matching'] is False
            actual = None
        if row['confirmed_c_string']:
            text = bytes.fromhex(row['string_hex'])
            assert row['string_type'] == 0 and b'\0' not in text
            assert actual == text + b'\0'
            confirmed_strings.append((row['site'], row['target'], text.decode('ascii')))
        else:
            assert row['string_hex'] is None and raw['size'] == 16
    for row in navigation['global_slots']:
        assert check_range(row) == b'\0' * 4 and row['va'] == '0xa76720'
    for row in navigation['reused_sources']:
        original_path = ROOT / row['path']
        load(original_path)
        assert hashes[row['path']] == row['sha256']
    declarations = load(HERE / 'grant_reuse_declarations_raw.json')
    literal = declarations['key_literal']
    assert literal['va'] == '0xa2d500' and literal['requested_size'] == 4
    assert disk(0xA2D500, 4) == bytes.fromhex(literal['idb_hex']) == b'num\0'
    for row in declarations['reused_sources']:
        load(ROOT / row['path'])
        assert hashes[row['path']] == row['sha256']
    for row in declarations['reused_declarations']:
        assert row['va'] == row['declared_start']
        assert row['declared_chunks'][-1]['end_va'] == row['declared_end']
        if row['va'] in functions:
            function = functions[row['va']]
            chunks = function.get('chunk_byte_ranges', function.get('chunks', function.get('byte_ranges')))
            assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in row['declared_chunks']] == [
                (int(c.get('va', c.get('start')), 16),
                 int(c['va'], 16) + c['size'] if 'va' in c else int(c['end'], 16)) for c in chunks]
    resource = load(HERE / 'grant_resource_raw.json')
    assert resource['source'] == 'Data/Grant.kpd' and resource['exists'] is False
    assert not (ROOT / resource['source']).exists()
    assert sorted(resource['data_filenames']) == sorted(path.name for path in (ROOT / 'Data').iterdir()
                                                        if path.is_file())
    anchors = {
        0x628119: ('push', '0x1871c'),
        0x62815A: ('mov', 'dword ptr [0xa76720], ecx'),
        0x7D9138: ('cmp', 'dword ptr [ebp - 8], 5'),
        0x7D9150: ('cmp', 'dword ptr [ebp - 0xc], 0x1388'),
        0x7D915C: ('imul', 'edx, edx, 0x4e20'),
        0x7D916C: ('mov', 'dword ptr [ecx + edx*4], 0xffffffff'),
        0x7D917A: ('mov', 'dword ptr [eax + 0x186a8], 0'),
        0x7D9184: ('push', '0x64'),
        0x7D919D: ('mov', 'byte ptr [edx + 0x18710], 0'),
        0x7D91A7: ('mov', 'dword ptr [eax + 0x18714], 0x3f800000'),
        0x7D91B4: ('mov', 'dword ptr [ecx + 0x18718], 0x3f800000'),
        0x7D922B: ('jne', '0x7d924e'),
        0x7D922D: ('mov', 'byte ptr [ebp - 0x171], 0'),
        0x7D9306: ('mov', 'dword ptr [ecx + 0x186a8], eax'),
        0x7D9376: ('mov', 'byte ptr [ecx + 0x18710], al'),
        0x7D93F6: ('mov', 'dword ptr [edx], eax'),
        0x7D944B: ('mov', 'dword ptr [ecx + 4], eax'),
        0x7D952A: ('add', 'edx, dword ptr [ebp - 0x168]'),
        0x7D9530: ('mov', 'byte ptr [edx + 0x186ac], 1'),
        0x7D96F0: ('push', '0xa2d500'),
        0x7D9742: ('imul', 'edx, edx, 0x4e20'),
        0x7D9755: ('mov', 'dword ptr [edx + ecx*4], eax'),
        0x7D97D7: ('fstp', 'dword ptr [edx + 0x18714]'),
        0x7D9830: ('fstp', 'dword ptr [eax + 0x18718]'),
        0x7D9836: ('mov', 'byte ptr [ebp - 0x172], 1'),
        0x7D98EE: ('cmp', 'dword ptr [ebp + 8], 0'),
        0x7D98F2: ('jl', '0x7d98fa'),
        0x7D98F4: ('cmp', 'dword ptr [ebp + 8], 5'),
        0x7D98F8: ('jl', '0x7d98ff'),
        0x7D9912: ('mov', 'eax, dword ptr [edx + eax*4]'),
        0x7D995E: ('mov', 'al, 1'),
        0x7D996D: ('ret', '8'),
        0x7D99E4: ('mov', 'al, byte ptr [eax + 0x186ac]'),
        0x6B76E1: ('mov', 'eax, dword ptr [eax + 0x186a8]'),
        0x6A35C2: ('jl', '0x6a3614'),
        0x6A3652: ('jl', '0x6a3671'),
        0x6A17CA: ('jge', '0x6a1833'),
        0x6A1808: ('jl', '0x6a1823'),
        0x6A180E: ('jle', '0x6a1827'),
        0x623E52: ('push', '0xa222d0'),
        0x62439A: ('mov', 'dword ptr [0xa76720], 0'),
        0x7D9C41: ('mov', 'dword ptr [eax], 0'),
        0x7D9C4A: ('mov', 'dword ptr [ecx + 4], 0xffffffff'),
        0x819988: ('mov', 'byte ptr [edx], 0'),
        0x8199F4: ('cmp', 'edx, dword ptr [ebp + 0xc]'),
        0x8199F7: ('jle', '0x819a10'),
        0x81A0B0: ('mov', 'dword ptr [edx + 0x94], ecx'),
        0x81A0C2: ('mov', 'dword ptr [eax + 0x90], edx'),
        0x81A0D4: ('mov', 'dword ptr [eax + 0x8c], edx'),
        0x71176C: ('cmp', 'dword ptr [ebp - 0x60], -1'),
        0x71178B: ('add', 'eax, 1'),
        0x711791: ('jle', '0x7117dd'),
        0x7CDB01: ('movzx', 'esi, word ptr [ecx + eax + 0x1708]'),
        0x7CDB09: ('add', 'esi, 1'),
        0x7CDB2E: ('jle', '0x7cdb37'),
    }
    for ea, expected in anchors.items():
        instruction = decoded[ea]
        assert (instruction.mnemonic, instruction.op_str) == expected, (hex(ea), instruction.mnemonic, instruction.op_str)
    semantic_targets = {0x628139: 0x7D9100, 0x7D9224: 0x81B4C0,
                        0x7D9281: 0x819250, 0x7D92AA: 0x819470,
                        0x7D92BE: 0x819660, 0x7D92EF: 0x8198E0,
                        0x7D9316: 0x81A090, 0x6A3661: 0x7D9940,
                        0x6A1791: 0x7D99D0, 0x623E57: 0x6280E0,
                        0x623E5E: 0x7D91D0, 0x7D9121: 0x7D9C30,
                        0x71175B: 0x7D98E0, 0x7CDAEB: 0x7D98E0,
                        0x7CDB27: 0x7D98E0}
    for ea, expected in semantic_targets.items():
        instruction = decoded[ea]
        assert instruction.mnemonic == 'call'
        target = int(instruction.op_str, 16)
        while disk(target, 5)[0] == 0xE9:
            destination = target + 5 + struct.unpack_from('<i', disk(target, 5), 1)[0]
            check_bridge(target, destination)
            target = destination
        assert target == expected, (hex(ea), hex(target))
    if args.show:
        start, end = [int(value, 16) for value in args.show]
        for ea, instruction in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X}  {instruction.mnemonic:8} {instruction.op_str}')
        return
    status_counts = {}
    if not args.evidence_only:
        ledger = load(TOPIC / '函数审阅清单.json')['functions']
        assert {row['va'] for row in ledger} == set(functions) | limited_entries
        assert len(ledger) == len(functions) + len(limited_entries)
        status_counts = dict(Counter(row['status'] for row in ledger))
        assert status_counts == {'完整函数静态审阅': 10, '字段或调用路径局部审阅': 5}
        for row in ledger:
            assert all(row.get(key) for key in ('status', 'conclusion', 'unknown', 'evidence', 'document'))
            assert row['status'] != '待采证'
            document = (TOPIC / row['document']).resolve()
            assert document.is_relative_to(TOPIC) and document.is_file()
            assert isinstance(row['evidence'], str)
            for reference in row['evidence'].split('；'):
                filename, separator, pointer = reference.partition('#')
                path = (TOPIC / filename).resolve()
                assert path.is_relative_to(TOPIC) and path.is_file(), reference
                target = load(path)
                if separator:
                    assert pointer.startswith('/') and not re.search(r'~(?![01])', pointer), reference
                    for component in pointer[1:].split('/'):
                        key = component.replace('~1', '/').replace('~0', '~')
                        if isinstance(target, list):
                            assert re.fullmatch(r'0|[1-9][0-9]*', key), reference
                            target = target[int(key)]
                        else:
                            assert isinstance(target, dict) and key in target, reference
                            target = target[key]
                    assert isinstance(target, dict), reference
                    if 'va' in target:
                        assert target['va'] == row['va'], reference
        documents = sorted(TOPIC.glob('*.txt'))
        assert len(documents) >= 5
        for path in documents:
            hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
            assert all(not line.strip() or line.lstrip().startswith('//')
                       for line in path.read_text('utf-8').splitlines())
    result = dict(status='EVIDENCE_CHECKED' if args.evidence_only else 'PASS',
                  disk_sha256=EXPECTED_SHA, functions=len(functions), **counters,
                  unique_bridges=len(bridges), confirmed_string_references=len(confirmed_strings),
                  navigation_data_references=len(navigation['data_refs']),
                  legacy_functions_rechecked=len(reused['legacy_rechecked_functions']),
                  consumer_windows=len(reused['consumer_windows']),
                  ledger_entries=len(functions) + len(limited_entries),
                  manual_bounded_literals=1, reused_declaration_checks=len(declarations['reused_declarations']),
                  semantic_anchors=len(anchors), semantic_call_targets=len(semantic_targets),
                  resource_exists=False, semantic_status=status_counts, source_sha256=hashes,
                  boundary='当前磁盘字节和有限静态契约；Grant资源缺失，未运行游戏。')
    result['source_sha256'][Path(__file__).relative_to(ROOT).as_posix()] = hashlib.sha256(
        Path(__file__).read_bytes()).hexdigest()
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
