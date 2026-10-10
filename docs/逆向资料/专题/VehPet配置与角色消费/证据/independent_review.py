"""独立复算当前 PE、完整块、桥、字段锚点和 VehPet 资源，不导入作者验证器。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_PE = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(name):
    return json.loads((HERE / name).read_text(encoding='utf-8'))


def review():
    executable = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(executable) == EXPECTED_PE
    nt = struct.unpack_from('<I', executable, 60)[0]
    assert executable[:2] == b'MZ' and executable[nt:nt + 4] == b'PE\0\0'
    nsections, optsize = struct.unpack_from('<H', executable, nt + 6)[0], struct.unpack_from('<H', executable, nt + 20)[0]
    assert struct.unpack_from('<H', executable, nt + 24)[0] == 0x10b
    image_base = struct.unpack_from('<I', executable, nt + 52)[0]
    sections = [struct.unpack_from('<IIII', executable, nt + 24 + optsize + 40 * n + 8)
                for n in range(nsections)]

    def disk(va, size):
        rva = va - image_base
        offsets = [raw + rva - start for _, start, count, raw in sections
                   if start <= rva and rva + size <= start + count]
        assert len(offsets) == 1, (hex(va), size)
        assert offsets[0] + size <= len(executable)
        return offsets[0], executable[offsets[0]:offsets[0] + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions = {}
    checked_ranges = []
    source_hashes = {}

    def block(va, data):
        offset, actual = disk(va, len(data))
        assert actual == data, hex(va)
        decoded = list(decoder.disasm(actual, va))
        assert sum(ins.size for ins in decoded) == len(actual), hex(va)
        for ins in decoded:
            old = instructions.setdefault(ins.address, ins)
            assert old.bytes == ins.bytes
        checked_ranges.append(dict(va=hex(va), size=len(actual), disk_offset=hex(offset), sha256=digest(actual)))
        return decoded

    raw = load('vehpet_raw.json')
    assert raw['disk_sha256'] == EXPECTED_PE
    supplemental = load('supplement_raw.json')
    assert supplemental['disk_sha256'] == EXPECTED_PE
    raw['functions'].extend(supplemental['functions'])
    raw['thunks'].extend(supplemental['thunks'])
    for filename in ('vehpet_raw.json', 'supplement_raw.json', 'vehpet_context.json', 'resources.json'):
        source_hashes[filename] = digest((HERE / filename).read_bytes())
    body_exports = []
    bridges = {}
    for row in raw['thunks']:
        va = int(row['va'], 16)
        encoded = bytes.fromhex(row['idb_hex'])
        assert encoded == bytes.fromhex(row['disk_hex']) and row['matching'] is True
        bridge = block(va, encoded)
        assert len(bridge) == 1 and encoded[0] == 0xe9 and len(encoded) == 5
        target = va + 5 + struct.unpack_from('<i', encoded, 1)[0]
        assert target == int(row['target'], 16)
        if va in bridges:
            assert bridges[va] == target
        bridges[va] = target
    for function in raw['functions']:
        address_set = set()
        chunks = function['chunk_byte_ranges']
        assert {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']} == {
            (int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks}
        for chunk in chunks:
            encoded = bytes.fromhex(chunk['idb_hex'])
            assert len(encoded) == chunk['size'] and chunk['matching'] is True
            assert encoded == bytes.fromhex(chunk['disk_hex'])
            address_set.update(ins.address for ins in block(int(chunk['va'], 16), encoded))
        assert address_set == {int(row['va'], 16) for row in function['assembly']}
        instr_range_set = set()
        for chunk in function['byte_ranges']:
            encoded = bytes.fromhex(chunk['idb_hex'])
            assert len(encoded) == chunk['size'] and encoded == bytes.fromhex(chunk['disk_hex'])
            instr_range_set.update(ins.address for ins in block(int(chunk['va'], 16), encoded))
        assert instr_range_set == address_set
        calls = {ins.address for va, ins in instructions.items() if va in address_set and ins.mnemonic == 'call'}
        assert calls == {int(row['site'], 16) for row in function['calls']}
        for call in function['calls']:
            site, target = int(call['site'], 16), int(call['target'], 16)
            assert instructions[site].op_str == hex(target)
            for bridge in call['thunks']:
                assert target == int(bridge, 16)
                target = bridges[target]
            assert target == int(call['implementation'], 16)
        body_exports.append(dict(va=function['va'], instructions=len(address_set), chunks=len(chunks)))

    reused = load('reused_verified.json')
    assert reused['disk_sha256'] == EXPECTED_PE
    reused_functions = []
    for item in reused['functions']:
        source_path = ROOT / 'docs/逆向资料/专题' / item['source']
        source_bytes = source_path.read_bytes()
        assert digest(source_bytes) == item['source_sha256']
        source_hashes[item['source']] = digest(source_bytes)
        source = json.loads(source_bytes)
        teachmode = 'teachmode' in source_path.name
        sprite = '角色与精灵动画/' in item['source']
        key = 'address' if sprite else 'va'
        matches = [f for f in source['functions'] if int(f[key], 16) == int(item['va'], 16)]
        assert len(matches) == 1
        function = matches[0]
        expected_chunks, addresses = [], set()
        for chunk in function.get('chunks', function.get('byte_ranges', [])):
            va = int(chunk['start' if sprite else 'va'], 16)
            data = bytes.fromhex(chunk['bytes_hex' if sprite else 'idb_hex'])
            expected_chunks.append((va, data))
            addresses.update(ins.address for ins in block(va, data))
        assert expected_chunks == [(int(c['va'], 16), bytes.fromhex(c['idb_hex'])) for c in item['chunks']]
        rows = function['instructions' if teachmode else 'assembly']
        assert addresses == {int(row['ea' if sprite else 'va'], 16) for row in rows}
        for window in item['windows']:
            assert int(window['site'], 16) in addresses
            for row in window['context']:
                ins = instructions[int(row['va'], 16)]
                assert ins.size == row['size'] and ins.bytes.hex() == row['hex'] == row['disk_hex']
                assert row['capstone'] == ins.mnemonic + ' ' + ins.op_str
        reused_functions.append(dict(va=item['va'], instructions=len(addresses), chunks=len(expected_chunks), scope='完整字节重核；仅字段窗口语义'))

    context = load('vehpet_context.json')
    verified = load('vehpet_context_verified.json')
    assert verified['source_sha256'] == digest((HERE / 'vehpet_context.json').read_bytes())
    assert verified['disk_sha256'] == EXPECTED_PE
    assert len(context['literals']) == len(verified['literals'])
    for original, row in zip(context['literals'], verified['literals']):
        assert all(row[k] == v for k, v in original.items())
        va, content = int(row['target'], 16), bytes.fromhex(row['content_hex'])
        assert content and all(32 <= b <= 126 for b in content) and row['string_type'] == 0
        assert disk(va, row['size'])[1] == content + b'\0' == bytes.fromhex(row['hex']) == bytes.fromhex(row['disk_hex'])
        ins = instructions[int(row['site'], 16)]
        assert ins.mnemonic == 'push' and ins.op_str == hex(va)
    window_counts = {}
    for key in ('windows', 'incoming'):
        assert len(context[key]) == len(verified[key])
        count = 0
        for original, group in zip(context[key], verified[key]):
            assert original['site'] == group['site'] and len(original['context']) == len(group['context'])
            for first, row in zip(original['context'], group['context']):
                assert all(row[k] == v for k, v in first.items())
                va, encoded = int(row['va'], 16), bytes.fromhex(row['hex'])
                assert disk(va, row['size'])[1] == encoded == bytes.fromhex(row['disk_hex']) and row['matching'] is True
                decoded = list(decoder.disasm(encoded, va))
                assert len(decoded) == 1 and decoded[0].size == row['size']
                old = instructions.setdefault(va, decoded[0])
                assert old.bytes == decoded[0].bytes
                count += 1
        window_counts[key] = count

    supplement_context = load('supplement_context.json')
    source_hashes['supplement_context.json'] = digest((HERE / 'supplement_context.json').read_bytes())
    supplement_verified = load('supplement_context_verified.json')
    assert supplement_verified['source_sha256'] == source_hashes['supplement_context.json']
    assert supplement_verified['disk_sha256'] == EXPECTED_PE
    for key in ('data', 'literals', 'incoming'):
        assert len(supplement_context[key]) == len(supplement_verified[key])
        for original, verified_row in zip(supplement_context[key], supplement_verified[key]):
            for field, value in original.items():
                if field != 'context':
                    assert verified_row[field] == value
            if key == 'incoming':
                assert len(original['context']) == len(verified_row['context'])
                pairs = zip(original['context'], verified_row['context'])
            else:
                pairs = [(original, verified_row)]
            for first, row in pairs:
                assert all(row[field] == value for field, value in first.items())
                va = int(row['target' if key == 'literals' else 'va'], 16)
                offset, data = disk(va, row['size'])
                assert int(row['disk_offset'], 16) == offset
                assert data.hex() == row['hex'] == row['disk_hex'] and row['matching'] is True
                if key == 'literals':
                    assert disk(va, 128)[1].hex() == row['bounded_hex'] == row['bounded_disk_hex']
    supplemental_data = {}
    for row in supplement_context['data']:
        va, data = int(row['va'], 16), bytes.fromhex(row['hex'])
        assert len(data) == row['size'] and disk(va, len(data))[1] == data
        supplemental_data[va] = data
    assert supplemental_data[0xa226fc] == b'ALL\0'
    assert supplemental_data[0xa22700] == b'max\0'
    for va, target in {0x612155: 0x63fb20, 0x60cdcc: 0x629570,
                       0x60212e: 0x640020, 0x60a0d6: 0x627cf0}.items():
        data = supplemental_data[va]
        assert data[0] == 0xe9 and len(data) == 5 and va + 5 + struct.unpack_from('<i', data, 1)[0] == target
    type_targets = struct.unpack('<III', supplemental_data[0xa672f8])
    types = []
    for row in supplement_context['literals']:
        target = int(row['target'], 16)
        assert type_targets[row['index']] == target
        bounded = bytes.fromhex(row['bounded_hex'])
        assert len(bounded) == 128 and disk(target, 128)[1] == bounded
        content = bounded.split(b'\0', 1)[0]
        assert content and all(32 <= b <= 126 for b in content)
        assert bytes.fromhex(row['hex']) == content + b'\0' and bytes.fromhex(row['content_hex']) == content
        types.append(content)
    assert types == [b'CAR', b'MOTO', b'PET']
    supplemental_window_rows = 0
    for group in supplement_context['incoming']:
        for row in group['context']:
            va, data = int(row['va'], 16), bytes.fromhex(row['hex'])
            assert disk(va, row['size'])[1] == data
            decoded = list(decoder.disasm(data, va))
            assert len(decoded) == 1 and decoded[0].size == row['size']
            assert instructions.setdefault(va, decoded[0]).bytes == decoded[0].bytes
            supplemental_window_rows += 1

    encoded = (ROOT / 'Data/VehPet.kpd').read_bytes()
    transformed = bytes((byte - encoded[0]) % 256 for byte in encoded[1:])
    plain_size, packed_size = struct.unpack_from('<II', transformed)
    assert packed_size == len(transformed) - 8
    plain = lzokay.decompress(transformed[8:], plain_size)
    resource = load('resources.json')
    assert len(plain) == plain_size == resource['decoded_size']
    for key, data in (('source', encoded), ('packed', transformed), ('compressed', transformed[8:]), ('decoded', plain)):
        assert resource[key + '_sha256'] == digest(data)
        assert resource[key + '_size'] == len(data)
    assert bytes.fromhex(resource['decoded_hex']) == plain
    decoded_lines = plain.splitlines(keepends=True)
    assert len(decoded_lines) == len(resource['lines'])
    cursor = 0
    sections_found, entries_found = [], []
    groups = {}
    section_index, section = -1, None
    for number, row in enumerate(resource['lines'], 1):
        data = bytes.fromhex(row['hex'])
        assert data == decoded_lines[number - 1]
        assert row['number'] == number and row['offset'] == cursor and row['size'] == len(data)
        assert plain[cursor:cursor + len(data)] == data
        text = data.rstrip(b'\r\n')
        clean = text.strip(b' \t')
        if clean.startswith(b'[') and clean.endswith(b']'):
            section_index += 1
            section = clean[1:-1]
            sections_found.append((section_index, number, cursor, section.hex()))
        elif b'=' in text:
            key, value = text.split(b'=', 1)
            entries_found.append((number, cursor, section_index, section.hex() if section else None, key.hex(), cursor + len(key) + 1, value.hex()))
            groups.setdefault((section_index, key.hex()), []).append(number)
        cursor += len(data)
    assert cursor == len(plain)
    assert sections_found == [(x['index'], x['line'], x['offset'], x['hex']) for x in resource['sections']]
    assert entries_found == [(x['line'], x['line_offset'], x['section_index'], x['section_hex'], x['key_hex'], x['value_offset'], x['value_hex']) for x in resource['entries']]
    assert resource['duplicate_keys'] == [dict(section_index=s, key_hex=k, lines=v) for (s, k), v in groups.items() if len(v) > 1]
    for entry in resource['entries']:
        value = bytes.fromhex(entry['value_hex']).strip(b' \t')
        if re.fullmatch(rb'[+-]?[0-9]+', value):
            assert entry['decimal_literal'] == int(value)
        for codec, result in entry['decoding_candidates'].items():
            if result.get('roundtrip'):
                assert result['text'].encode(codec) == bytes.fromhex(entry['value_hex']).lstrip(b' \t')

    items = {}
    for entry in resource['entries']:
        if bytes.fromhex(entry['section_hex']) == b'ITEM':
            items.setdefault(entry['section_index'], {})[bytes.fromhex(entry['key_hex']).strip()] = bytes.fromhex(entry['value_hex']).strip()
    assert len(items) == 49
    assert sorted(int(item[b'indx']) for item in items.values()) == [i for i in range(50) if i != 44]
    assert all(int(item[b'indx']) < 128 for item in items.values())
    type_counts = {value.decode('ascii'): sum(item[b'type'] == value for item in items.values())
                   for value in (b'CAR', b'MOTO', b'PET', b'Car', b'Pet')}
    assert type_counts == dict(CAR=17, MOTO=6, PET=21, Car=2, Pet=3)
    smoke_counts = {value.decode('ascii'): sum(item[b'smoke'] == value for item in items.values())
                    for value in (b'true', b'false')}
    assert smoke_counts == {'true': 17, 'false': 32}
    prop_counts = {str(i): sum(b'prop' + str(i).encode() in item for item in items.values()) for i in range(16)}
    assert list(prop_counts.values()) == [49, 47, 47, 49, 49, 10] + [0] * 10
    assert all(b'desc' in item for item in items.values())
    assert {n: sum(sum(key.startswith(b'prop') for key in item) == n for item in items.values())
            for n in (3, 5, 6)} == {3: 2, 5: 37, 6: 10}
    assert any(bytes.fromhex(entry['section_hex']) == b'ALL' and bytes.fromhex(entry['key_hex']).strip() == b'max'
               and bytes.fromhex(entry['value_hex']).strip() == b'128' for entry in resource['entries'])

    anchors = {
        0x63fb81: ('mov', 'dword ptr [eax + 4], 0'),
        0x63fc39: ('test', 'eax, eax'), 0x63fc3b: ('jne', '0x63fc61'),
        0x63fce2: ('mov', 'dword ptr [ecx], eax'), 0x63fcf5: ('imul', 'ecx, ecx, 0x4c'),
        0x63fd20: ('push', '0x4c'), 0x63fd5f: ('mov', 'dword ptr [eax + 4], ecx'),
        0x63fdc4: ('imul', 'edx, edx, 0x4c'), 0x63fdd0: ('mov', 'dword ptr [edx + ecx], eax'),
        0x63fde5: ('cmp', 'dword ptr [ebp - 0x38], 0x10'),
        0x63fe4e: ('mov', 'dword ptr [ecx + edx*4 + 8], eax'),
        0x63fe96: ('mov', 'dword ptr [ecx + edx + 4], eax'),
        0x63fea6: ('mov', 'byte ptr [ecx + edx + 0x48], 1'),
        0x63feea: ('neg', 'eax'), 0x63feec: ('sbb', 'eax, eax'), 0x63feee: ('inc', 'eax'),
        0x63fefb: ('mov', 'byte ptr [edx + ecx + 0x48], al'),
        0x63ffd9: ('cmp', 'dword ptr [ebp - 8], 3'), 0x63ffdd: ('jae', '0x640001'),
        0x63ffe2: ('mov', 'edx, dword ptr [ecx*4 + 0xa672f8]'),
        0x640001: ('or', 'eax, 0xffffffff'), 0x640011: ('ret', '4'),
        0x6400c7: ('movzx', 'eax, byte ptr [ebp + 0x10]'),
        0x6400cb: ('neg', 'eax'), 0x6400cd: ('sbb', 'eax, eax'), 0x6400cf: ('neg', 'eax'),
        0x6400da: ('push', '4'), 0x6400fb: ('ret', '0xc'),
        0x627d20: ('cmp', 'dword ptr [0xa766ec], 0'), 0x627d29: ('push', '8'),
        0x627d67: ('mov', 'dword ptr [0xa766ec], ecx'), 0x627d6d: ('mov', 'eax, dword ptr [0xa766ec]'),
        0x640075: ('imul', 'ecx, ecx, 0x4c'),
        0x640081: ('mov', 'ecx, dword ptr [ecx + eax*4 + 8]'),
        0x640085: ('cmp', 'ecx, dword ptr [ebp + 8]'),
        0x64009f: ('or', 'eax, 0xffffffff'),
        0x6428dc: ('mov', 'dword ptr [ecx + 0x1e8], eax'),
        0x64291b: ('mov', 'dword ptr [edx + 0x1ec], eax'),
        0x642c14: ('cmp', 'dword ptr [ecx + 8], 9'),
        0x642c26: ('mov', 'eax, dword ptr [edx + 0x1ec]'),
        0x6437dd: ('cmp', 'dword ptr [edx + 0x14], 0'),
        0x6246ae: ('mov', 'dword ptr [0xa766ec], 0'),
        0x63fb3a: ('mov', 'dword ptr [eax], 0xffffffff'),
        0x63fb52: ('cmp', 'dword ptr [ebp - 8], 0x10'),
        0x63fb5e: ('mov', 'dword ptr [eax + edx*4 + 8], 0xffffffff'),
        0x63fbaa: ('cmp', 'dword ptr [eax + 4], 0'),
        0x63fbc8: ('mov', 'dword ptr [ecx + 4], 0'),
        0x629589: ('and', 'eax, 1'), 0x62958c: ('je', '0x62959a'),
        0x7fdb21: ('imul', 'eax, eax, 0x4c'),
        0x7fdb2c: ('cmp', 'dword ptr [edx + eax + 4], 0'),
        0x7fdb31: ('sete', 'cl'),
        0x6466a1: ('imul', 'eax, eax, 0x4c'),
        0x6466aa: ('mov', 'al, byte ptr [edx + eax + 0x48]'),
        0x643a3b: ('mov', 'byte ptr [ebp - 0x63], 0'),
        0x6440e1: ('mov', 'byte ptr [ebp - 0x63], 1'),
        0x64422f: ('jne', '0x64428c'), 0x644242: ('call', '0x6019c7'),
        0x64424c: ('je', '0x64428c'), 0x64426f: ('call', '0x60dd12'),
        0x644be0: ('jne', '0x644c3d'), 0x644bf3: ('call', '0x6019c7'),
        0x644bfd: ('je', '0x644c3d'), 0x644c20: ('call', '0x60dd12'),
        0x64260e: ('push', '0x47'), 0x642610: ('push', '0xf'), 0x642612: ('push', '0xa'),
        0x64266a: ('push', '0x48'), 0x64266c: ('push', '0xf'), 0x64266e: ('push', '0xa'),
        0x6426bf: ('push', '0x49'), 0x6426c1: ('push', '0xf'), 0x6426c3: ('push', '0xa'),
        0x7f7177: ('mov', 'dword ptr [ebp - 8], 0x64'),
        0x7f718b: ('je', '0x7f71ba'),
        0x7f7190: ('mov', 'edx, dword ptr [ecx + 0x238]'),
        0x7f71aa: ('mov', 'dword ptr [ebp - 8], 0x79'),
        0x7f71b3: ('mov', 'dword ptr [ebp - 8], 0x78'),
    }
    for va, expected in anchors.items():
        ins = instructions[va]
        assert (ins.mnemonic, ins.op_str) == expected, (hex(va), ins.mnemonic, ins.op_str, expected)

    auxiliary = []
    for va, size, expected in ((0x642724, 16, bytes.fromhex('fe2564000c26640068266400bd266400')),
                               (0x60fbe9, 5, bytes.fromhex('e9627c1c00'))):
        offset, actual = disk(va, size)
        assert actual == expected
        auxiliary.append(dict(va=hex(va), size=size, disk_offset=hex(offset), hex=actual.hex(), sha256=digest(actual)))
    assert struct.unpack('<IIII', bytes.fromhex(auxiliary[0]['hex'])) == (0x6425fe, 0x64260c, 0x642668, 0x6426bd)
    assert 0x60fbe9 + 5 + struct.unpack_from('<i', bytes.fromhex(auxiliary[1]['hex']), 1)[0] == 0x7d7850
    assert (instructions[0x6425bd].mnemonic, instructions[0x6425bd].op_str) == ('mov', 'dword ptr [ebp - 8], 0x17')
    assert (instructions[0x642686].mnemonic, instructions[0x642686].op_str) == ('sub', 'edx, dword ptr [ebp - 8]')
    assert (instructions[0x642689].mnemonic, instructions[0x642689].op_str) == ('sar', 'edx, 1')
    assert (64 - 23) >> 1 == 20

    topic = HERE.parent
    manifest = json.loads((topic / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert len(manifest['functions']) == 16
    assert len({row['va'] for row in manifest['functions']}) == 16
    for row in manifest['functions']:
        assert row['status'] and row['conclusion'] and row['unknown'] and row['evidence']
        assert all((topic / evidence).is_file() for evidence in row['evidence'])
    document_hashes = {}
    for path in sorted(topic.glob('*.txt')):
        content = path.read_bytes()
        assert all(not line.strip() or line.startswith('//') for line in content.decode('utf-8').splitlines())
        if path.name == '独立审阅.txt':
            continue
        document_hashes[path.name] = digest(content)
    assert len(document_hashes) == 7
    document_hashes['函数审阅清单.json'] = digest((topic / '函数审阅清单.json').read_bytes())
    validation = load('validation.json')
    assert validation['status'] == 'PASS' and validation['disk_sha256'] == EXPECTED_PE
    for row in validation['sources']:
        actual = digest((HERE / row['path']).read_bytes())
        assert actual == row['sha256']
        source_hashes[row['path']] = actual
    result = dict(status='PASS', disk_sha256=EXPECTED_PE,
                  sources=source_hashes, body_exports=body_exports, reused_functions=reused_functions,
                  final_documents=document_hashes, auxiliary_pe_data=auxiliary,
                  resource_statistics=dict(types=type_counts, smoke=smoke_counts, prop_slots=prop_counts),
                  checked_ranges=len(checked_ranges), unique_verified_instructions=len(instructions),
                  new_bridges=len(bridges), context_instruction_rows=window_counts, literals=len(context['literals']),
                  supplemental_data=len(supplement_context['data']), supplemental_literals=len(types),
                  supplemental_window_rows=supplemental_window_rows,
                  rejected_literals=len(context['rejected_literals']), resource_lines=len(resource['lines']),
                  resource_sections=len(sections_found), resource_entries=len(entries_found), semantic_anchors=len(anchors) + 3,
                  scope='独立当前 PE 与资源核验；复用大函数只审有限字段窗口；未运行游戏')
    (HERE / 'independent_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(review(), ensure_ascii=True))
