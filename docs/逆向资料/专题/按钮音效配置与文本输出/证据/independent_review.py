"""按钮配置独审：当前PE映射、完整解码与原证绑定；不访问IDA。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import capstone

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs/逆向资料'
HERE = Path(__file__).resolve().parent
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = {0x90B6E0, 0x90D890, 0x90B9C0, 0x90BA00, 0x90BAD0, 0x90BF60, 0x90B500}


def audit(final=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(va, size):
        matches = [(rva, off) for _, rva, count, off in sections
                   if rva <= va - base and va - base + size <= rva + count]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        result = image[off + va - base - rva:off + va - base - rva + size]
        assert len(result) == size
        return result

    def resolve(va):
        payload = read(va, 5)
        return va + 5 + struct.unpack_from('<i', payload, 1)[0] if payload[0] == 0xE9 else va

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    transcript = ['// 当前PE独立重解码；局部窗不登记owner完成，虚槽不默认为运行时实现。']

    def decode(payload, start, label):
        instructions = list(decoder.disasm(payload, start))
        assert sum(i.size for i in instructions) == len(payload)
        transcript.append('// ' + label)
        for i in instructions:
            transcript.append('// %08X %s %s %s' % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
        return instructions

    checked = 0

    def walk(node):
        nonlocal checked
        if isinstance(node, dict):
            if ('start_va' in node or 'va' in node) and 'idb_hex' in node and node.get('disk_hex') is not None:
                payload = bytes.fromhex(node['idb_hex'])
                assert payload == bytes.fromhex(node['disk_hex'])
                assert len(payload) == node['size'] and node['matching'] is True
                assert payload == read(int(node.get('start_va', node.get('va')), 16), len(payload))
                if node.get('sha256'):
                    assert hashlib.sha256(payload).hexdigest() == node['sha256']
                checked += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    raw_path = HERE / 'bounded_raw.json'
    raw = json.loads(raw_path.read_text(encoding='utf-8'))
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['disk_sha256'] == EXPECTED_SHA
    assert {int(row['seed_va'], 16) for row in raw['seeds']} == SEEDS
    walk(raw)
    direct = {}
    indirect = []
    subjects = []
    decoded_by_seed = {}
    for audit_row in raw['current_chunk_audits']:
        va = int(audit_row['seed_va'], 16)
        blocks = audit_row['chunk_byte_ranges']
        addresses = set()
        size = count = 0
        all_instructions = []
        for block in blocks:
            payload = bytes.fromhex(block['idb_hex'])
            instructions = decode(payload, int(block['start_va'], 16), '主体 ' + hex(va))
            size += len(payload)
            count += len(instructions)
            all_instructions.extend(instructions)
            for instruction in instructions:
                assert instruction.address not in addresses
                addresses.add(instruction.address)
                if instruction.mnemonic == 'call':
                    operand = instruction.operands[0]
                    if operand.type == capstone.x86.X86_OP_IMM:
                        direct[(va, instruction.address)] = operand.imm
                    else:
                        indirect.append(dict(seed_va=hex(va), site_va=hex(instruction.address),
                                             operand=instruction.op_str, bytes=instruction.bytes.hex()))
        decoded_by_seed[va] = all_instructions
        function = next((f for f in raw['functions'] if int(f['seed_va'], 16) == va), None)
        if function:
            assert function['chunk_byte_ranges'] == blocks
            assert addresses == {int(row['site_va'], 16) for row in function['assembly'] if row['is_code']}
            main = next(row for row in blocks if int(row['start_va'], 16) == va)
            assert va + main['size'] == int(function['end_va'], 16)
        subjects.append(dict(va=hex(va), size=size, instructions=count, chunks=len(blocks),
                             source_kind='新主体' if function else '旧源指定范围重核'))
    declared = {(int(row['seed_va'], 16), int(row['site_va'], 16)):
                int(row['target_va'], 16) for row in raw['calls']}
    assert len(declared) == len(raw['calls']) and direct == declared
    for row in raw['calls']:
        target = int(row['target_va'], 16)
        for bridge in row['bridges']:
            assert target == int(bridge, 16) and read(target, 1) == b'\xe9'
            target = resolve(target)
        assert target == int(row['implementation_va'], 16)
    for row in raw['verified_direct_bridges']:
        va = int(row['start_va'], 16)
        assert row['size'] == 5 and read(va, 1) == b'\xe9'
        assert resolve(va) == int(row['target_va'], 16)
    for row in raw['strings']:
        payload, nul = bytes.fromhex(row['payload_hex']), bytes.fromhex(row['nul_hex'])
        width = row['unit_width']
        assert width in (1, 2) and len(nul) == width and not any(nul)
        assert len(payload) % width == 0
        assert all(any(payload[i:i + width]) for i in range(0, len(payload), width))
        assert read(int(row['target_va'], 16), len(payload) + width) == payload + nul
        assert bytes.fromhex(row['byte_audit']['idb_hex']) == payload + nul
    windows = []

    def check_window(window):
        transcript.append('// 局部窗 owner=%s site=%s' % (window.get('owner_va'), window.get('site_va')))
        count = 0
        for row in window['assembly']:
            if not row['is_code']:
                continue
            payload = bytes.fromhex(row['bytes']['idb_hex'])
            assert payload == bytes.fromhex(row['bytes']['disk_hex']) == read(int(row['site_va'], 16), len(payload))
            assert len(payload) == row['bytes']['size'] and row['bytes']['matching'] is True
            assert hashlib.sha256(payload).hexdigest() == row['bytes']['sha256']
            instructions = decode(payload, int(row['site_va'], 16), '局部指令')
            assert len(instructions) == 1
            count += 1
        windows.append(dict(owner_va=window.get('owner_va'), site_va=window.get('site_va'), instructions=count))

    for window in raw['explicit_owner_windows']:
        check_window(window)
    for incoming in raw['incoming'].values():
        for row in incoming:
            va = int(row['site_va'], 16)
            if row['is_code']:
                instruction = next(decoder.disasm(read(va, 15), va))
                assert instruction.mnemonic in ('call', 'jmp')
                assert instruction.operands[0].type == capstone.x86.X86_OP_IMM
                assert instruction.operands[0].imm == int(row['target_va'], 16)
                if row['verified_bridge']:
                    assert resolve(va) == int(row['final_implementation_va'], 16)
            else:
                assert struct.unpack('<I', read(va, 4))[0] == int(row['target_va'], 16)
            if row.get('owner_window'):
                check_window(row['owner_window'])
    for source in raw['reuse_sources']:
        path = (DOCS / source['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
    old_path = DOCS / '专题/界面系统/第二批/ida_ui_batch2_raw.json'
    old = json.loads(old_path.read_text(encoding='utf-8'))['functions']['0x90b500']
    old_payload = bytes.fromhex(old['idb_bytes_hex'])
    assert old_payload == read(0x90B500, len(old_payload))
    assert len(old_payload) == int(old['end'], 16) - 0x90B500 == 371
    assert {i.address for i in decoded_by_seed[0x90B500]} == {
        int(row['va'], 16) for row in old['instructions']}
    lexical_path = DOCS / '专题/提示文本生命周期/证据/lifecycle.json'
    lexical_source = json.loads(lexical_path.read_text(encoding='utf-8'))
    assert lexical_source['disk_sha256'] == EXPECTED_SHA
    lexical = next(row for row in lexical_source['functions'] if row['va'] == '0x8e06f0')
    walk(lexical['byte_ranges'])
    addresses = set()
    lexical_size = lexical_count = 0
    for block in lexical['byte_ranges']:
        instructions = decode(bytes.fromhex(block['idb_hex']), int(block['va'], 16), '复用词法8E06F0')
        addresses.update(i.address for i in instructions)
        lexical_count += len(instructions)
        lexical_size += block['size']
    assert addresses == {int(row['va'], 16) for row in lexical['assembly']}
    assert lexical_size == 620
    lexical_words = {
        0xA67A9C: b'top', 0xA67A94: b'true', 0xA67A8C: b'false',
        0xA67A84: b'left', 0xA67A80: b'mid', 0xA67A78: b'right',
        0xA67A70: b'rect', 0xA67A68: b'bottom', 0xA67A64: b'pic',
        0xA67A58: b'HScroll', 0xA67A4C: b'VScroll', 0xA67A44: b'null',
    }
    for va, payload in lexical_words.items():
        assert read(va, len(payload) + 1) == payload + b'\0'
    result = dict(status='字节已核，待人工独审与终稿', disk_sha256=EXPECTED_SHA,
                  raw_source_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                  subjects=subjects, byte_ranges_checked=checked, static_calls_checked=len(direct),
                  indirect_calls=indirect, bridges_checked=len(raw['verified_direct_bridges']),
                  strings_checked=len(raw['strings']), windows=windows,
                  incoming_checked=sum(map(len, raw['incoming'].values())))
    result.update(old_90b500_source_sha256=hashlib.sha256(old_path.read_bytes()).hexdigest(),
                  lexical_reuse=dict(va='0x8e06f0', size=lexical_size, instructions=lexical_count,
                                     exact_words_checked=len(lexical_words),
                                     source_sha256=hashlib.sha256(lexical_path.read_bytes()).hexdigest()))
    dependencies = []
    for path, vas in (
        (DOCS / '专题/文本宽度到字符位置/证据/width_position.json', {0x8E1800, 0x924FC0, 0x8E0A00}),
        (HERE / 'dependency_raw.json', {0x90BFB0}),
    ):
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['disk_sha256'] == EXPECTED_SHA
        for va in sorted(vas):
            function = next(row for row in data['functions'] if int(row['va'], 16) == va)
            blocks = function.get('chunk_byte_ranges', function.get('byte_ranges', function.get('chunks')))
            assert blocks
            walk(blocks)
            addresses = set()
            size = count = 0
            for block in blocks:
                payload = bytes.fromhex(block.get('idb_hex', block.get('ida_hex')))
                start = int(block.get('start_va', block.get('va')), 16)
                assert payload == bytes.fromhex(block['disk_hex']) == read(start, len(payload))
                assert len(payload) == block['size']
                assert block.get('matching', block.get('equal')) is True
                if block.get('sha256'):
                    assert hashlib.sha256(payload).hexdigest() == block['sha256']
                instructions = decode(payload, start,
                                      '依赖 ' + hex(va))
                size += block['size']
                count += len(instructions)
                addresses.update(i.address for i in instructions)
            assert addresses == {int(row['va'], 16) for row in function.get('assembly', function.get('instructions'))}
            dependencies.append(dict(va=hex(va), size=size, instructions=count, chunks=len(blocks),
                                     path=path.relative_to(DOCS).as_posix(),
                                     source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    result['dependencies'] = dependencies
    if final:
        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        def pointer(path, address):
            node = json.loads(path.read_text(encoding='utf-8'))
            assert address.startswith('/')
            for part in address[1:].split('/'):
                part = part.replace('~1', '/').replace('~0', '~')
                node = node[int(part)] if isinstance(node, list) else node[part]
            return node

        def source_record(record):
            path = (HERE.parent / record['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            assert digest(path) == record['sha256']
            return pointer(path, record['json_pointer'])

        formal_path = HERE / 'formal_functions.json'
        formal = json.loads(formal_path.read_text(encoding='utf-8'))
        assert formal['disk_sha256'] == EXPECTED_SHA
        assert formal['source_sha256'] == digest(raw_path)
        assert len(formal['functions']) == 7
        for index, row in enumerate(formal['functions']):
            original = source_record(row['source'])
            va = int(row['va'], 16)
            if index < 6:
                assert original == raw['functions'][index]
                assert row['va'] == original['seed_va']
                for key in ('end_va', 'name', 'pseudocode', 'decompile_error'):
                    assert row[key] == original[key]
                assert row['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code'])
                                           for i in original['assembly']]
                blocks = original['chunk_byte_ranges']
            else:
                assert original == old and va == 0x90B500
                assert row['end_va'] == old['end'] and row['name'] == old['name']
                assert row['pseudocode'] == old['pseudocode'] and row['assembly'] == old['instructions']
                assert row['decompile_error'] is None
                audit_source = source_record(row['current_audit_source'])
                assert audit_source['seed_va'] == row['va']
                blocks = audit_source['chunk_byte_ranges']
            expected_blocks = [dict(va=b['start_va'], **{k:v for k,v in b.items() if k != 'start_va'})
                               for b in blocks]
            assert row['chunk_byte_ranges'] == expected_blocks
            assert row['declared_chunks'] == [dict(start_va=b['va'],
                end_va=hex(int(b['va'], 16) + b['size']), is_main=b['va'] == row['va'])
                for b in expected_blocks]
            assert row['bytes_match_disk'] is True
        assert {int(f['va'], 16) for f in formal['functions']} == SEEDS
        dep = json.loads((HERE / 'dependency_raw.json').read_text(encoding='utf-8'))
        walk(dep)
        assert len(dep['functions']) == 1
        dependency = dep['functions'][0]
        assert dependency['va'] == '0x90bfb0' and dependency['end_va'] == '0x90bfdc'
        assert dependency['declared_chunks'] == [dict(start_va='0x90bfb0', end_va='0x90bfdc', is_main=True)]
        dependency_instructions = list(decoder.disasm(read(0x90BFB0, 44), 0x90BFB0))
        dependency_calls = {i.address:i.operands[0].imm for i in dependency_instructions if i.mnemonic == 'call'}
        assert dependency_calls == {int(c['site'], 16):int(c['target'], 16) for c in dependency['calls']}
        for call in dependency['calls']:
            target = int(call['target'], 16)
            for bridge in call['thunks']:
                assert target == int(bridge, 16) and read(target, 1) == b'\xe9'
                target = resolve(target)
            assert target == int(call['implementation'], 16)
        dependency_bridges = set()
        for bridge in dep['thunks']:
            va = int(bridge['va'], 16)
            assert bridge['size'] == 5 and read(va, 1) == b'\xe9'
            assert resolve(va) == int(bridge['target'], 16)
            dependency_bridges.add(va)
        bridge_vas = {int(b['start_va'], 16) for b in raw['verified_direct_bridges']} | dependency_bridges
        assert len(bridge_vas) == 20
        manifest_path = HERE.parent / '函数审阅清单.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        assert manifest['disk_sha256'] == EXPECTED_SHA
        expected_full = SEEDS | {0x90BFB0, 0x8E06F0, 0x8E1800, 0x8E0A00, 0x924FC0}
        assert len(manifest['functions']) == len(expected_full) + len(bridge_vas) == 32
        assert {int(r['va'], 16) for r in manifest['functions']} == expected_full | bridge_vas
        reference_hashes = {}
        for row in manifest['functions']:
            relative, address = row['evidence'].split('#', 1)
            path = (HERE.parent / relative).resolve()
            assert path.is_relative_to(DOCS.resolve())
            node = pointer(path, address)
            va = int(row['va'], 16)
            assert int(node.get('va', node.get('start_va')), 16) == va
            assert row['status'] == ('直接桥静态核验' if va in bridge_vas else '完整函数静态审阅')
            assert row['conclusion'] and row['unknown'] and row['coverage_origin']
            assert (HERE.parent / row['document']).is_file()
            reference_hashes[path.relative_to(DOCS).as_posix()] = digest(path)
        assert sum(r['coverage_origin'] == '本批新增完整主体' for r in manifest['functions']) == 6
        assert sum(r['coverage_origin'] == '本批新增短依赖完整主体' for r in manifest['functions']) == 1
        assert len(manifest['windows']) == 3
        assert {int(w['owner_va'], 16) for w in manifest['windows']} == {0x90B480, 0x8F7A80, 0x90B0A0}
        window_pointers = set()
        for row in manifest['windows']:
            assert not {'va', 'status', 'conclusion'}.intersection(row)
            assert row['window_status'] == '仅有限窗口导航' and row['coverage_origin'] == '不计函数审阅'
            for evidence in row['evidence']:
                relative, address = evidence.split('#', 1)
                path = (HERE.parent / relative).resolve()
                assert path == raw_path.resolve()
                node = pointer(path, address)
                assert node['owner_va'] == row['owner_va']
                assert address not in window_pointers
                window_pointers.add(address)
        assert window_pointers == {'/explicit_owner_windows/' + str(i) for i in range(4)}
        texts = {}
        for path in sorted(HERE.parent.glob('*.txt')):
            assert all(not line.strip() or line.startswith('//')
                       for line in path.read_text(encoding='utf-8-sig').splitlines())
            texts[path.name] = digest(path)
        result.update(status='PASS', scope='本体静态语义人工审阅及机械绑定通过；不证明运行时播放或绘制',
                      manifest_sha256=digest(manifest_path), formal_sha256=digest(formal_path),
                      reference_sha256=reference_hashes, document_sha256=texts,
                      manifest_full_functions=len(expected_full), manifest_bridges=len(bridge_vas),
                      navigation_owners=len(manifest['windows']),
                      formal_sources_checked=8, final_byte_range_records=checked)
    result['transcript_lines'] = len(transcript)
    (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--final', action='store_true')
    arguments = parser.parse_args()
    result = audit(arguments.final)
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
