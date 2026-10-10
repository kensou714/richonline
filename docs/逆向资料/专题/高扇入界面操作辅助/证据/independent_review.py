"""只读独审：当前 PE 指令锚点与有限采证字节，不访问 IDA，不写作者文件。"""
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
SEEDS = (0x6E3A30, 0x71AA20, 0x71AAC0, 0x747C70)
SITES = (0x75E882, 0x75EF1D, 0x748E87, 0x719DC4, 0x719F1C,
         0x71A0B8, 0x71A763, 0x74599F, 0x7461E8, 0x74730A)


def audit(require_raw=False, final=False):
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
        at = off + va - base - rva
        result = image[at:at + size]
        assert len(result) == size
        return result

    def resolve(va):
        raw = read(va, 5)
        return va + 5 + struct.unpack_from('<i', raw, 1)[0] if raw[0] == 0xE9 else va

    inventory = {int(f['va'], 16): f for f in
                 json.loads((DOCS / '全量分析/functions.json').read_text(encoding='utf-8'))}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    transcript = ['// 当前 PE 独立重解码；窗口只证明声明局部，不登记 owner 全函数。']
    decoded = {}
    ranges = []
    for va in SEEDS:
        count = inventory[va]['span_bytes']
        raw = read(va, count)
        instructions = list(decoder.disasm(raw, va))
        assert sum(i.size for i in instructions) == count
        decoded.update({i.address: i for i in instructions})
        ranges.append(dict(seed_va=hex(va), size=count, sha256=hashlib.sha256(raw).hexdigest()))

    # 断言依据本代理逐指令读盘；函数名和作者伪码不参与这些断言。
    anchors = {
        0x6E3A48: '6a4c', 0x6E3A57: '7441', 0x6E3A5F: '8b8234270000',
        0x6E3A75: 'ff504c', 0x6E3A84: '6a17',
        0x71AA3A: '6818010000', 0x71AA5B: 'ff90c8000000',
        0x71AA68: '0fb64d0c', 0x71AA6E: '7432', 0x71AA7E: 'ff9290000000',
        0x71AA8D: 'ff15bc3cad00', 0x71AA9D: '894154',
        0x71AAA5: 'c7425400000000', 0x71AABA: 'c20800',
        0x71AB06: '83784cff', 0x71AB0A: '742c', 0x71AB1E: 'db4050',
        0x71AB27: 'd88d64ffffff', 0x71AB46: '6894a4a200',
        0x71AB5C: '6801010000', 0x71AB89: 'ff9290000000',
        0x747C93: '68d5000000', 0x747CB2: 'ff92c8000000',
        0x747CC1: '68d6000000', 0x747CE0: 'ff92c8000000',
        0x747CEF: '68d2000000', 0x747D11: 'ff9290000000',
        0x747D20: '68d3000000', 0x747D42: 'ff9290000000',
        0x747D51: '68d7000000', 0x747D73: 'ff9290000000',
    }
    for va, expected in anchors.items():
        assert decoded[va].bytes.hex() == expected, hex(va)
    assert resolve(0x60FF7C) == 0x6E4520
    assert resolve(0x610297) == 0x8E2C10
    assert resolve(0x60974E) == 0x8EA570
    assert read(0xA2A494, 9) == b'%d ($%d)\0'
    assert read(0xA2A89C, 3) == b'\0\0\0'
    slots = {}
    for va, implementation in ((0xA314F8, 0x8E3EB0), (0xA3063C, 0x8E3960)):
        target = struct.unpack('<I', read(va, 4))[0]
        assert resolve(target) == implementation
        slots[hex(va)] = dict(target_va=hex(target), implementation_va=hex(implementation))

    def c_string(va):
        payload = bytearray()
        while len(payload) <= 4096:
            unit = read(va + len(payload), 1)
            if unit == b'\0':
                return payload.decode('ascii')
            payload.extend(unit)
        raise AssertionError('超出字符串有限范围')

    imports_rva = struct.unpack_from('<I', image, pe + 24 + 104)[0]
    descriptor = base + imports_rva
    tick_name = None
    while any(read(descriptor, 20)):
        lookup, _, _, dll, iat = struct.unpack('<5I', read(descriptor, 20))
        index = 0
        while True:
            item = struct.unpack('<I', read(base + (lookup or iat) + index * 4, 4))[0]
            if not item:
                break
            if base + iat + index * 4 == 0xAD3CBC:
                assert not item & 0x80000000
                tick_name = (c_string(base + dll), c_string(base + item + 2))
            index += 1
        descriptor += 20
    assert tick_name == ('KERNEL32.dll', 'GetTickCount')

    old_path = DOCS / '专题/输入与快捷键/ida_input_raw.json'
    old = json.loads(old_path.read_text(encoding='utf-8'))
    focus = old['functions']['0x8ea570']
    for block in focus['ranges']:
        payload = bytes.fromhex(block['idb_bytes_hex'])
        assert read(int(block['start'], 16), len(payload)) == payload

    result = dict(scope='只读 PE 锚点独核；不表示四函数完整语义已经审阅',
                  disk_sha256=EXPECTED_SHA, seed_main_ranges=ranges,
                  instruction_anchors=len(anchors), import_identity=tick_name,
                  static_vtable_slots=slots,
                  old_focus_source_sha256=hashlib.sha256(old_path.read_bytes()).hexdigest(),
                  old_focus_current_bytes_equal=True)
    raw_path = HERE / 'bounded_raw.json'
    if require_raw:
        assert raw_path.is_file(), '主采证尚未落盘'
    if raw_path.exists():
        raw = json.loads(raw_path.read_text(encoding='utf-8'))
        assert raw['schema'] == 'richonline-bounded-preparation-1'
        assert raw['disk_sha256'] == EXPECTED_SHA
        assert {int(f['seed_va'], 16) for f in raw['seeds']} == set(SEEDS)
        assert {int(w['site_va'], 16) for w in raw['explicit_owner_windows']} == set(SITES)
        checked = 0

        def walk(node):
            nonlocal checked
            if isinstance(node, dict):
                if ('start_va' in node or 'va' in node) and 'idb_hex' in node and node.get('disk_hex') is not None:
                    payload = bytes.fromhex(node['idb_hex'])
                    assert len(payload) == node['size']
                    assert payload == bytes.fromhex(node['disk_hex'])
                    assert read(int(node.get('start_va', node.get('va')), 16), len(payload)) == payload
                    assert node['matching'] is True
                    if node.get('sha256'):
                        assert hashlib.sha256(payload).hexdigest() == node['sha256']
                    checked += 1
                assert not ('status' in node and 'conclusion' in node), '原证混入完成结论'
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(raw)
        subjects = []
        direct_calls = {}
        for function in raw['functions']:
            seed = int(function['seed_va'], 16)
            assert seed in SEEDS
            declared = function['chunk_byte_ranges']
            matching_audit = next(row for row in raw['current_chunk_audits']
                                  if int(row['seed_va'], 16) == seed)
            assert declared == matching_audit['chunk_byte_ranges']
            addresses = set()
            count = total = 0
            transcript.append('// 主体 %s' % hex(seed))
            for block in declared:
                payload = bytes.fromhex(block['idb_hex'])
                instructions = list(decoder.disasm(payload, int(block['start_va'], 16)))
                assert sum(i.size for i in instructions) == len(payload)
                total += len(payload)
                count += len(instructions)
                for instruction in instructions:
                    assert instruction.address not in addresses
                    addresses.add(instruction.address)
                    transcript.append('// %08X %s %s %s' % (
                        instruction.address, instruction.bytes.hex(),
                        instruction.mnemonic, instruction.op_str))
                    if instruction.mnemonic == 'call' and instruction.bytes[0] == 0xE8:
                        direct_calls[(seed, instruction.address)] = instruction.operands[0].imm
                    elif instruction.mnemonic == 'call':
                        operand = instruction.operands[0]
                        if (operand.type == capstone.x86.X86_OP_MEM
                                and not operand.mem.base and not operand.mem.index):
                            direct_calls[(seed, instruction.address)] = operand.mem.disp
            assert addresses == {int(row['site_va'], 16) for row in function['assembly']
                                 if row['is_code']}
            assert len(declared) == 1 and int(function['end_va'], 16) == seed + total
            subjects.append(dict(seed_va=hex(seed), chunks=len(declared),
                                 declared_bytes=total, instructions=count))
        declared_calls = {(int(row['seed_va'], 16), int(row['site_va'], 16)):
                          int(row['target_va'], 16) for row in raw['calls']}
        assert len(declared_calls) == len(raw['calls'])
        assert declared_calls == direct_calls
        for row in raw['calls']:
            current = int(row['target_va'], 16)
            for bridge in row['bridges']:
                assert current == int(bridge, 16)
                assert read(current, 1) == b'\xe9'
                current = resolve(current)
            assert current == int(row['implementation_va'], 16)
        for row in raw['verified_direct_bridges']:
            start = int(row['start_va'], 16)
            assert row['size'] == 5 and read(start, 1) == b'\xe9'
            assert resolve(start) == int(row['target_va'], 16)
        for row in raw['strings']:
            payload = bytes.fromhex(row['payload_hex'])
            nul = bytes.fromhex(row['nul_hex'])
            width = row['unit_width']
            assert width in (1, 2) and len(nul) == width and not any(nul)
            assert len(payload) % width == 0
            assert all(any(payload[i:i + width]) for i in range(0, len(payload), width))
            assert read(int(row['target_va'], 16), len(payload) + width) == payload + nul
            assert bytes.fromhex(row['byte_audit']['idb_hex']) == payload + nul
        windows = []

        def check_window(window, label):
            transcript.append('// %s owner=%s site=%s' % (
                label, window.get('owner_va'), window.get('site_va')))
            count = 0
            for row in window['assembly']:
                if not row['is_code']:
                    continue
                block = row['bytes']
                start = int(row['site_va'], 16)
                assert start == int(block.get('start_va', hex(start)), 16)
                payload = bytes.fromhex(block['idb_hex'])
                assert payload == bytes.fromhex(block['disk_hex']) == read(start, len(payload))
                assert len(payload) == block['size'] and block['matching'] is True
                assert hashlib.sha256(payload).hexdigest() == block['sha256']
                instructions = list(decoder.disasm(bytes.fromhex(block['idb_hex']), start))
                assert len(instructions) == 1 and instructions[0].size == block['size']
                instruction = instructions[0]
                transcript.append('// %08X %s %s %s' % (
                    start, instruction.bytes.hex(), instruction.mnemonic, instruction.op_str))
                count += 1
            windows.append(dict(owner_va=window.get('owner_va'),
                                site_va=window.get('site_va'), start_va=window.get('start_va'),
                                instructions=count, kind=label))

        for window in raw['explicit_owner_windows']:
            check_window(window, '显式有限窗')
        for seed, rows in raw['incoming'].items():
            for row in rows:
                start = int(row['site_va'], 16)
                instruction = next(decoder.disasm(read(start, 15), start))
                assert instruction.mnemonic in ('call', 'jmp')
                assert instruction.operands[0].type == capstone.x86.X86_OP_IMM
                assert instruction.operands[0].imm == int(row['target_va'], 16)
                if row['verified_bridge']:
                    assert read(start, 1) == b'\xe9'
                    assert resolve(start) == int(row['final_implementation_va'], 16)
                if row.get('owner_window'):
                    check_window(row['owner_window'], '入边有限窗')
        reuse_checked = []
        for relative, seed in (
            ('专题/控件树与对象生命周期/证据/创建与链表.json', 0x8E2C10),
            ('专题/控件树与对象生命周期/证据/状态与销毁.json', 0x8E3EB0),
            ('专题/股票与交易流程/证据/stock_core.json', 0x692FA0),
        ):
            path = DOCS / relative
            data = json.loads(path.read_text(encoding='utf-8'))
            assert data['disk_sha256'] == EXPECTED_SHA
            function = next(row for row in data['functions'] if int(row['va'], 16) == seed)
            walk(function.get('chunk_byte_ranges', function.get('byte_ranges')))
            reuse_checked.append(dict(path=relative, seed_va=hex(seed),
                                      source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        for source in raw['reuse_sources']:
            path = (DOCS / source['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
        result.update(raw_source_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                      bounded_disk_ranges_checked=checked,
                      complete_subjects=subjects, static_target_calls_checked=len(direct_calls),
                      relative_direct_calls_checked=len(direct_calls) - 1,
                      absolute_import_calls_checked=1,
                      verified_bridge_records=len(raw['verified_direct_bridges']),
                      strict_strings_checked=len(raw['strings']), windows=windows,
                      current_reuse_checked=reuse_checked,
                      pending_status='原证字节已核；作者正文、NULL边界和动态目标仍待人工独审')
        supplements = []
        for path in sorted(HERE.glob('*supplement*.json')):
            if path.name.endswith('validation.json'):
                continue
            data = json.loads(path.read_text(encoding='utf-8'))
            walk(data)
            supplements.append(dict(path=path.name,
                                    source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        result['supplement_sources'] = supplements
        dependency_path = HERE / 'dependency_raw.json'
        dependencies = []
        if dependency_path.is_file():
            dependency = json.loads(dependency_path.read_text(encoding='utf-8'))
            assert dependency['disk_sha256'] == EXPECTED_SHA
            walk(dependency)
            for function in dependency['functions']:
                seed = int(function['va'], 16)
                addresses = set()
                count = total = 0
                transcript.append('// 当前依赖 %s' % hex(seed))
                for block in function['chunk_byte_ranges']:
                    start = int(block.get('start_va', block.get('va')), 16)
                    instructions = list(decoder.disasm(bytes.fromhex(block['idb_hex']), start))
                    assert sum(i.size for i in instructions) == block['size']
                    total += block['size']
                    for instruction in instructions:
                        addresses.add(instruction.address)
                        count += 1
                        transcript.append('// %08X %s %s %s' % (
                            instruction.address, instruction.bytes.hex(),
                            instruction.mnemonic, instruction.op_str))
                assert addresses == {int(row['va'], 16) for row in function['assembly']}
                assert int(function['end_va'], 16) == seed + total
                dependencies.append(dict(seed_va=hex(seed), declared_bytes=total,
                                         instructions=count, chunks=len(function['chunk_byte_ranges'])))
            result['dependency_source_sha256'] = hashlib.sha256(dependency_path.read_bytes()).hexdigest()
        result['current_dependencies'] = dependencies
        context_path = HERE / 'owner_context_raw.json'
        if context_path.is_file():
            context = json.loads(context_path.read_text(encoding='utf-8'))
            assert context['disk_sha256'] == EXPECTED_SHA
            walk(context)
            declarations = {}
            for window in context['windows']:
                start = int(window['start_va'], 16)
                payload = bytes.fromhex(window['idb_hex'])
                instructions = list(decoder.disasm(payload, start))
                assert sum(i.size for i in instructions) == len(payload)
                assert start + len(payload) == int(window['end_va'], 16)
                assert {i.address for i in instructions} == {
                    int(row['site_va'], 16) for row in window['assembly'] if row['is_code']}
                check_window(window, '上游完整局部块')
                declarations[start] = window
            for control in context['controls']:
                for block in control['blocks']:
                    declaration = declarations[int(block['block_start_va'], 16)]
                    assert declaration['owner_va'] == control['owner_va']
                    assert 0 <= block['depth'] <= control['predecessor_depth'] <= 2
                site = int(control['site_va'], 16)
                assert any(int(window['start_va'], 16) <= site < int(window['end_va'], 16)
                           for window in context['windows']
                           if window['owner_va'] == control['owner_va'])
            result['owner_context_source_sha256'] = hashlib.sha256(context_path.read_bytes()).hexdigest()
            result['owner_context_blocks_checked'] = len(context['windows'])
            result['owner_context_controls_checked'] = len(context['controls'])
        result['bounded_disk_ranges_checked'] = checked
    if final:
        assert require_raw and raw_path.is_file()
        author_files = sorted(HERE.parent.glob('*.txt'))
        author_files = [path for path in author_files if path.name != '06_独立审阅.txt']
        assert author_files
        hashes = {}
        for path in author_files:
            content = path.read_text(encoding='utf-8')
            assert all(not line.strip() or line.startswith('//') for line in content.splitlines())
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        formal_path = HERE / 'formal_functions.json'
        formal = json.loads(formal_path.read_text(encoding='utf-8'))
        assert formal['schema'] == 'richonline-formal-bounded-adaptation-1'
        assert formal['disk_sha256'] == EXPECTED_SHA
        assert formal['source_sha256'] == result['raw_source_sha256']
        assert len(formal['functions']) == len(raw['functions']) == 4
        for index, (adapted, original) in enumerate(zip(formal['functions'], raw['functions'])):
            assert adapted['va'] == original['seed_va']
            assert adapted['end_va'] == original['end_va']
            assert adapted['name'] == original['name']
            assert adapted['pseudocode'] == original['pseudocode']
            assert adapted['decompile_error'] == original['decompile_error']
            assert adapted['assembly'] == [dict(va=row['site_va'], text=row['text'],
                                               is_code=row['is_code'])
                                           for row in original['assembly']]
            ranges = [dict(va=row['start_va'], **{key: value for key, value in row.items()
                                                if key != 'start_va'})
                      for row in original['chunk_byte_ranges']]
            assert adapted['chunk_byte_ranges'] == ranges
            assert adapted['declared_chunks'] == [dict(
                start_va=row['va'], end_va=hex(int(row['va'], 16) + row['size']),
                is_main=row['va'] == original['seed_va']) for row in ranges]
            assert adapted['bytes_match_disk'] is True
            assert adapted['source'] == dict(path='证据/bounded_raw.json',
                                             sha256=result['raw_source_sha256'],
                                             json_pointer='/functions/' + str(index))

        def dereference(reference):
            relative, pointer = reference.split('#', 1)
            source_path = (HERE.parent / relative).resolve()
            assert source_path.is_relative_to(DOCS.resolve()) and source_path.is_file()
            node = json.loads(source_path.read_text(encoding='utf-8'))
            assert pointer.startswith('/')
            for token in pointer[1:].split('/'):
                token = token.replace('~1', '/').replace('~0', '~')
                node = node[int(token)] if isinstance(node, list) else node[token]
            return source_path, node

        manifest_path = HERE.parent / '函数审阅清单.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        assert manifest['disk_sha256'] == EXPECTED_SHA
        rows = manifest['functions']
        assert len(rows) == 21 and len({row['va'] for row in rows}) == 21
        full = set(SEEDS) | {0x6E4520, 0x727800, 0x922798, 0x8E2C10, 0x8EA570, 0x692FA0}
        bridges = {0x609BDB, 0x6077F5, 0x602D9A, 0x600423}
        partial = {0x8E3EB0, 0x8E3960, 0x719D80, 0x719E60, 0x744DF0, 0x75E6F0, 0x748CA0}
        reference_hashes = {}
        for row in rows:
            va = int(row['va'], 16)
            expected = ('完整函数静态审阅' if va in full else
                        '直接桥静态核验' if va in bridges else '字段或调用路径局部审阅')
            assert va in full | bridges | partial and row['status'] == expected
            assert row['conclusion'] and row['unknown'] and row['coverage_origin']
            assert row['document'] in hashes
            for reference in row['evidence'].split('；'):
                source_path, node = dereference(reference)
                reference_hashes[source_path.relative_to(DOCS).as_posix()] = hashlib.sha256(
                    source_path.read_bytes()).hexdigest()
                if va in full:
                    assert isinstance(node, dict)
                    if 'va' in node:
                        assert int(node['va'], 16) == va
                if va in bridges:
                    assert int(node['start_va'], 16) == va and node['size'] == 5
        reviewer_path = HERE.parent / '06_独立审阅.txt'
        assert all(not line.strip() or line.startswith('//')
                   for line in reviewer_path.read_text(encoding='utf-8').splitlines())
        result.update(author_text_sha256=hashes,
                      status='PASS', manifest_records_checked=len(rows),
                      manifest_full_functions=len(full), manifest_partial_functions=len(partial),
                      manifest_bridges=len(bridges), manifest_reference_sha256=reference_hashes,
                      manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                      formal_source_sha256=hashlib.sha256(formal_path.read_bytes()).hexdigest(),
                      reviewer_text_sha256=hashlib.sha256(reviewer_path.read_bytes()).hexdigest(),
                      scope='四主体完整声明块及有限调用窗独审；不登记 owner 完整语义',
                      pending_status='独立复核完成；动态类型和未声明消费者保留边界')
    result['transcript_lines'] = len(transcript)
    if require_raw:
        (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-raw', action='store_true')
    parser.add_argument('--final', action='store_true')
    arguments = parser.parse_args()
    result = audit(arguments.require_raw, arguments.final)
    if arguments.require_raw:
        (HERE / 'independent_validation.json').write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
