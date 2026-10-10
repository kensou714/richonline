"""独立读取当前PE核验声明范围，不访问IDA、不写作者或中央资料。"""
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
SEEDS = (0x72E250, 0x72E2D0, 0x72E2F0, 0x7348F0, 0x7349D0, 0x7667A0, 0x766920)


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
        result = image[off + va - base - rva:off + va - base - rva + size]
        assert len(result) == size
        return result

    def resolve(va):
        payload = read(va, 5)
        return va + 5 + struct.unpack_from('<i', payload, 1)[0] if payload[0] == 0xE9 else va

    def c_string(va):
        payload = bytearray()
        while len(payload) <= 4096:
            unit = read(va + len(payload), 1)
            if unit == b'\0':
                return payload.decode('ascii')
            payload.extend(unit)
        raise AssertionError('导入名称超出有限范围')

    descriptor = base + struct.unpack_from('<I', image, pe + 24 + 104)[0]
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

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    transcript = ['// 当前PE独立重解码；各共享槽分别登记，不推定运行时虚表绑定。']

    def decode(payload, start, label):
        instructions = list(decoder.disasm(payload, start))
        assert sum(i.size for i in instructions) == len(payload)
        transcript.append('// ' + label)
        for instruction in instructions:
            transcript.append('// %08X %s %s %s' % (
                instruction.address, instruction.bytes.hex(), instruction.mnemonic,
                instruction.op_str))
        return instructions

    inventory = {int(row['va'], 16): row for row in json.loads(
        (DOCS / '全量分析/functions.json').read_text(encoding='utf-8'))}
    seeds = []
    for va in SEEDS:
        payload = read(va, inventory[va]['span_bytes'])
        instructions = decode(payload, va, '准备入口 ' + hex(va))
        seeds.append(dict(va=hex(va), size=len(payload), instructions=len(instructions),
                          sha256=hashlib.sha256(payload).hexdigest()))

    notify_path = DOCS / '专题/主界面角色通知/证据/notify_contract.json'
    notify = json.loads(notify_path.read_text(encoding='utf-8'))
    assert notify['disk_sha256'] == EXPECTED_SHA
    reused = []
    for va in (0x81BC80, 0x81BCB0):
        function = next(row for row in notify['functions'] if int(row['va'], 16) == va)
        addresses = set()
        size = count = 0
        for block in function['byte_ranges']:
            payload = bytes.fromhex(block['idb_hex'])
            assert payload == bytes.fromhex(block['disk_hex']) == read(int(block['va'], 16), len(payload))
            assert len(payload) == block['size'] and block['matching'] is True
            instructions = decode(payload, int(block['va'], 16), '复用 ' + hex(va))
            addresses.update(i.address for i in instructions)
            size += len(payload)
            count += len(instructions)
        assert addresses == {int(row['va'], 16) for row in function['assembly']}
        reused.append(dict(va=hex(va), size=size, instructions=count))
    startup_path = DOCS / '专题/启动线程与退出/证据/startup_exit_functions.json'
    startup = json.loads(startup_path.read_text(encoding='utf-8'))
    function = next(row for row in startup['functions'] if row['va'] == '0x796be0')
    assert function['end'] == '0x796bec'
    startup_payload = read(0x796BE0, 12)
    assert startup_payload.hex() == '558becc6059166a700015dc3'
    instructions = decode(startup_payload, 0x796BE0, '历史导航独立当前PE补核 796BE0')
    assert {i.address for i in instructions} == {int(row['va'], 16) for row in function['assembly']}

    result = dict(status='准备字节已核，待原证与人工独审', disk_sha256=EXPECTED_SHA,
                  import_identity=tick_name,
                  seed_main_ranges=seeds, current_notify_reuse=reused,
                  notify_source_sha256=hashlib.sha256(notify_path.read_bytes()).hexdigest(),
                  startup_source_sha256=hashlib.sha256(startup_path.read_bytes()).hexdigest(),
                  startup_current_range=dict(va='0x796be0', size=12, instructions=len(instructions),
                                            sha256=hashlib.sha256(startup_payload).hexdigest()))
    raw_path = HERE / 'bounded_raw.json'
    if require_raw:
        assert raw_path.is_file(), '尚未收到主采证'
    if raw_path.is_file():
        raw = json.loads(raw_path.read_text(encoding='utf-8'))
        assert raw['schema'] == 'richonline-bounded-preparation-1'
        assert raw['disk_sha256'] == EXPECTED_SHA
        assert {int(row['seed_va'], 16) for row in raw['seeds']} == set(SEEDS)
        assert {int(row['site_va'], 16) for row in raw['explicit_owner_windows']} == {0x6E8D60}
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
                assert not ('status' in node and 'conclusion' in node)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(raw)
        assert not raw['strings']
        assert {int(row['start_va'], 16) for row in raw['data_windows']} == {
            0xA84FE8, 0xA859C4, 0xA859CC}
        for row in raw['data_windows']:
            va = int(row['start_va'], 16)
            assert row['size'] == 4 and row['disk_hex'] is None and row['matching'] is None
            assert len(bytes.fromhex(row['idb_hex'])) == 4
            assert hashlib.sha256(bytes.fromhex(row['idb_hex'])).hexdigest() == row['sha256']
            assert not any(rva <= va - base and va - base + 4 <= rva + count
                           for _, rva, count, _ in sections)
        subjects = []
        direct = {}
        indirect_absolute = []
        for function in raw['functions']:
            va = int(function['seed_va'], 16)
            assert va in SEEDS
            blocks = function['chunk_byte_ranges']
            assert blocks == next(row['chunk_byte_ranges'] for row in raw['current_chunk_audits']
                                  if int(row['seed_va'], 16) == va)
            addresses = set()
            size = count = 0
            for block in blocks:
                payload = bytes.fromhex(block['idb_hex'])
                instructions = decode(payload, int(block['start_va'], 16), '主体 ' + hex(va))
                size += len(payload)
                count += len(instructions)
                for instruction in instructions:
                    assert instruction.address not in addresses
                    addresses.add(instruction.address)
                    if instruction.mnemonic != 'call':
                        continue
                    operand = instruction.operands[0]
                    if operand.type == capstone.x86.X86_OP_IMM:
                        direct[(va, instruction.address)] = operand.imm
                    elif (operand.type == capstone.x86.X86_OP_MEM
                          and not operand.mem.base and not operand.mem.index):
                        if operand.mem.disp == 0xAD3CBC:
                            direct[(va, instruction.address)] = operand.mem.disp
                        else:
                            indirect_absolute.append(dict(seed_va=hex(va),
                                                          site_va=hex(instruction.address),
                                                          slot_va=hex(operand.mem.disp)))
            assert addresses == {int(row['site_va'], 16) for row in function['assembly'] if row['is_code']}
            main = next(row for row in blocks if int(row['start_va'], 16) == va)
            assert va + main['size'] == int(function['end_va'], 16)
            subjects.append(dict(va=hex(va), bytes=size, instructions=count, chunks=len(blocks)))
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
        windows = []

        def check_window(window):
            count = 0
            for row in window['assembly']:
                if not row['is_code']:
                    continue
                payload = bytes.fromhex(row['bytes']['idb_hex'])
                assert payload == bytes.fromhex(row['bytes']['disk_hex'])
                assert payload == read(int(row['site_va'], 16), len(payload))
                assert len(payload) == row['bytes']['size'] and row['bytes']['matching'] is True
                assert hashlib.sha256(payload).hexdigest() == row['bytes']['sha256']
                instructions = decode(payload, int(row['site_va'], 16), '有限调用窗')
                assert len(instructions) == 1 and instructions[0].size == len(payload)
                count += 1
            windows.append(dict(owner_va=window.get('owner_va'), site_va=window.get('site_va'), instructions=count))

        for window in raw['explicit_owner_windows']:
            check_window(window)
        for incoming in raw['incoming'].values():
            for row in incoming:
                va = int(row['site_va'], 16)
                if not row['is_code']:
                    assert struct.unpack('<I', read(va, 4))[0] == int(row['target_va'], 16)
                    assert row['verified_bridge'] is False
                    continue
                instruction = next(decoder.disasm(read(va, 15), va))
                assert instruction.mnemonic in ('call', 'jmp')
                assert instruction.operands[0].type == capstone.x86.X86_OP_IMM
                assert instruction.operands[0].imm == int(row['target_va'], 16)
                if row['verified_bridge']:
                    assert resolve(va) == int(row['final_implementation_va'], 16)
                if row.get('owner_window'):
                    check_window(row['owner_window'])
        for source in raw['reuse_sources']:
            path = (DOCS / source['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
        result.update(raw_source_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                      current_subjects=subjects, byte_ranges_checked=checked,
                      static_calls_checked=len(direct), bridges_checked=len(raw['verified_direct_bridges']),
                      indirect_absolute_calls=indirect_absolute,
                      incoming_checked=sum(map(len, raw['incoming'].values())), windows=windows)
        result['data_window_boundary'] = '三个DWORD槽均无可映射磁盘初值；IDB显示不当作运行时初值'
        supplemental_reuse = []
        for relative, vas in (
            ('专题/727F控件状态接口/证据/seeds.json', (0x728060, 0x728120)),
            ('专题/40B0系列事件/证据/ui24_control_id.json', (0x7278E0,)),
        ):
            path = DOCS / relative
            data = json.loads(path.read_text(encoding='utf-8'))
            for va in vas:
                function = next(row for row in data['functions'] if int(row['va'], 16) == va)
                blocks = function.get('chunk_byte_ranges', function.get('byte_ranges'))
                assert blocks
                walk(blocks)
                addresses = set()
                for block in blocks:
                    instructions = decode(bytes.fromhex(block['idb_hex']),
                                          int(block.get('start_va', block.get('va')), 16),
                                          '指定复用 ' + hex(va))
                    addresses.update(i.address for i in instructions)
                assert addresses == {int(row['va'], 16) for row in function['assembly']}
                supplemental_reuse.append(dict(path=relative, va=hex(va),
                                               source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        result['supplemental_reuse'] = supplemental_reuse
        dependency_path = HERE / 'dependency_raw.json'
        if dependency_path.is_file():
            dependency = json.loads(dependency_path.read_text(encoding='utf-8'))
            assert dependency['disk_sha256'] == EXPECTED_SHA
            assert len(dependency['functions']) == 1
            function = dependency['functions'][0]
            assert function['va'] == '0x796be0' and function['end_va'] == '0x796bec'
            walk(function)
            assert bytes.fromhex(function['chunk_byte_ranges'][0]['idb_hex']) == startup_payload
            result['dependency_source_sha256'] = hashlib.sha256(dependency_path.read_bytes()).hexdigest()
        context_path = HERE / 'slot_owner_context.json'
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
                check_window(window)
                declarations[start] = window
            for control in context['controls']:
                for block in control['blocks']:
                    declaration = declarations[int(block['block_start_va'], 16)]
                    assert declaration['owner_va'] == control['owner_va']
                    assert 0 <= block['depth'] <= control['predecessor_depth'] <= 1
                site = int(control['site_va'], 16)
                assert any(int(window['start_va'], 16) <= site < int(window['end_va'], 16)
                           for window in context['windows'] if window['owner_va'] == control['owner_va'])
            result['slot_context_source_sha256'] = hashlib.sha256(context_path.read_bytes()).hexdigest()
            result['slot_context_blocks_checked'] = len(context['windows'])
            result['slot_context_controls_checked'] = len(context['controls'])
        xrefs_path = HERE / 'slot_xrefs.json'
        if xrefs_path.is_file():
            xrefs = json.loads(xrefs_path.read_text(encoding='utf-8'))
            reference_count = 0
            for slot in xrefs['slots']:
                va = int(slot['slot_va'], 16)
                for reference in slot['references']:
                    site = int(reference['site_va'], 16)
                    instruction = next(decoder.disasm(read(site, 15), site))
                    assert instruction.mnemonic in ('mov', 'cmp')
                    assert instruction.operands[0].type == capstone.x86.X86_OP_MEM
                    assert instruction.operands[0].mem.disp == va
                    assert instruction.operands[0].size == 4
                    assert instruction.operands[1].type == capstone.x86.X86_OP_IMM
                    assert instruction.operands[1].imm in (0, 1)
                    reference_count += 1
            result['slot_xrefs_source_sha256'] = hashlib.sha256(xrefs_path.read_bytes()).hexdigest()
            result['slot_xrefs_checked'] = reference_count
    if final:
        assert require_raw and raw_path.is_file()
        assert dependency_path.is_file() and context_path.is_file() and xrefs_path.is_file()
        formal_path = HERE / 'formal_functions.json'
        formal = json.loads(formal_path.read_text(encoding='utf-8'))
        assert formal['disk_sha256'] == EXPECTED_SHA
        assert formal['source_sha256'] == result['raw_source_sha256']
        assert len(formal['functions']) == len(raw['functions']) == 7
        for index, (adapted, original) in enumerate(zip(formal['functions'], raw['functions'])):
            assert adapted['va'] == original['seed_va'] and adapted['end_va'] == original['end_va']
            assert adapted['name'] == original['name']
            assert adapted['pseudocode'] == original['pseudocode']
            assert adapted['decompile_error'] == original['decompile_error']
            assert adapted['assembly'] == [dict(va=row['site_va'], text=row['text'],
                                               is_code=row['is_code']) for row in original['assembly']]
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
        hashes = {}
        for path in sorted(HERE.parent.glob('*.txt')):
            content = path.read_text(encoding='utf-8')
            assert all(not line.strip() or line.startswith('//') for line in content.splitlines())
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()

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
        full = set(SEEDS) | {0x81BC80, 0x81BCB0, 0x796BE0, 0x7278E0, 0x728060, 0x728120}
        bridges = {int(row['start_va'], 16) for row in raw['verified_direct_bridges']}
        assert len(rows) == 36 and len({row['va'] for row in rows}) == 36
        reference_hashes = {}
        for row in rows:
            va = int(row['va'], 16)
            assert va in full | bridges
            assert row['status'] == ('完整函数静态审阅' if va in full else '直接桥静态核验')
            assert row['conclusion'] and row['unknown'] and row['coverage_origin']
            assert row['document'] in hashes
            references = row['evidence'] if isinstance(row['evidence'], list) else [row['evidence']]
            for reference in references:
                source_path, node = dereference(reference)
                reference_hashes[source_path.relative_to(DOCS).as_posix()] = hashlib.sha256(
                    source_path.read_bytes()).hexdigest()
                assert isinstance(node, dict)
                if va in full:
                    assert int(node['va'], 16) == va
                if va in bridges:
                    assert int(node['start_va'], 16) == va and node['size'] == 5
        navigation = []

        def find_navigation(node):
            if isinstance(node, dict):
                if 'owner_va' in node:
                    assert 'va' not in node and 'status' not in node and 'conclusion' not in node
                    assert node['window_status'] and node['window_conclusion']
                    navigation.append(node)
                for value in node.values():
                    find_navigation(value)
            elif isinstance(node, list):
                for value in node:
                    find_navigation(value)

        find_navigation(manifest)
        assert len(navigation) == 4
        assert {int(row['owner_va'], 16) for row in navigation} == {0x6E8D10, 0x733960, 0x734000, 0x751180}
        for row in navigation:
            assert row['document'] in hashes
            references = row['evidence'] if isinstance(row['evidence'], list) else [row['evidence']]
            for reference in references:
                source_path, node = dereference(reference)
                reference_hashes[source_path.relative_to(DOCS).as_posix()] = hashlib.sha256(
                    source_path.read_bytes()).hexdigest()
                assert node['owner_va'] == row['owner_va']
        result.update(status='PASS', final_text_sha256=hashes,
                      manifest_records_checked=len(rows), manifest_full_functions=len(full),
                      manifest_bridges=len(bridges), navigation_only_owners=len(navigation),
                      manifest_reference_sha256=reference_hashes,
                      manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                      formal_source_sha256=hashlib.sha256(formal_path.read_bytes()).hexdigest(),
                      scope='七主体完整静态独审；四owner仅有限导航，不计函数语义覆盖')
    result['transcript_lines'] = len(transcript)
    (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-raw', action='store_true')
    parser.add_argument('--final', action='store_true')
    arguments = parser.parse_args()
    result = audit(arguments.require_raw, arguments.final)
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
