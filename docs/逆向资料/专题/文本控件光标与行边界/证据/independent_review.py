"""文本光标独审：只读当前PE及已落盘证据，不访问IDA。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import capstone

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs/逆向资料'
HERE = Path(__file__).resolve().parent
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
NEW = {0x8FC6A0, 0x8FC830, 0x8FCCD0}
REUSED = {0x90CE80, 0x90D120, 0x90D310, 0x8FAE70}


def audit(final=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
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
        payload = image[off + va - base - rva:off + va - base - rva + size]
        assert len(payload) == size
        return payload

    def resolve(va):
        payload = read(va, 5)
        assert payload[0] == 0xE9
        return va + 5 + struct.unpack_from('<i', payload, 1)[0]

    def cstring(va):
        value = bytearray()
        for offset in range(4096):
            byte = read(va + offset, 1)[0]
            if byte == 0:
                return value.decode('ascii')
            value.append(byte)
        raise AssertionError('导入名称没有有限终止符')

    # 磁盘IAT是静态hint/name RVA；必须解析导入目录，不能当运行时函数地址。
    import_rva, import_size = struct.unpack_from('<II', image, pe + 24 + 104)
    import_symbols = {}
    for offset in range(0, import_size, 20):
        descriptor = struct.unpack('<5I', read(base + import_rva + offset, 20))
        if not any(descriptor):
            break
        original, _, _, name_rva, first = descriptor
        module = cstring(base + name_rva)
        for index in range(16384):
            thunk = struct.unpack('<I', read(base + (original or first) + 4 * index, 4))[0]
            if thunk == 0:
                break
            name = None if thunk & 0x80000000 else cstring(base + thunk + 2)
            import_symbols[base + first + 4 * index] = dict(module=module, name=name,
                                                         lookup_value=hex(thunk))
        else:
            raise AssertionError('导入表没有有限终止符')
    slot_path = HERE / 'import_slot_audit.json'
    slot = json.loads(slot_path.read_text(encoding='utf-8'))
    assert slot['schema'] == 'richonline-distinct-import-slot-1'
    assert slot['disk_sha256'] == EXPECTED
    assert slot['start_va'] == '0xad3cbc' and slot['size'] == 4
    slot_offsets = [off + 0xAD3CBC - base - rva for _, rva, count, off in sections
                    if rva <= 0xAD3CBC - base and 0xAD3CBC - base + 4 <= rva + count]
    assert slot_offsets == [slot['file_offset']] == [4693180]
    assert slot['disk_hex'] == read(0xAD3CBC, 4).hex() == '80436d00'
    assert slot['idb_hex'] == 'ffffffff' and slot['matching'] is False
    symbol = import_symbols[0xAD3CBC]
    assert symbol == dict(module='KERNEL32.dll', name='GetTickCount', lookup_value='0x6d4380')
    assert slot['idb_imports'] == [dict(va='0xad3cbc', name='GetTickCount', ordinal=0, module='KERNEL32')]
    slot_audit = dict(slot_va='0xad3cbc', disk_hex=slot['disk_hex'], idb_hex=slot['idb_hex'],
                      matching=False, pe_import=symbol, runtime_target_verified=False,
                      evidence_sha256=hashlib.sha256(slot_path.read_bytes()).hexdigest())

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    transcript = ['// 当前PE独立重解码；旧范围重核与语义完成分开；调用窗不登记owner完成。']
    checked = 0

    def walk(node):
        nonlocal checked
        if isinstance(node, dict):
            payload_hex = node.get('idb_hex', node.get('ida_hex'))
            if payload_hex is not None and node.get('disk_hex') is not None:
                va = int(node.get('start_va', node.get('va')), 16)
                payload = bytes.fromhex(payload_hex)
                assert len(payload) == node['size']
                assert payload == bytes.fromhex(node['disk_hex']) == read(va, len(payload))
                assert node.get('matching', node.get('equal')) is True
                if node.get('sha256'):
                    assert hashlib.sha256(payload).hexdigest() == node['sha256']
                checked += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    def decode(payload, va, label):
        instructions = list(decoder.disasm(payload, va))
        assert sum(i.size for i in instructions) == len(payload)
        transcript.append('// ' + label)
        transcript.extend('// %08X %s %s %s' % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
                          for i in instructions)
        return instructions

    raw_path = HERE / 'bounded_raw.json'
    raw = json.loads(raw_path.read_text(encoding='utf-8'))
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['disk_sha256'] == EXPECTED
    assert {int(s['seed_va'], 16) for s in raw['seeds']} == NEW | REUSED
    assert {int(f['seed_va'], 16) for f in raw['functions']} == NEW
    walk(raw)
    direct, indirect, slot_calls, subjects, decoded = {}, [], {}, [], {}
    for row in raw['current_chunk_audits']:
        va = int(row['seed_va'], 16)
        instructions = []
        for block in row['chunk_byte_ranges']:
            instructions.extend(decode(bytes.fromhex(block['idb_hex']), int(block['start_va'], 16),
                                       '当前主体 ' + hex(va)))
        addresses = {i.address for i in instructions}
        assert len(addresses) == len(instructions)
        decoded[va] = instructions
        original = next((f for f in raw['functions'] if int(f['seed_va'], 16) == va), None)
        if original:
            assert original['chunk_byte_ranges'] == row['chunk_byte_ranges']
            assert addresses == {int(i['site_va'], 16) for i in original['assembly'] if i['is_code']}
        for instruction in instructions:
            if instruction.mnemonic == 'call':
                if instruction.operands[0].type == capstone.x86.X86_OP_IMM:
                    direct[(va, instruction.address)] = instruction.operands[0].imm
                else:
                    indirect.append(dict(seed_va=hex(va), site_va=hex(instruction.address),
                                         operand=instruction.op_str, bytes=instruction.bytes.hex()))
                    operand = instruction.operands[0]
                    if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == operand.mem.index == 0:
                        slot_calls[(va, instruction.address)] = operand.mem.disp
        subjects.append(dict(va=hex(va), bytes=sum(b['size'] for b in row['chunk_byte_ranges']),
                             instructions=len(instructions), chunks=len(row['chunk_byte_ranges']),
                             origin='新主体' if va in NEW else '旧指定范围重核'))
    assert set(decoded) == NEW | REUSED
    locator = {i.address:i for i in decoded[0x90CE80]}
    esp = 0
    for instruction in decoded[0x90CE80]:
        if instruction.address > 0x90CEC0:
            break
        if instruction.mnemonic == 'push':
            esp -= 4
        elif instruction.mnemonic in ('sub', 'add') and instruction.op_str.startswith('esp,'):
            esp += instruction.operands[1].imm * (1 if instruction.mnemonic == 'add' else -1)
    assert esp == -0x1C
    length_slot = esp + locator[0x90CEC0].operands[0].mem.disp
    origin_slot = esp + locator[0x90CF52].operands[0].mem.disp
    assert length_slot == -4 and origin_slot == 8
    for va in (0x90D00A, 0x90D00B, 0x90D00C):
        assert locator[va].mnemonic == 'pop'
        esp += 4
    returned_slot = esp + locator[0x90D013].operands[1].mem.disp
    assert esp == -0x10 and returned_slot == origin_slot != length_slot
    equality_stack = dict(entry_esp_symbol='S', length_slot='S-4', node_origin_slot='S+8',
                          esp_at_90d013='S-0x10', returned_slot='S+8',
                          conclusion='原子节点等宽且flag低BYTE为0返回节点起点B；不返回全串长度')
    assert direct | slot_calls == {(int(c['seed_va'], 16), int(c['site_va'], 16)):int(c['target_va'], 16)
                      for c in raw['calls']}
    assert len(direct) + len(slot_calls) == len(raw['calls'])
    for call in raw['calls']:
        target = int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert target == int(bridge, 16)
            target = resolve(target)
        assert target == int(call['implementation_va'], 16)
    for bridge in raw['verified_direct_bridges']:
        assert bridge['size'] == 5
        assert resolve(int(bridge['start_va'], 16)) == int(bridge['target_va'], 16)
    navigation = set()
    windows = {}

    def check_window(window):
        key = (int(window['owner_va'], 16), int(window['site_va'], 16))
        assert '完整' in window['pending_status']
        rows = window['assembly']
        addresses = []
        for row in rows:
            byte = row['bytes']
            va = int(row['site_va'], 16)
            instructions = list(decoder.disasm(read(va, byte['size']), va))
            assert len(instructions) == 1 and instructions[0].size == byte['size']
            addresses.append(va)
        assert key[1] in addresses and len(addresses) == len(set(addresses))
        if key in windows:
            assert windows[key] == rows
        windows[key] = rows

    for seed, entries in raw['incoming'].items():
        assert int(seed, 16) in NEW | REUSED
        for entry in entries:
            assert entry['is_code'] is True
            site, target = int(entry['site_va'], 16), int(entry['target_va'], 16)
            instruction = next(decoder.disasm(read(site, 5), site))
            assert instruction.mnemonic in ('call', 'jmp')
            assert instruction.operands[0].type == capstone.x86.X86_OP_IMM
            assert instruction.operands[0].imm == target
            if entry['verified_bridge']:
                assert resolve(site) == int(entry['final_implementation_va'], 16)
            if entry.get('owner_window'):
                check_window(entry['owner_window'])
            navigation.add((int(seed, 16), site, target))
    for window in raw['explicit_owner_windows']:
        check_window(window)
    assert raw['strings'] == raw['rejected_string_candidates'] == raw['data_windows'] == []
    reused = []
    for relative, vas in (
        ('专题/文本宽度到字符位置/证据/width_position.json', {0x90CE80, 0x90D120, 0x90D310}),
        ('专题/727F控件状态接口/证据/text_dependencies.json', {0x8FAE70}),
    ):
        source_path = DOCS / relative
        data = json.loads(source_path.read_text(encoding='utf-8'))
        for va in sorted(vas):
            index, function = next((i,f) for i,f in enumerate(data['functions']) if int(f['va'],16) == va)
            blocks = function.get('chunk_byte_ranges', function.get('chunks'))
            walk(blocks)
            old_addresses = set()
            for block in blocks:
                payload = bytes.fromhex(block.get('idb_hex', block.get('ida_hex')))
                old_addresses.update(i.address for i in decoder.disasm(payload, int(block['va'],16)))
            assert old_addresses == {i.address for i in decoded[va]}
            assert old_addresses == {int(i['va'],16) for i in function.get('assembly', function.get('instructions'))}
            reused.append(dict(va=hex(va), path=relative, json_pointer='/functions/'+str(index),
                               sha256=hashlib.sha256(source_path.read_bytes()).hexdigest()))
    for source in raw['reuse_sources']:
        path = (DOCS / source['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
    dependencies = []
    for relative, indices in (
        ('专题/列表控件行记录与布局/证据/list_functions.json', {16:0x8F4B10, 18:0x8F4BA0, 19:0x8F4C20}),
        ('专题/列表控件行记录与布局/证据/list_dependencies.json', {5:0x8F39D0}),
        ('专题/控件回调与事件表/证据/注册与生命周期.json', {9:0x8EB410}),
    ):
        source_path = DOCS / relative
        data = json.loads(source_path.read_text(encoding='utf-8'))
        for index, va in indices.items():
            function = data['functions'][index]
            assert int(function['va'], 16) == va
            blocks = function.get('chunk_byte_ranges', function.get('byte_ranges'))
            walk(blocks)
            instructions = []
            for block in blocks:
                instructions.extend(decode(bytes.fromhex(block['idb_hex']), int(block['va'], 16),
                                           '指定依赖旧完整范围重核 ' + hex(va)))
            assert {i.address for i in instructions} == {int(i['va'],16) for i in function['assembly']}
            dependencies.append(dict(va=hex(va), path=relative, json_pointer='/functions/'+str(index),
                                     sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
                                     bytes=sum(i.size for i in instructions), instructions=len(instructions)))
    result = dict(status='字节初核；人工语义及终稿尚未完成', disk_sha256=EXPECTED,
                  raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(), subjects=subjects,
                  static_calls=len(direct), indirect_calls=indirect, reuse=reused,
                  byte_records=checked, bridges=len(raw['verified_direct_bridges']),
                  import_slot_exception=slot_audit, incoming_records=len(navigation),
                  navigation_window_count=len(windows),
                  navigation_owner_count=len({owner for owner, _ in windows}),
                  specified_dependencies=dependencies, atomic_equality_stack=equality_stack)
    if final:
        topic = HERE.parent

        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        def bound(source):
            assert source['base'] in ('topic', 'docs')
            root = topic if source['base'] == 'topic' else DOCS
            path = (root / source['path']).resolve()
            assert path.is_relative_to(root.resolve())
            assert digest(path) == source['sha256']
            node = json.loads(path.read_bytes())
            assert source['json_pointer'].startswith('/')
            for token in source['json_pointer'][1:].split('/'):
                token = token.replace('~1', '/').replace('~0', '~')
                node = node[int(token)] if isinstance(node, list) else node[token]
            return node

        def reference(value):
            path, pointer = value.split('#')
            source = dict(base='topic', path=path, json_pointer=pointer,
                          sha256=digest(topic / path))
            return bound(source)

        def normalize(record, ranges):
            rows = record.get('assembly', record.get('instructions'))
            return dict(va=record.get('va', record.get('seed_va')), name=record['name'],
                        end_va=record.get('end_va', hex(max(
                            int(b.get('start_va', b.get('va')), 16) + b['size'] for b in ranges))),
                        assembly=[dict(va=i.get('va', i.get('site_va')), text=i['text'],
                                       is_code=i.get('is_code', True)) for i in rows],
                        pseudocode=record['pseudocode'],
                        decompile_error=record.get('decompile_error', record.get('pseudocode_error')),
                        error_field_present='decompile_error' in record or 'pseudocode_error' in record,
                        chunk_byte_ranges=[dict(va=b.get('start_va', b.get('va')), size=b['size'],
                            idb_hex=b.get('idb_hex', b.get('ida_hex')), disk_hex=b['disk_hex'],
                            matching=b.get('matching', b.get('equal')),
                            sha256=hashlib.sha256(bytes.fromhex(
                                b.get('idb_hex', b.get('ida_hex')))).hexdigest()) for b in ranges])

        formal_path = HERE / 'formal_functions.json'
        formal = json.loads(formal_path.read_bytes())
        assert formal['schema'] == 'richonline-caret-formal-adaptation-1'
        assert formal['disk_sha256'] == EXPECTED and formal['source_sha256'] == digest(raw_path)
        order = [int(s['seed_va'], 16) for s in raw['seeds']]
        assert [int(f['va'], 16) for f in formal['functions']] == order
        source_by_va = {int(r['va'], 16):r for r in reused}
        for index, f in enumerate(formal['functions']):
            va = int(f['va'], 16)
            original = bound(f['source'])
            assert original == f['source_record']
            if va in NEW:
                assert f['source'] == dict(base='topic', path='证据/bounded_raw.json',
                    sha256=digest(raw_path), json_pointer='/functions/' + str(index))
                assert original == raw['functions'][index]
                assert 'current_audit_source' not in f and 'current_audit_record' not in f
                ranges = original['chunk_byte_ranges']
                origin = '本批新增完整主体'
            else:
                source = source_by_va[va]
                assert f['source'] == dict(base='docs', path=source['path'],
                    sha256=source['sha256'], json_pointer=source['json_pointer'])
                ai, current = next((i, c) for i, c in enumerate(raw['current_chunk_audits'])
                                   if int(c['seed_va'], 16) == va)
                assert f['current_audit_source'] == dict(base='topic', path='证据/bounded_raw.json',
                    sha256=digest(raw_path), json_pointer='/current_chunk_audits/' + str(ai))
                assert bound(f['current_audit_source']) == f['current_audit_record'] == current
                ranges = current['chunk_byte_ranges']
                origin = '指定旧主体完整静态复核；不计新增'
            expected = normalize(original, ranges)
            assert all(f[key] == value for key, value in expected.items())
            assert f['coverage_origin'] == origin and f['bytes_match_disk'] is True
            assert f['status'] == '原证无损适配；语义分级见函数审阅清单.json'
            assert f['declared_chunks'] == [dict(start_va=b['va'],
                end_va=hex(int(b['va'], 16) + b['size']), is_main=b['va'] == f['va'])
                for b in f['chunk_byte_ranges']]
            assert {int(i['va'], 16) for i in f['assembly'] if i['is_code']} == {
                i.address for i in decoded[va]}

        manifest_path = topic / '函数审阅清单.json'
        manifest = json.loads(manifest_path.read_bytes())
        assert manifest['disk_sha256'] == EXPECTED
        rows = manifest['functions']
        assert len(rows) == len({r['va'] for r in rows}) == 26
        assert [int(r['va'], 16) for r in rows[:7]] == order
        for index, row in enumerate(rows[:7]):
            assert row['status'] == '完整函数静态审阅'
            assert row['evidence'] == '证据/formal_functions.json#/functions/' + str(index)
            assert reference(row['evidence']) == formal['functions'][index]
            assert row['coverage_origin'] == formal['functions'][index]['coverage_origin']
            assert row['conclusion'] and row['unknown']
        for index, row in enumerate(rows[7:]):
            bridge = raw['verified_direct_bridges'][index]
            assert row['va'] == bridge['start_va']
            assert row['status'] == '直接桥静态核验'
            assert row['coverage_origin'] == '直接桥；不计业务主体'
            assert row['conclusion'] == 'E9到' + bridge['target_va']
            assert row['evidence'] == '证据/bounded_raw.json#/verified_direct_bridges/' + str(index)
            assert reference(row['evidence']) == bridge
        explicit = raw['explicit_owner_windows']
        assert len(explicit) == 6 and len(manifest['windows']) == 4
        seen_windows = set()
        for window in manifest['windows']:
            assert not {'va', 'status', 'conclusion'} & window.keys()
            assert window['window_status'] == '仅有限窗口导航'
            for ref in window['evidence']:
                value = reference(ref)
                assert value['owner_va'] == window['owner_va']
                index = explicit.index(value)
                assert ref == '证据/bounded_raw.json#/explicit_owner_windows/' + str(index)
                assert index not in seen_windows
                seen_windows.add(index)
        assert seen_windows == set(range(6))
        assert {w['owner_va'] for w in manifest['windows']} == {w['owner_va'] for w in explicit}
        assert len(formal['dependencies']) == len(manifest['dependency_contracts']) == 5
        for index, (dep, contract, source) in enumerate(zip(
                formal['dependencies'], manifest['dependency_contracts'], dependencies)):
            assert dep['va'] == contract['va'] == source['va']
            assert dep['source'] == dict(base='docs', path=source['path'],
                sha256=source['sha256'], json_pointer=source['json_pointer'])
            assert bound(dep['source']) == dep['source_record']
            assert dep['scope'] == contract['scope'] == '仅指定旧依赖调用契约；不计本批完整主体或新增成果'
            assert dep['contract'] == contract['contract']
            assert contract['evidence'] == '证据/formal_functions.json#/dependencies/' + str(index)
            assert reference(contract['evidence']) == dep
        assert sum(s['bytes'] for s in subjects) == 3212
        assert sum(s['instructions'] for s in subjects) == 1049
        assert sum(s['bytes'] for s in subjects if int(s['va'], 16) in NEW) == 1288
        assert sum(s['instructions'] for s in subjects if int(s['va'], 16) in NEW) == 364
        assert sum(s['bytes'] for s in dependencies) == 1721
        assert sum(s['instructions'] for s in dependencies) == 519
        doc_names = ('00_有限采证实施计划.txt', '01_行记录与位置量度.txt',
                     '02_光标更新与递归边界.txt', '03_选区清理与插入续接.txt',
                     '04_证据分层与未决项.txt', '06_独立审阅.txt')
        for name in doc_names:
            lines = (topic / name).read_text(encoding='utf-8-sig').splitlines()
            assert all(not line.strip() or line.startswith('//') for line in lines)
        assert all(row['document'] in doc_names for row in rows + manifest['windows'])
        author = json.loads((HERE / 'author_validation.json').read_bytes())
        assert author['status'] == 'PASS' and author['disk_sha256'] == EXPECTED
        for relative, expected_sha in author['final_binding_sha256'].items():
            assert digest(topic / relative) == expected_sha
        locked = [topic / n for n in doc_names] + [manifest_path, formal_path,
            raw_path, slot_path, HERE / 'independent_review.py', HERE / 'author_validation.json']
        result.update(status='PASS', scope='独立静态终审；不证明运行时行为、导入目标或容量安全',
            formal_functions=7, new_functions=3, reused_functions=4,
            manifest_functions=26, explicit_navigation_windows=6,
            explicit_navigation_owners=4, specified_dependency_count=5,
            final_binding_sha256={str(p.relative_to(topic)).replace('\\', '/'):digest(p) for p in locked})
    (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--final', action='store_true')
    args = parser.parse_args()
    result = audit(args.final)
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True, indent=2))
