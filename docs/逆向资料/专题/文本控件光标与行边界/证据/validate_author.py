"""Validate seven bodies, dual bindings, ABI stack evidence and distinct IAT audit."""
import hashlib
import json
from pathlib import Path
import struct

import capstone
from build_formal_functions import binding, normalized

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '6a313dc34df5930635ad34d9b2aa90da72fa170288fcf09ecaacab1ff33b06d2'
SEEDS = ('0x8fc6a0', '0x8fc830', '0x8fccd0', '0x90ce80', '0x90d120', '0x90d310', '0x8fae70')
DOC_NAMES = ('00_有限采证实施计划.txt', '01_行记录与位置量度.txt', '02_光标更新与递归边界.txt',
             '03_选区清理与插入续接.txt', '04_证据分层与未决项.txt')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert sha(image) == EXPECTED
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def offset(va, size):
        matches = [off + va - base - rva for _, rva, count, off in sections
                   if rva <= va - base and va - base + size <= rva + count]
        assert len(matches) == 1, (hex(va), size)
        return matches[0]

    def read(va, size):
        off = offset(va, size)
        payload = image[off:off + size]
        assert len(payload) == size
        return payload

    checked = []

    def walk(node):
        if isinstance(node, dict):
            payload = node.get('idb_hex', node.get('ida_hex'))
            if payload is not None and 'disk_hex' in node:
                va = int(node.get('start_va', node.get('va')), 16)
                blob = bytes.fromhex(payload)
                assert len(blob) == node['size']
                assert blob == bytes.fromhex(node['disk_hex']) == read(va, len(blob))
                assert node.get('matching', node.get('equal')) is True
                if node.get('sha256'):
                    assert sha(blob) == node['sha256']
                checked.append((hex(va), len(blob)))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True

    def decode(ranges):
        instructions = []
        for block in ranges:
            va = int(block.get('start_va', block.get('va')), 16)
            payload = bytes.fromhex(block.get('idb_hex', block.get('ida_hex')))
            result = list(decoder.disasm(payload, va))
            assert sum(i.size for i in result) == len(payload) == block['size']
            instructions.extend(result)
        assert len({i.address for i in instructions}) == len(instructions)
        return instructions

    def bound_record(source):
        actual, node = binding(source['path'], source['json_pointer'], source['base'])
        assert actual == source
        return node

    raw_bytes = (HERE / 'bounded_raw.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == EXPECTED
    assert tuple(s['seed_va'] for s in raw['seeds']) == SEEDS
    assert raw['data_windows'] == []
    walk(raw)
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    assert formal['disk_sha256'] == EXPECTED and formal['source_sha256'] == RAW_SHA
    assert tuple(f['va'] for f in formal['functions']) == SEEDS
    subjects, instructions_by_va, direct, indirect = [], {}, {}, {}
    for index, f in enumerate(formal['functions']):
        original = bound_record(f['source'])
        assert original == f['source_record']
        if index < 3:
            assert original == raw['functions'][index]
            ranges = original['chunk_byte_ranges']
            assert 'current_audit_record' not in f
            assert f['coverage_origin'] == '本批新增完整主体'
        else:
            audit = bound_record(f['current_audit_source'])
            assert audit == f['current_audit_record'] and audit['seed_va'] == f['va']
            ranges = audit['chunk_byte_ranges']
            old_ranges = original.get('chunk_byte_ranges', original.get('chunks'))
            assert [(int(b.get('start_va', b.get('va')), 16), b['size'], b['disk_hex']) for b in old_ranges] == [
                (int(b['start_va'], 16), b['size'], b['disk_hex']) for b in ranges]
            assert f['coverage_origin'] == '指定旧主体完整静态复核；不计新增'
        walk(original)
        expected = normalized(original, ranges)
        assert all(f[k] == v for k, v in expected.items())
        assert f['bytes_match_disk'] is True
        assert f['declared_chunks'] == [dict(start_va=b['va'], end_va=hex(int(b['va'], 16) + b['size']),
                                              is_main=b['va'] == f['va']) for b in f['chunk_byte_ranges']]
        instructions = decode(f['chunk_byte_ranges'])
        assert {i.address for i in instructions} == {int(i['va'], 16) for i in f['assembly'] if i['is_code']}
        assert len(f['chunk_byte_ranges']) == 1
        block = f['chunk_byte_ranges'][0]
        assert int(f['end_va'], 16) == int(block['va'], 16) + block['size']
        instructions_by_va[f['va']] = {i.address: i for i in instructions}
        for i in instructions:
            if i.mnemonic == 'call':
                operand = i.operands[0]
                key = (f['va'], hex(i.address))
                if operand.type == capstone.x86.X86_OP_IMM:
                    direct[key] = hex(operand.imm)
                else:
                    assert operand.type == capstone.x86.X86_OP_MEM
                    assert operand.mem.base == operand.mem.index == 0
                    indirect[key] = hex(operand.mem.disp)
        subjects.append(dict(va=f['va'], bytes=block['size'], instructions=len(instructions),
                             chunks=1, origin=f['coverage_origin']))
    assert [s['bytes'] for s in subjects] == [307, 867, 114, 528, 154, 264, 978]
    assert [s['instructions'] for s in subjects] == [95, 236, 33, 208, 73, 118, 286]
    assert direct | indirect == {(c['seed_va'], c['site_va']): c['target_va'] for c in raw['calls']}
    assert len(direct) == 46 and len(indirect) == 2
    assert indirect == {('0x8fc6a0', '0x8fc7c0'): '0xad3cbc', ('0x8fc830', '0x8fcb70'): '0xad3cbc'}

    def bridge_target(va):
        payload = read(va, 5)
        assert payload[0] == 0xE9
        return va + 5 + struct.unpack_from('<i', payload, 1)[0]

    assert len({b['start_va'] for b in raw['verified_direct_bridges']}) == 19
    for b in raw['verified_direct_bridges']:
        assert b['size'] == 5 and bridge_target(int(b['start_va'], 16)) == int(b['target_va'], 16)
    for c in raw['calls']:
        target = int(c['target_va'], 16)
        for bridge in c['bridges']:
            assert target == int(bridge, 16)
            target = bridge_target(target)
        assert target == int(c['implementation_va'], 16)

    equality = instructions_by_va['0x90ce80']
    assert equality[0x90CEC0].op_str == 'dword ptr [esp + 0x18], eax'
    assert equality[0x90CF52].op_str == 'dword ptr [esp + 0x24], esi'
    assert all(equality[va].mnemonic == 'pop' for va in (0x90D00A, 0x90D00B, 0x90D00C))
    assert equality[0x90D013].op_str == 'eax, dword ptr [esp + 0x18]'
    stack = dict(entry_esp='S', body_esp='S-0x1c', length_slot='S-4', node_start_slot='S+8',
        esp_after_three_pops='S-0x10', return_load_slot='S+8', conclusion='原子等宽flag0返回段起点')
    insert = instructions_by_va['0x8fae70']
    assert insert[0x8FB115].mnemonic == 'push' and insert[0x8FB115].operands[0].imm == 61
    assert insert[0x8FB11F].mnemonic == insert[0x8FB12F].mnemonic == 'call'
    assert instructions_by_va['0x90d120'][0x90D175].op_str == '8'
    assert insert[0x8FB12C].op_str == 'eax, edx' and insert[0x8FB12E].op_str == 'eax'

    windows = {}

    def window(w):
        rows = w['assembly']
        key = (w['owner_va'], w['site_va'])
        if key in windows:
            assert rows == windows[key]
        windows[key] = rows
        assert w['site_va'] in {i['site_va'] for i in rows}
        for row in rows:
            block = row['bytes']
            va = int(row['site_va'], 16)
            decoded = list(decoder.disasm(read(va, block['size']), va))
            assert len(decoded) == 1 and decoded[0].size == block['size']

    incoming_count = 0
    for seed, entries in raw['incoming'].items():
        assert seed in SEEDS
        for entry in entries:
            incoming_count += 1
            assert entry['is_code'] is True
            va = int(entry['site_va'], 16)
            instruction = next(decoder.disasm(read(va, 5), va))
            assert instruction.mnemonic in ('call', 'jmp')
            assert instruction.operands[0].type == capstone.x86.X86_OP_IMM
            assert instruction.operands[0].imm == int(entry['target_va'], 16)
            if entry['verified_bridge']:
                assert bridge_target(va) == int(entry['final_implementation_va'], 16)
            if entry.get('owner_window'):
                window(entry['owner_window'])
    for w in raw['explicit_owner_windows']:
        window(w)
    assert len(raw['explicit_owner_windows']) == 6
    assert len({w['owner_va'] for w in raw['explicit_owner_windows']}) == 4

    dependencies = []
    assert len(formal['dependencies']) == 5
    for dep in formal['dependencies']:
        record = bound_record(dep['source'])
        assert record == dep['source_record'] and record['va'] == dep['va']
        walk(record)
        ranges = record.get('chunk_byte_ranges', record.get('byte_ranges'))
        instructions = decode(ranges)
        assert {i.address for i in instructions} == {int(i['va'], 16) for i in record['assembly']}
        dependencies.append(dict(va=dep['va'], source=dep['source'],
            bytes=sum(b['size'] for b in ranges), instructions=len(instructions), scope=dep['scope']))
    assert sum(d['bytes'] for d in dependencies) == 1721
    assert sum(d['instructions'] for d in dependencies) == 519

    # Unequal IAT evidence is deliberately outside the equal-byte walker.
    slot = json.loads((HERE / 'import_slot_audit.json').read_bytes())
    assert slot['disk_sha256'] == EXPECTED and slot['start_va'] == '0xad3cbc' and slot['size'] == 4
    assert offset(0xAD3CBC, 4) == slot['file_offset'] == 4693180
    assert slot['disk_hex'] == read(0xAD3CBC, 4).hex() == '80436d00'
    assert slot['idb_hex'] == 'ffffffff' and slot['matching'] is False
    assert slot['idb_imports'] == [dict(va='0xad3cbc', name='GetTickCount', ordinal=0, module='KERNEL32')]

    def cstring(va):
        output = bytearray()
        for n in range(4096):
            char = read(va + n, 1)[0]
            if not char:
                return output.decode('ascii')
            output.append(char)
        raise AssertionError('unterminated PE import string')

    import_rva, import_size = struct.unpack_from('<II', image, pe + 24 + 104)
    imports = {}
    for position in range(0, import_size, 20):
        descriptor = struct.unpack('<5I', read(base + import_rva + position, 20))
        if not any(descriptor):
            break
        original, _, _, module, first = descriptor
        for index in range(16384):
            lookup = struct.unpack('<I', read(base + (original or first) + index * 4, 4))[0]
            if not lookup:
                break
            imports[base + first + index * 4] = dict(module=cstring(base + module),
                name=None if lookup & 0x80000000 else cstring(base + lookup + 2), lookup_value=hex(lookup))
        else:
            raise AssertionError('unterminated PE import table')
    assert imports[0xAD3CBC] == dict(module='KERNEL32.dll', name='GetTickCount', lookup_value='0x6d4380')

    manifest = json.loads((HERE.parent / '函数审阅清单.json').read_bytes())
    assert manifest['disk_sha256'] == EXPECTED
    assert len(manifest['functions']) == len({f['va'] for f in manifest['functions']}) == 26
    bodies = [f for f in manifest['functions'] if f['status'] == '完整函数静态审阅']
    assert tuple(f['va'] for f in bodies) == SEEDS
    assert sum(f['coverage_origin'] == '本批新增完整主体' for f in bodies) == 3
    assert len(manifest['windows']) == 4 and len(manifest['dependency_contracts']) == 5
    assert not any({'va', 'status', 'conclusion'}.intersection(w) for w in manifest['windows'])
    for row in manifest['functions'] + manifest['dependency_contracts']:
        path, pointer = row['evidence'].split('#')
        _, evidence = binding(path, pointer, 'topic')
        assert evidence.get('va', evidence.get('start_va')) == row['va']
    for row in manifest['windows']:
        for reference in row['evidence']:
            path, pointer = reference.split('#')
            _, evidence = binding(path, pointer, 'topic')
            assert evidence['owner_va'] == row['owner_va']
    for name in DOC_NAMES:
        lines = (HERE.parent / name).read_text(encoding='utf-8-sig').splitlines()
        assert all(not line.strip() or line.startswith('//') for line in lines)
    author_paths = [HERE.parent / n for n in DOC_NAMES] + [HERE.parent / '函数审阅清单.json'] + [
        HERE / n for n in ('formal_functions.json', 'bounded_raw.json', 'import_slot_audit.json',
                          'export_bounded.py', 'build_formal_functions.py', 'build_review.py', 'validate_author.py')]
    hashes = {str(p.relative_to(HERE.parent)).replace('\\', '/'): sha(p.read_bytes()) for p in author_paths}
    return dict(status='PASS', scope='作者静态验证；不证明运行时编辑/绘制/导入目标或容量安全',
        disk_sha256=EXPECTED, raw_sha256=RAW_SHA, subjects=subjects, dependencies=dependencies,
        equal_byte_records=len(checked), direct_calls=len(direct), indirect_slot_calls=len(indirect),
        bridges=19, incoming_entries=incoming_count, unique_navigation_windows=len(windows),
        explicit_windows=6, explicit_owners=4, equality_stack=stack,
        iat=dict(pe_import=imports[0xAD3CBC], matching=False, runtime_target_verified=False),
        final_binding_sha256=hashes)


if __name__ == '__main__':
    result = validate()
    (HERE / 'author_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=result['status'], subjects=result['subjects'],
        equal_byte_records=result['equal_byte_records'], direct_calls=result['direct_calls'],
        indirect_calls=result['indirect_slot_calls'], bridges=result['bridges']), ensure_ascii=True))
