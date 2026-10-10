"""三类型结果专题独立离线核验；不调用 IDA 或作者校验器。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preparation-only', action='store_true')
    parser.add_argument('--evidence-only', action='store_true')
    parser.add_argument('--show', nargs=2)
    args = parser.parse_args()
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    assert blob[:2] == b'MZ'
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    hashes, decoded = {}, {}
    counts = dict(reused_functions=0, reused_full_entries=0, reused_limited_entries=0,
                  reused_chunks=0, reused_instructions=0)

    def load(path):
        raw = path.read_bytes()
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def disk(ea, size):
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + length]
        assert len(matches) <= 1
        if not matches:
            return None
        rva, offset = matches[0]
        result = blob[offset + ea - base - rva:offset + ea - base - rva + size]
        assert len(result) == size
        return result

    def pointer(data, value):
        assert value.startswith('/')
        for part in value[1:].split('/'):
            assert '~' not in part.replace('~0', '').replace('~1', '')
            key = part.replace('~1', '/').replace('~0', '~')
            if isinstance(data, list):
                assert key.isdecimal() and (key == '0' or not key.startswith('0'))
                data = data[int(key)]
            else:
                data = data[key]
        return data

    reused = load(HERE / 'reused_preparation.json')
    assert reused['disk_sha256'] == SHA
    assert {row['va'] for row in reused['functions']} == {
        '0x8bb2e0', '0x8bb090', '0x755de0', '0x8ba950', '0x8bb700'}
    sources = {}
    for reference in reused['sources']:
        path = (DOCS / reference['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        sources[reference['path']] = load(path)
        assert hashes[path.relative_to(ROOT).as_posix()] == reference['source_sha256']
    for row in reused['functions']:
        original = pointer(sources[row['source']], row['source_pointer'])
        assert original['va'] == row['va']
        chunks = row['chunk_byte_ranges']
        full = row['va'] in {'0x8ba950', '0x8bb700'}
        if full:
            assert len(chunks) == len(original['chunk_byte_ranges']) == len(original['declared_chunks'])
            for chunk, prior, declared in zip(chunks, original['chunk_byte_ranges'], original['declared_chunks']):
                assert chunk['start_va'] == prior['va'] == declared['start_va']
                assert chunk['size'] == prior['size'] == int(declared['end_va'], 16) - int(declared['start_va'], 16)
                assert chunk['disk_hex'] == prior['disk_hex'].lower() == prior['idb_hex'].lower()
                assert prior['matching'] is True
        else:
            assert len(chunks) == 1 and original['matches_disk'] is True
            assert chunks[0]['start_va'] == row['va']
            assert chunks[0]['size'] == original['byte_count']
            assert chunks[0]['sha256'] == original['disk_sha256'] == original['idb_sha256']
            assert chunks[0]['size'] == int(original['end_va'], 16) - int(original['va'], 16)
        actual_assembly = []
        for chunk in chunks:
            start = int(chunk['start_va'], 16)
            raw = disk(start, chunk['size'])
            assert raw is not None and raw.hex() == chunk['disk_hex']
            assert hashlib.sha256(raw).hexdigest() == chunk['sha256']
            instructions = list(decoder.disasm(raw, start))
            assert sum(ins.size for ins in instructions) == len(raw)
            for ins in instructions:
                assert ins.address not in decoded or decoded[ins.address].bytes == ins.bytes
                decoded[ins.address] = ins
                actual_assembly.append(dict(va=hex(ins.address), size=ins.size, bytes_hex=ins.bytes.hex(),
                                            text=ins.mnemonic + ' ' + ins.op_str))
            counts['reused_chunks'] += 1
            counts['reused_instructions'] += len(instructions)
        assert actual_assembly == row['assembly']
        counts['reused_functions'] += 1
        counts['reused_full_entries' if full else 'reused_limited_entries'] += 1
    counts.update(reference_functions=0, reference_chunks=0, reference_instructions=0)
    reference_seeds = {
        'reader_and_cleanup.json': {'0x8ba830', '0x8baf70', '0x8cc740'},
        'tree_helpers.json': {'0x8bc550'},
        'direct_dependencies.json': {'0x8bc4e0', '0x8c0390'},
        'callers_and_node.json': {'0x8c6ad0', '0x8c6dd0'},
    }
    for name, seeds in reference_seeds.items():
        source = load(DOCS / '专题/整数键树容器契约/证据' / name)
        assert source['disk_sha256'] == SHA
        selected = [row for row in source['functions'] if row['va'] in seeds]
        assert {row['va'] for row in selected} == seeds
        for row in selected:
            assert len(row['declared_chunks']) == len(row['chunk_byte_ranges'])
            for declared, chunk in zip(row['declared_chunks'], row['chunk_byte_ranges']):
                ea, size = int(chunk['va'], 16), chunk['size']
                assert ea == int(declared['start_va'], 16)
                assert ea + size == int(declared['end_va'], 16)
                raw = disk(ea, size)
                assert raw is not None and chunk['matching'] is True
                assert raw.hex() == chunk['disk_hex'].lower() == chunk['idb_hex'].lower()
                instructions = list(decoder.disasm(raw, ea))
                assert sum(ins.size for ins in instructions) == size
                for ins in instructions:
                    assert ins.address not in decoded or decoded[ins.address].bytes == ins.bytes
                    decoded[ins.address] = ins
                counts['reference_chunks'] += 1
                counts['reference_instructions'] += len(instructions)
            counts['reference_functions'] += 1
    assert {row['va'] for row in reused['historical_contracts']} == {
        '0x8ba830', '0x8baf70', '0x8cc740', '0x8bc4e0', '0x8c6ad0', '0x8c6dd0'}
    for row in reused['historical_contracts']:
        original = pointer(sources[row['source']], row['source_pointer'])
        assert original['va'] == row['va']
        assert len(row['chunk_byte_ranges']) == len(original['chunk_byte_ranges'])
        transcript = []
        for chunk, prior in zip(row['chunk_byte_ranges'], original['chunk_byte_ranges']):
            assert chunk['start_va'] == prior['va'] and chunk['size'] == prior['size']
            raw = disk(int(chunk['start_va'], 16), chunk['size'])
            assert raw.hex() == chunk['disk_hex'] == prior['disk_hex'].lower() == prior['idb_hex'].lower()
            assert hashlib.sha256(raw).hexdigest() == chunk['sha256']
            transcript.extend(dict(va=hex(ins.address), size=ins.size, bytes_hex=ins.bytes.hex(),
                                   text=ins.mnemonic + ' ' + ins.op_str)
                              for ins in decoder.disasm(raw, int(chunk['start_va'], 16)))
        assert transcript == row['assembly']
    assert len(reused['static_data']) == 2
    for row, ea, expected in zip(reused['static_data'], (0xA3023C, 0xA30248),
                                 ((44, 4, 4), (3644, 4404, 4))):
        assert int(row['start_va'], 16) == ea and row['size'] == 12
        raw = disk(ea, 12)
        assert raw.hex() == row['disk_hex'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        assert struct.unpack('<3I', raw) == expected == tuple(row['dwords'])
    anchors = {
        0x8BAA67: ('cmp', 'dword ptr [ebp - 0x20], 3'),
        0x8BAA6B: ('jae', '0x8baa8b'),
        0x8BAA7A: ('jb', '0x8baa8b'),
        0x8BAA89: ('jbe', '0x8baa92'),
        0x8BAC7B: ('mov', 'dword ptr [eax + 0xe10], esi'),
        0x8BACAA: ('jae', '0x8baceb'),
        0x8BACCC: ('imul', 'edx, edx, 0x24'),
        0x8BACD1: ('mov', 'ecx, 9'),
        0x8BACD8: ('rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
        0x8BAD28: ('mov', 'dword ptr [eax + 0x1130], esi'),
        0x8BAD57: ('jae', '0x8bad98'),
        0x8BAD79: ('imul', 'edx, edx, 0x2c'),
        0x8BAD7E: ('mov', 'ecx, 0xb'),
        0x8BAD85: ('rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
        0x8BADD7: ('mov', 'dword ptr [eax + 0x10], 3'),
        0x8BB778: ('mov', 'dword ptr [ebp - 0x36], eax'),
        0x8BB77B: ('push', '0x20'),
        0x8BB851: ('push', '0x2a'),
        0x8BB892: ('push', '0x2a'),
        0x8BB4D3: ('and', 'eax, 0x20'),
        0x8BB4D8: ('cmp', 'dword ptr [ebp - 0x50], 0'),
        0x8BB537: ('push', '0'),
        0x8BB53E: ('push', 'eax'),
        0x8BB53F: ('call', 'dword ptr [0xacbd60]'),
        0x755E04: ('movzx', 'eax, byte ptr [ebp + 0xc]'),
        0x755E3B: ('push', '0x69'),
        0x755E50: ('push', '0x69'),
        0x755E84: ('cmp', 'dword ptr [ebp - 8], 0'),
        0x755E88: ('jle', '0x755ee4'),
        0x755E8A: ('cmp', 'dword ptr [ebp - 8], 0x2710'),
        0x755E91: ('jg', '0x755ee4'),
        0x755F98: ('ret', '8'),
        0x8BA85F: ('mov', 'dword ptr [edx + 4], ecx'),
        0x8BAF96: ('mov', 'eax, dword ptr [eax + 4]'),
        0x8CC76B: ('mov', 'eax, dword ptr [eax]'),
        0x8CC770: ('push', '4'),
        0x8BC508: ('push', '0x64'),
        0x8BC50A: ('push', '0x24'),
        0x8BC518: ('mov', 'dword ptr [eax + 0xe10], 0'),
        0x8C03C6: ('mov', 'ecx, 0x385'),
        0x8C6B16: ('mov', 'ecx, 0x386'),
        0x8C6B23: ('mov', 'byte ptr [eax + 0xe24], cl'),
        0x8C6B2C: ('mov', 'byte ptr [eax + 0xe25], 0'),
        0x8C6DF1: ('imul', 'eax, eax, 0xe28'),
    }
    for ea, expected in anchors.items():
        assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
    targets = {0x8CC766: 0x8BAF70, 0x8CC775: 0x8BA830,
               0x8BAA4E: 0x8CC740, 0x8BAD13: 0x8CC740,
               0x8BB770: 0x8BB970, 0x8BB7BE: 0x8BB270}
    for ea, target in targets.items():
        ins = decoded[ea]
        assert ins.mnemonic == 'call'
        actual, seen = int(ins.op_str, 16), set()
        while disk(actual, 5)[0] == 0xE9:
            assert actual not in seen and len(seen) < 16
            seen.add(actual)
            raw = disk(actual, 5)
            actual += 5 + struct.unpack_from('<i', raw, 1)[0]
        assert actual == target, hex(ea)
    counts.update(semantic_anchors=len(anchors), semantic_target_chains=len(targets))
    if not args.preparation_only:
        assert (HERE / 'bounded_raw.json').is_file(), '有限IDA原证尚未采集'
        bounded = load(HERE / 'bounded_raw.json')
        assert bounded['disk_sha256'] == SHA
        core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
        assert hashlib.sha256(core.read_bytes()).hexdigest() == bounded['exporter_sha256']
        assert [row['seed_va'] for row in bounded['seeds']] == [
            '0x8ba7b0', '0x8ba8d0', '0x8bba00', '0x8bbcd0', '0x8bc220', '0x8bc2c0']
        counts.update(new_exports=len(bounded['functions']), bounded_reused_seeds=len(bounded['reused_seeds']),
                      new_chunks=0, new_code_items=0, new_data_items=0, direct_calls=0,
                      owner_window_items=0, strict_strings=0)

        def audit(row):
            start, size = int(row['start_va'], 16), row['size']
            actual = disk(start, size)
            if row['disk_hex'] is None:
                assert actual is None and row['matching'] is None
                assert sum(base + rva <= start and start + size <= base + rva + virtual
                           for virtual, rva, _, _ in sections) == 1
                if row['idb_hex'] is not None:
                    raw = bytes.fromhex(row['idb_hex'])
                    assert len(raw) == size and hashlib.sha256(raw).hexdigest() == row['sha256']
                return None
            assert row['matching'] is True and actual is not None
            assert actual.hex() == row['disk_hex'] == row['idb_hex']
            assert hashlib.sha256(actual).hexdigest() == row['sha256']
            return actual

        for row in bounded['current_chunk_audits']:
            assert row['seed_va'] in {seed['seed_va'] for seed in bounded['seeds']}
            for chunk in row['chunk_byte_ranges']:
                assert audit(chunk) is not None
        for row in bounded['functions']:
            matching_audits = [audit_row for audit_row in bounded['current_chunk_audits']
                               if audit_row['seed_va'] == row['seed_va']]
            assert len(matching_audits) == 1
            assert row['chunk_byte_ranges'] == matching_audits[0]['chunk_byte_ranges']
            covered_heads = set()
            for chunk in row['chunk_byte_ranges']:
                raw = audit(chunk)
                assert raw is not None
                start, end = int(chunk['start_va'], 16), int(chunk['start_va'], 16) + len(raw)
                heads = [item for item in row['assembly'] if start <= int(item['site_va'], 16) < end]
                assert heads and int(heads[0]['site_va'], 16) == start
                for index, item in enumerate(heads):
                    ea = int(item['site_va'], 16)
                    item_end = int(heads[index + 1]['site_va'], 16) if index + 1 < len(heads) else end
                    assert ea < item_end and ea not in covered_heads
                    covered_heads.add(ea)
                    if item['is_code']:
                        instructions = list(decoder.disasm(disk(ea, item_end - ea), ea))
                        assert len(instructions) == 1 and instructions[0].size == item_end - ea
                        decoded[ea] = instructions[0]
                        counts['new_code_items'] += 1
                    else:
                        counts['new_data_items'] += 1
                counts['new_chunks'] += 1
            assert len(covered_heads) == len(row['assembly'])
        bridges = {}
        for row in bounded['verified_direct_bridges']:
            raw = audit(row)
            start = int(row['start_va'], 16)
            target = int(row['target_va'], 16)
            assert len(raw) == 5 and raw[0] == 0xE9
            assert start + 5 + struct.unpack_from('<i', raw, 1)[0] == target
            bridges[start] = target
        counts['unique_bounded_bridges'] = len(bridges)
        for row in bounded['calls']:
            ins = decoded[int(row['site_va'], 16)]
            assert ins.mnemonic in ('call', 'jmp') and int(ins.op_str, 16) == int(row['target_va'], 16)
            target = int(row['target_va'], 16)
            for bridge in row['bridges']:
                assert target == int(bridge, 16)
                target = bridges[target]
            assert target == int(row['implementation_va'], 16)
            counts['direct_calls'] += 1
        for row in bounded['strings']:
            raw = audit(row['byte_audit'])
            width = row['unit_width']
            assert width in (1, 2) and row['ida_string_type'] == (0 if width == 1 else 1)
            payload = bytes.fromhex(row['payload_hex'])
            assert bytes.fromhex(row['nul_hex']) == bytes(width)
            assert raw == payload + bytes(width) and len(payload) % width == 0
            assert all(payload[index:index + width] != bytes(width)
                       for index in range(0, len(payload), width))
            counts['strict_strings'] += 1
        for row in bounded['data_windows']:
            audit(row)
        windows = bounded['explicit_owner_windows'] + [edge['owner_window']
                  for edges in bounded['incoming'].values() for edge in edges if 'owner_window' in edge]
        for window in windows:
            if window['owner_va'] is None:
                assert not window['assembly']
                continue
            heads = [item['site_va'] for item in window['assembly']]
            assert window['site_va'] in heads and len(heads) <= 11
            for item in window['assembly']:
                raw = audit(item['bytes'])
                ea = int(item['site_va'], 16)
                assert raw is not None and ea == int(item['bytes']['start_va'], 16)
                assert isinstance(item['is_code'], bool)
                if item['is_code']:
                    instructions = list(decoder.disasm(raw, ea))
                    assert len(instructions) == 1 and instructions[0].size == len(raw)
                    decoded[ea] = instructions[0]
                counts['owner_window_items'] += 1
        for row in bounded['reuse_sources']:
            path = (DOCS / row['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            load(path)
            assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
        dependency = load(HERE / 'dependency_raw.json')
        assert dependency['disk_sha256'] == SHA
        assert {row['va'] for row in dependency['functions']} == {
            '0x8ba510', '0x8ba880', '0x8bb270', '0x8bb970', '0x8bbc60',
            '0x8bbf10', '0x8bcf20', '0x8bd130', '0x8bd240', '0x8bd430',
            '0x8bd480', '0x8cc5d0', '0x8cc820'}
        counts.update(closure_functions=0, closure_chunks=0, closure_instructions=0,
                      closure_bridges=0, closure_direct_calls=0)
        closure_bridges = {}
        for row in dependency['thunks']:
            ea = int(row['va'], 16)
            raw = disk(ea, row['size'])
            assert row['matching'] is True and row['size'] == 5
            assert raw.hex() == row['idb_hex'].lower() == row['disk_hex'].lower()
            assert raw[0] == 0xE9
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            assert target == int(row['target'], 16)
            assert ea not in closure_bridges or closure_bridges[ea] == target
            closure_bridges[ea] = target
        counts['closure_bridges'] = len(closure_bridges)
        for row in dependency['functions']:
            assert row['bytes_match_disk'] is True
            assert len(row['declared_chunks']) == len(row['chunk_byte_ranges'])
            heads = set()
            for chunk, declared in zip(row['chunk_byte_ranges'], row['declared_chunks']):
                ea, size = int(chunk['va'], 16), chunk['size']
                assert ea == int(declared['start_va'], 16)
                assert ea + size == int(declared['end_va'], 16)
                raw = disk(ea, size)
                assert chunk['matching'] is True
                assert raw.hex() == chunk['idb_hex'].lower() == chunk['disk_hex'].lower()
                instructions = list(decoder.disasm(raw, ea))
                assert sum(ins.size for ins in instructions) == size
                for ins in instructions:
                    assert ins.address not in heads
                    heads.add(ins.address)
                    assert ins.address not in decoded or decoded[ins.address].bytes == ins.bytes
                    decoded[ins.address] = ins
                counts['closure_chunks'] += 1
                counts['closure_instructions'] += len(instructions)
            assert heads == {int(item['va'], 16) for item in row['assembly']}
            for call in row['calls']:
                ins = decoded[int(call['site'], 16)]
                assert ins.mnemonic in ('call', 'jmp')
                target = int(ins.op_str, 16)
                assert target == int(call['target'], 16)
                for bridge in call['thunks']:
                    assert target == int(bridge, 16)
                    target = closure_bridges[target]
                assert target == int(call['implementation'], 16)
                counts['closure_direct_calls'] += 1
            counts['closure_functions'] += 1
        closure_anchors = {
            0x8BA536: ('mov', 'byte ptr [eax + 8], 0'),
            0x8BA547: ('mov', 'dword ptr [eax + 0x10], 1'),
            0x8BA551: ('mov', 'dword ptr [eax + 0x14], 0xffffffff'),
            0x8BA558: ('push', '8'),
            0x8BA568: ('mov', 'dword ptr [eax + 0x28], 0'),
            0x8BA8A9: ('mov', 'edx, dword ptr [ecx]'),
            0x8BA8AB: ('mov', 'dword ptr [eax + 4], edx'),
            0x8BB29E: ('and', 'eax, 1'),
            0x8BB2C5: ('ret', '4'),
            0x8BB996: ('mov', 'byte ptr [eax], 0xd'),
            0x8BB99C: ('mov', 'byte ptr [eax + 1], 0xa'),
            0x8BB9A3: ('mov', 'dword ptr [eax + 2], 0'),
            0x8BB9AD: ('mov', 'dword ptr [eax + 6], 0xffffffff'),
            0x8BB9B4: ('push', '0x20'),
            0x8BBC93: ('mov', 'dword ptr [eax + 2], 1'),
            0x8BBC9D: ('mov', 'dword ptr [eax + 6], 0xffffffff'),
            0x8BBF43: ('mov', 'dword ptr [eax + 2], 2'),
            0x8BBF4D: ('mov', 'dword ptr [eax + 6], 0xffffffff'),
            0x8BBF54: ('push', '0x20'),
            0x8BCFD7: ('add', 'eax, 4'),
            0x8BCFFE: ('ret', '4'),
            0x8BD156: ('mov', 'ecx, dword ptr [eax + 4]'),
            0x8BD317: ('ret', '8'),
            0x8BD459: ('mov', 'eax, dword ptr [eax]'),
            0x8BD45B: ('sub', 'eax, dword ptr [ecx]'),
            0x8BD4AF: ('movzx', 'eax, al'),
            0x8BD4B2: ('neg', 'eax'),
            0x8BD4B4: ('sbb', 'eax, eax'),
            0x8BD4B6: ('inc', 'eax'),
            0x8CC5F9: ('mov', 'dword ptr [eax + 0xc], ecx'),
            0x8CC61A: ('mov', 'dword ptr [edx], eax'),
            0x8CC63A: ('ret', '4'),
            0x8CC87B: ('ret', '8'),
        }
        for ea, expected in closure_anchors.items():
            assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
        counts['closure_semantic_anchors'] = len(closure_anchors)
        helpers = load(HERE / 'dependency_helpers_raw.json')
        assert helpers['disk_sha256'] == SHA
        assert {row['va'] for row in helpers['functions']} == {
            '0x8ba5b0', '0x8bafb0', '0x8bb040', '0x8bd060', '0x8bf550',
            '0x8bfd70', '0x8c00c0', '0x8c0120', '0x8c0170', '0x8c04b0', '0x8cc8a0'}
        counts.update(helper_functions=0, helper_chunks=0, helper_instructions=0,
                      helper_bridges=0, helper_direct_calls=0, helper_indirect_iat_calls=0)
        helper_bridges = {}
        for row in helpers['thunks']:
            ea = int(row['va'], 16)
            raw = disk(ea, row['size'])
            assert row['matching'] is True and row['size'] == 5
            assert raw.hex() == row['idb_hex'].lower() == row['disk_hex'].lower()
            assert raw[0] == 0xE9
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            assert target == int(row['target'], 16)
            assert ea not in helper_bridges or helper_bridges[ea] == target
            helper_bridges[ea] = target
        counts['helper_bridges'] = len(helper_bridges)
        for row in helpers['functions']:
            assert row['bytes_match_disk'] is True
            assert len(row['declared_chunks']) == len(row['chunk_byte_ranges'])
            heads = set()
            for chunk, declared in zip(row['chunk_byte_ranges'], row['declared_chunks']):
                ea, size = int(chunk['va'], 16), chunk['size']
                assert ea == int(declared['start_va'], 16)
                assert ea + size == int(declared['end_va'], 16)
                raw = disk(ea, size)
                assert chunk['matching'] is True
                assert raw.hex() == chunk['idb_hex'].lower() == chunk['disk_hex'].lower()
                instructions = list(decoder.disasm(raw, ea))
                assert sum(ins.size for ins in instructions) == size
                for ins in instructions:
                    assert ins.address not in heads
                    heads.add(ins.address)
                    assert ins.address not in decoded or decoded[ins.address].bytes == ins.bytes
                    decoded[ins.address] = ins
                counts['helper_chunks'] += 1
                counts['helper_instructions'] += len(instructions)
            assert heads == {int(item['va'], 16) for item in row['assembly']}
            for call in row['calls']:
                ins = decoded[int(call['site'], 16)]
                assert ins.mnemonic in ('call', 'jmp')
                if ins.bytes[:2] == b'\xff\x15':
                    target = struct.unpack_from('<I', ins.bytes, 2)[0]
                    assert call['thunks'] == []
                    counts['helper_indirect_iat_calls'] += 1
                else:
                    target = int(ins.op_str, 16)
                    counts['helper_direct_calls'] += 1
                assert target == int(call['target'], 16)
                for bridge in call['thunks']:
                    assert target == int(bridge, 16)
                    target = helper_bridges[target]
                assert target == int(call['implementation'], 16)
            counts['helper_functions'] += 1
        formal = load(HERE / 'formal_functions.json')
        assert formal['disk_sha256'] == SHA and formal['source_file'] == 'bounded_raw.json'
        assert formal['source_sha256'] == hashes[(HERE / 'bounded_raw.json').relative_to(ROOT).as_posix()]
        assert len(formal['functions']) == len(bounded['functions'])
        for index, row in enumerate(formal['functions']):
            origin = pointer(bounded, row['source_pointer'])
            assert row['source_pointer'] == f'/functions/{index}'
            assert row['va'] == row['seed_va'] == origin['seed_va']
            assert row['source_file'] == 'bounded_raw.json' and row['status']
            assert row['byte_ranges'] == row['chunk_byte_ranges'] == origin['chunk_byte_ranges']
            assert set(row['source_field_pointers']) == set(origin)
            for field, reference in row['source_field_pointers'].items():
                assert reference == f'/functions/{index}/{field}'
                assert row[field] == pointer(bounded, reference)
            for declared, chunk in zip(row['declared_chunks'], row['chunk_byte_ranges']):
                assert declared['start_va'] == chunk['start_va']
                assert int(declared['end_va'], 16) == int(chunk['start_va'], 16) + chunk['size']
                assert declared['is_main'] == (declared['start_va'] == row['va'])
        owner = load(HERE / 'owner_context_raw.json')
        assert owner['disk_sha256'] == SHA
        counts['extra_owner_items'] = 0
        for window in owner['windows']:
            cursor = int(window['start_va'], 16)
            for item in window['assembly']:
                ea = int(item['site_va'], 16)
                assert ea == cursor and item['is_code'] is True
                saved = item['bytes']
                raw = disk(ea, saved['size'])
                assert saved['matching'] is True
                assert raw.hex() == saved['idb_hex'] == saved['disk_hex']
                assert hashlib.sha256(raw).hexdigest() == saved['sha256']
                instructions = list(decoder.disasm(raw, ea))
                assert len(instructions) == 1 and instructions[0].size == len(raw)
                decoded[ea] = instructions[0]
                cursor += len(raw)
                counts['extra_owner_items'] += 1
            assert cursor == int(window['end_va'], 16)
        imports = {entry.address: entry.name for descriptor in pefile.PE(data=blob).DIRECTORY_ENTRY_IMPORT
                   for entry in descriptor.imports}
        assert imports[0xAD40CC] == b'WSACloseEvent'
        assert imports[0xAD40D0] == b'closesocket'
        counts['verified_cleanup_imports'] = 2
        helper_anchors = {
            0x8BA5F2: ('cmp', 'dword ptr [eax + 0xc], 0'),
            0x8BA619: ('push', '1'),
            0x8BA63B: ('cmp', 'dword ptr [eax + 0x28], 0'),
            0x8BA662: ('push', '1'),
            0x8BA684: ('movzx', 'ecx, byte ptr [eax + 8]'),
            0x8BA68A: ('je', '0x8ba6b7'),
            0x8BA691: ('mov', 'ecx, dword ptr [eax + 4]'),
            0x8BA695: ('call', 'dword ptr [0xad40cc]'),
            0x8BA6A7: ('mov', 'ecx, dword ptr [eax]'),
            0x8BA6AA: ('call', 'dword ptr [0xad40d0]'),
            0x8BA6C1: ('add', 'ecx, 0x18'),
            0xA1B073: ('add', 'ecx, 0x18'),
            0x8BAFD6: ('mov', 'eax, dword ptr [eax + 8]'),
            0x8BB069: ('add', 'ecx, dword ptr [ebp + 8]'),
            0x8BB06F: ('mov', 'dword ptr [edx + 8], ecx'),
            0x8BD088: ('push', '0x64'),
            0x8BD08A: ('push', '0x2c'),
            0x8BD098: ('mov', 'dword ptr [eax + 0x1130], 0'),
            0x8C04DB: ('mov', 'dword ptr [eax], edx'),
            0x8C04E0: ('add', 'edi, 4'),
            0x8C04E6: ('mov', 'ecx, 0x44d'),
            0x8C04EB: ('rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
            0x8CC8C9: ('push', 'ecx'),
            0x8CC8CA: ('push', '0'),
            0x75578F: ('movsx', 'ecx, byte ptr [0xa842d0]'),
            0x755798: ('jne', '0x7557f7'),
            0x75580E: ('push', '0xa842d0'),
            0x755819: ('imul', 'edx, edx, 0x54'),
            0x75581C: ('mov', 'eax, dword ptr [edx + 0xa85a10]'),
        }
        for ea, expected in helper_anchors.items():
            assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
        counts['helper_semantic_anchors'] = len(helper_anchors)
        leaf = load(HERE / 'dependency_leaf_raw.json')
        assert leaf['disk_sha256'] == SHA
        assert {row['va'] for row in leaf['functions']} == {'0x8c3900', '0x8c3950'}
        counts.update(leaf_functions=0, leaf_chunks=0, leaf_instructions=0, leaf_bridges=0)
        leaf_bridges = {}
        for row in leaf['thunks']:
            ea, size = int(row['va'], 16), row['size']
            raw = disk(ea, size)
            assert size == 5 and row['matching'] is True and raw[0] == 0xE9
            assert raw.hex() == row['idb_hex'] == row['disk_hex']
            leaf_bridges[ea] = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            assert leaf_bridges[ea] == int(row['target'], 16)
        counts['leaf_bridges'] = len(leaf_bridges)
        for row in leaf['functions']:
            assert row['bytes_match_disk'] is True
            assert len(row['declared_chunks']) == len(row['chunk_byte_ranges'])
            heads = set()
            for chunk, declared in zip(row['chunk_byte_ranges'], row['declared_chunks']):
                ea, size = int(chunk['va'], 16), chunk['size']
                assert ea == int(declared['start_va'], 16)
                assert ea + size == int(declared['end_va'], 16)
                raw = disk(ea, size)
                assert chunk['matching'] is True
                assert raw.hex() == chunk['idb_hex'] == chunk['disk_hex']
                instructions = list(decoder.disasm(raw, ea))
                assert sum(ins.size for ins in instructions) == size
                for ins in instructions:
                    heads.add(ins.address)
                    decoded[ins.address] = ins
                counts['leaf_chunks'] += 1
                counts['leaf_instructions'] += len(instructions)
            assert heads == {int(item['va'], 16) for item in row['assembly']}
            for call in row['calls']:
                ins = decoded[int(call['site'], 16)]
                assert ins.mnemonic == 'call'
                target = int(ins.op_str, 16)
                assert target == int(call['target'], 16)
                for bridge in call['thunks']:
                    assert target == int(bridge, 16)
                    target = leaf_bridges[target]
                assert target == int(call['implementation'], 16)
            counts['leaf_functions'] += 1
    if args.show:
        start, end = map(lambda value: int(value, 16), args.show)
        for ea, ins in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X}  {ins.mnemonic:8} {ins.op_str}')
        return
    final = not args.preparation_only and not args.evidence_only
    if final:
        ledger = load(TOPIC / '函数审阅清单.json')
        assert ledger['disk_sha256'] == SHA
        final_sources = {name: load(HERE / name) for name in ledger['source_sha256']}
        expected_addresses = set()
        for name, source in final_sources.items():
            assert hashlib.sha256((HERE / name).read_bytes()).hexdigest() == ledger['source_sha256'][name]
            expected_addresses.update(row.get('va', row.get('seed_va')) for row in source['functions'])
        assert len(ledger['functions']) == len(expected_addresses) == 37
        assert {row['va'] for row in ledger['functions']} == expected_addresses
        counts['ledger_functions'] = len(ledger['functions'])
        counts['ledger_semantic_anchors'] = 0
        for row in ledger['functions']:
            assert row['status'] and row['conclusion'] and row['unknown'] and row['evidence_refs']
            if row['va'] in {'0x8bb2e0', '0x8bb090', '0x755de0'}:
                assert row['status'] == '历史复用主区间局部已审'
            if row['va'] in {'0x8ba950', '0x8bb700'}:
                assert row['status'] == '历史完整声明块复用已审'
            for ref in row['evidence_refs']:
                assert ref['file'] in final_sources
                origin = pointer(final_sources[ref['file']], ref['pointer'])
                assert origin.get('va', origin.get('seed_va')) == row['va']
                ranges = [(int(chunk.get('start_va', chunk.get('va')), 16), chunk['size'])
                          for chunk in origin['chunk_byte_ranges']]
                for anchor in row['semantic_anchors']:
                    ea = int(anchor['va'], 16)
                    assert any(start <= ea < start + size for start, size in ranges)
                    ins = decoded[ea]
                    text_value = ins.mnemonic + ' ' + ins.op_str
                    assert all(token in text_value for token in anchor['tokens']), (row['va'], anchor)
                    counts['ledger_semantic_anchors'] += 1
        counts['ledger_owner_windows'] = len(ledger['owner_windows'])
        assert counts['ledger_owner_windows'] == 9
        for row in ledger['owner_windows']:
            filename, reference = row['evidence'].split('#', 1)
            path = (TOPIC / filename).resolve()
            assert path.is_relative_to(HERE.resolve())
            origin = pointer(load(path), reference)
            assert row['owner_va'] == origin['owner_va']
            start = origin.get('start_va', origin['assembly'][0]['site_va'])
            last = origin['assembly'][-1]
            end = origin.get('end_va', hex(int(last['site_va'], 16) + last['bytes']['size']))
            assert row['start_va'] == start and row['end_va'] == end
            assert row['status'] == '局部owner窗口；不计新函数'
    for path in TOPIC.glob('*.txt'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in path.read_text('utf-8').splitlines())
    for path in (HERE / 'export_bounded.py', HERE / 'prepare_reuse.py',
                 DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py',
                 HERE / 'adapt_bounded.py', HERE / 'validate_current.py'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    hashes[Path(__file__).relative_to(ROOT).as_posix()] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result = dict(status='PASS' if final else 'PREPARATION_CHECKED' if args.preparation_only else 'EVIDENCE_CHECKED', disk_sha256=SHA, **counts, source_sha256=hashes,
                  boundary='独立核原证、逐条指令、来源与终稿范围；未采IDA、未运行客户端，不代表外依赖完成。' if final else '独立核复用及有限原证与当前磁盘；尚非作者终稿审定，未采IDA、未运行客户端。')
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
