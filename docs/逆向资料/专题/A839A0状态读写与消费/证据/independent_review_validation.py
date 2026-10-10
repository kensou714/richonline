"""A839A0 状态专题独立离线核验；不调用 IDA 或作者校验器。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
import pefile

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = ('0x6b77b0', '0x6b8320', '0x796db0', '0x7978b0', '0x798d10',
         '0x798d20', '0x798d40', '0x798d60', '0x768080')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preparation-only', action='store_true')
    parser.add_argument('--evidence-only', action='store_true')
    parser.add_argument('--show', nargs=2)
    args = parser.parse_args()
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA and blob[:2] == b'MZ'
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[pe:pe + 4] == b'PE\0\0' and struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, at + 40 * index + 8)
                for index in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    imports = {item.address: item.name.decode('ascii') for entry in pefile.PE(data=blob).DIRECTORY_ENTRY_IMPORT
               for item in entry.imports if item.name}
    decoded, hashes, counts = {}, {}, {}

    def load(path):
        raw = path.read_bytes()
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def disk(ea, size):
        hits = [(rva, offset) for _, rva, length, offset in sections
                if base + rva <= ea and ea + size <= base + rva + length]
        assert len(hits) <= 1
        if not hits:
            return None
        rva, offset = hits[0]
        raw = blob[offset + ea - base - rva:offset + ea - base - rva + size]
        assert len(raw) == size
        return raw

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

    def audit(row, address=None):
        ea = address if address is not None else int(row.get('start_va', row.get('va')), 16)
        size = row['size']
        raw = disk(ea, size)
        if row['disk_hex'] is None:
            assert raw is None and row['matching'] is None
            assert sum(base + rva <= ea and ea + size <= base + rva + virtual
                       for virtual, rva, _, _ in sections) == 1
            return None
        assert raw is not None and raw.hex() == row['disk_hex'].lower()
        if 'idb_hex' in row:
            assert raw.hex() == row['idb_hex'].lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw

    source = load(DOCS / '专题/TeachMode对象与消费者/证据/teachmode_raw.json')
    historical = pointer(source, '/functions/75')
    assert historical['va'] == '0x6b77b0' and historical['end_va'] == '0x6b77c2'
    assert len(historical['chunks']) == 1
    chunk = historical['chunks'][0]
    raw = audit(chunk)
    assert len(raw) == 18
    instructions = list(decoder.disasm(raw, 0x6B77B0))
    assert sum(ins.size for ins in instructions) == 18 and len(instructions) == 9
    assert len(historical['instructions']) == 9
    for ins, item in zip(instructions, historical['instructions']):
        assert hex(ins.address) == item['va'] and ins.size == item['size']
        assert ins.bytes.hex() == item['hex']
        decoded[ins.address] = ins
    assert (decoded[0x6B77B3].mnemonic, decoded[0x6B77B3].op_str) == ('mov', 'eax, dword ptr [0xa839a0]')
    assert (decoded[0x6B77B8].mnemonic, decoded[0x6B77B8].op_str) == ('and', 'eax, 2')
    counts.update(historical_functions=1, historical_chunks=1, historical_instructions=9)
    if not args.preparation_only:
        bounded = load(HERE / 'bounded_raw.json')
        assert bounded['disk_sha256'] == SHA
        assert tuple(row['seed_va'] for row in bounded['seeds']) == SEEDS
        core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
        assert hashlib.sha256(core.read_bytes()).hexdigest() == bounded['exporter_sha256']
        counts.update(new_functions=len(bounded['functions']), reused_seeds=len(bounded['reused_seeds']),
                      new_chunks=0, new_instructions=0, data_items=0, direct_calls=0,
                      owner_items=0, strict_strings=0, iat_calls=0)
        for row in bounded['current_chunk_audits']:
            assert row['seed_va'] in SEEDS
            for chunk in row['chunk_byte_ranges']:
                assert audit(chunk) is not None
        assert len(bounded['current_chunk_audits']) == len(SEEDS)
        reused_current = bounded['current_chunk_audits'][0]['chunk_byte_ranges']
        assert [(x['start_va'], x['size'], x['disk_hex']) for x in reused_current] == [
            (x.get('start_va', x.get('va')), x['size'], x['disk_hex']) for x in historical['chunks']]
        assert [x['seed_va'] for x in bounded['reused_seeds']] == ['0x6b77b0']
        assert {x['seed_va'] for x in bounded['functions']} == set(SEEDS[1:])
        for row in bounded['functions']:
            current = [item for item in bounded['current_chunk_audits'] if item['seed_va'] == row['seed_va']]
            assert len(current) == 1 and row['chunk_byte_ranges'] == current[0]['chunk_byte_ranges']
            heads = set()
            for chunk in row['chunk_byte_ranges']:
                raw = audit(chunk)
                ea, end = int(chunk['start_va'], 16), int(chunk['start_va'], 16) + chunk['size']
                items = [item for item in row['assembly'] if ea <= int(item['site_va'], 16) < end]
                assert items and int(items[0]['site_va'], 16) == ea
                for index, item in enumerate(items):
                    start = int(item['site_va'], 16)
                    stop = int(items[index + 1]['site_va'], 16) if index + 1 < len(items) else end
                    assert start not in heads and stop > start
                    heads.add(start)
                    if item['is_code']:
                        ins = list(decoder.disasm(disk(start, stop - start), start))
                        assert len(ins) == 1 and ins[0].size == stop - start
                        decoded[start] = ins[0]
                        counts['new_instructions'] += 1
                    else:
                        counts['data_items'] += 1
                counts['new_chunks'] += 1
            assert heads == {int(item['site_va'], 16) for item in row['assembly']}
        bridges = {}
        for row in bounded['verified_direct_bridges']:
            raw = audit(row)
            ea = int(row['start_va'], 16)
            assert len(raw) == 5 and raw[0] == 0xE9
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            assert target == int(row['target_va'], 16)
            assert ea not in bridges or bridges[ea] == target
            bridges[ea] = target
        counts['unique_bridges'] = len(bridges)
        for row in bounded['calls']:
            ins = decoded[int(row['site_va'], 16)]
            assert ins.mnemonic in ('call', 'jmp')
            if ins.operands[0].type == X86_OP_IMM:
                target = ins.operands[0].imm
                counts['direct_calls'] += 1
            else:
                operand = ins.operands[0]
                assert operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0
                target = operand.mem.disp
                assert imports[target] == 'GetTickCount' and not row['bridges']
                counts['iat_calls'] += 1
            assert target == int(row['target_va'], 16)
            for bridge in row['bridges']:
                assert target == int(bridge, 16)
                target = bridges[target]
            assert target == int(row['implementation_va'], 16)
        windows = bounded['explicit_owner_windows'] + [edge['owner_window']
                  for edges in bounded['incoming'].values() for edge in edges if 'owner_window' in edge]
        for window in windows:
            if window['owner_va'] is None:
                assert not window['assembly']
                continue
            assert window['site_va'] in [item['site_va'] for item in window['assembly']]
            assert len(window['assembly']) <= 11
            for item in window['assembly']:
                ea = int(item['site_va'], 16)
                raw = audit(item['bytes'], ea)
                assert isinstance(item['is_code'], bool)
                if item['is_code']:
                    ins = list(decoder.disasm(raw, ea))
                    assert len(ins) == 1 and ins[0].size == len(raw)
                    decoded[ea] = ins[0]
                counts['owner_items'] += 1
        for row in bounded['strings']:
            raw = audit(row['byte_audit'])
            width = row['unit_width']
            assert width in (1, 2) and row['ida_string_type'] == (0 if width == 1 else 1)
            payload = bytes.fromhex(row['payload_hex'])
            assert raw == payload + bytes(width) and bytes.fromhex(row['nul_hex']) == bytes(width)
            assert len(payload) % width == 0
            assert all(payload[index:index + width] != bytes(width) for index in range(0, len(payload), width))
            counts['strict_strings'] += 1
        for row in bounded['data_windows']:
            audit(row)
            assert row['start_va'] == '0xa839a0' and row['size'] == 4 and row['disk_hex'] is None
            assert hashlib.sha256(bytes.fromhex(row['idb_hex'])).hexdigest() == row['sha256']
        for row in bounded['reuse_sources']:
            path = (DOCS / row['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            load(path)
            assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
        anchors = {
            0x6B8323: ('mov', 'eax, dword ptr [ebp + 8]'),
            0x6B8326: ('mov', 'dword ptr [0xa839a0], eax'),
            0x796DB8: ('and', 'eax, 4'), 0x7978B8: ('and', 'eax, 8'),
            0x798D13: ('mov', 'eax, dword ptr [0xa839a0]'),
            0x798D28: ('or', 'eax, 2'), 0x798D2B: ('mov', 'dword ptr [0xa839a0], eax'),
            0x798D48: ('or', 'eax, 4'), 0x798D4B: ('mov', 'dword ptr [0xa839a0], eax'),
            0x798D68: ('or', 'eax, 8'), 0x798D6B: ('mov', 'dword ptr [0xa839a0], eax'),
            0x7680C8: ('sub', 'ecx, 0xb'), 0x7680CE: ('cmp', 'dword ptr [ebp - 0x4c], 3'),
            0x7680D2: ('ja', '0x7683f9'), 0x7680DB: ('jmp', 'dword ptr [edx*4 + 0x768455]'),
            0x7680F4: ('mov', 'dword ptr [ecx + 0x54], eax'),
            0x7680FD: ('sub', 'eax, 1'), 0x768103: ('mov', 'dword ptr [ecx + 0x4c], eax'),
            0x768109: ('cmp', 'dword ptr [edx + 0x4c], 0'),
            0x768178: ('mov', 'eax, dword ptr [edx + 0x4c]'), 0x76817B: ('add', 'eax, 1'),
            0x768201: ('mov', 'dword ptr [edx + 0x54], eax'),
            0x76820A: ('add', 'ecx, 1'), 0x768210: ('mov', 'dword ptr [edx + 0x4c], ecx'),
            0x7682F6: ('movzx', 'eax, byte ptr [edx + 0x50]'),
            0x7682FC: ('je', '0x768375'), 0x768301: ('mov', 'edx, dword ptr [ecx + 0x48]'),
            0x768307: ('cmp', 'dword ptr [ebp - 0x68], 1'),
            0x76830D: ('cmp', 'dword ptr [ebp - 0x68], 2'),
            0x768313: ('cmp', 'dword ptr [ebp - 0x68], 3'),
            0x76836B: ('push', '0x3c'), 0x76839C: ('cmp', 'dword ptr [eax + 0x48], 0'),
            0x7683A0: ('jle', '0x7683f9'),
            0x7683A5: ('movzx', 'edx, byte ptr [ecx + 0x50]'),
            0x7683A9: ('neg', 'edx'), 0x7683AB: ('sbb', 'edx, edx'),
            0x7683AD: ('inc', 'edx'), 0x7683B1: ('mov', 'byte ptr [eax + 0x50], dl'),
            0x7683F9: ('mov', 'al, 1'), 0x768423: ('ret', '8'),
            0x72CDE5: ('movzx', 'eax, al'), 0x73BCE7: ('movzx', 'edx, al'),
            0x6A12CD: ('movzx', 'ecx, al'), 0x6AC4AB: ('push', 'eax'),
            0x6AC4AC: ('call', '0x600df1'),
        }
        for ea, expected in anchors.items():
            assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
        for ea in (0x6B77B0, 0x796DB0, 0x7978B0):
            assert (decoded[ea + 11].mnemonic, decoded[ea + 13].mnemonic,
                    decoded[ea + 15].mnemonic) == ('neg', 'sbb', 'inc')
        counts['independent_semantic_anchors'] = len(anchors) + 11
        if (HERE / 'formal_functions.json').exists():
            formal = load(HERE / 'formal_functions.json')
            assert formal['disk_sha256'] == SHA and formal['source_file'] == 'bounded_raw.json'
            assert formal['source_sha256'] == hashlib.sha256((HERE / 'bounded_raw.json').read_bytes()).hexdigest()
            assert len(formal['functions']) == 8
            for index, row in enumerate(formal['functions']):
                ref = '/functions/' + str(index)
                original = pointer(bounded, ref)
                assert row['source_pointer'] == ref and row['source_file'] == 'bounded_raw.json'
                assert row['source_field_pointers'] == {key: ref + '/' + key for key in original}
                assert all(row[key] == value for key, value in original.items())
                assert all(pointer(bounded, value) == row[key] for key, value in row['source_field_pointers'].items())
                assert row['va'] == original['seed_va']
                assert row['byte_ranges'] == original['chunk_byte_ranges']
                assert row['declared_chunks'] == [dict(start_va=x['start_va'],
                    end_va=hex(int(x['start_va'], 16) + x['size']), is_main=x['start_va'] == row['va'])
                    for x in original['chunk_byte_ranges']]
            reused = load(HERE / 'reused_functions.json')
            assert reused['disk_sha256'] == SHA and len(reused['functions']) == 1
            row = reused['functions'][0]
            assert row['source_path'] == '专题/TeachMode对象与消费者/证据/teachmode_raw.json'
            assert row['source_pointer'] == '/functions/75'
            assert row['source_sha256'] == hashlib.sha256((DOCS / row['source_path']).read_bytes()).hexdigest()
            assert all(row[key] == value for key, value in historical.items())
            assert row['source_field_pointers'] == {key: '/functions/75/' + key for key in historical}
            assert row['assembly'] == [dict(site_va=x['va'], text=x['text'], is_code=True,
                bytes_hex=x['hex'], size=x['size']) for x in historical['instructions']]
            assert row['chunk_byte_ranges'] == [dict(start_va=x['va'],
                **{key: value for key, value in x.items() if key != 'va'}) for x in historical['chunks']]
            assert row['declared_chunks'] == [dict(start_va=x['va'],
                end_va=hex(int(x['va'], 16) + x['size']), is_main=x['va'] == row['va']) for x in historical['chunks']]
            assert reused['sources'] == [dict(path=row['source_path'], source_sha256=row['source_sha256'])]
            counts['lossless_adapted_functions'] = 9
        supplement = HERE / 'navigation_supplement/bounded_raw.json'
        if supplement.exists():
            navigation = load(supplement)
            assert navigation['disk_sha256'] == SHA and not navigation['functions']
            assert len(navigation['data_windows']) == 2
            table, pointers = [audit(x) for x in navigation['data_windows']]
            assert navigation['data_windows'][0]['start_va'] == '0x768455'
            assert struct.unpack('<4I', table) == (0x7680E2, 0x7681EF, 0x7682F3, 0x768399)
            assert navigation['data_windows'][1]['start_va'] == '0xa29c98'
            assert struct.unpack_from('<I', pointers, 16)[0] == 0x60058B
            for window in navigation['explicit_owner_windows']:
                assert window['owner_va'] == '0x828f60' and len(window['assembly']) <= 11
                for item in window['assembly']:
                    ea = int(item['site_va'], 16)
                    raw = audit(item['bytes'], ea)
                    ins = list(decoder.disasm(raw, ea))
                    assert len(ins) == 1 and ins[0].size == len(raw)
                    decoded[ea] = ins[0]
            counts['supplement_owner_items'] = sum(len(x['assembly']) for x in navigation['explicit_owner_windows'])
            counts['supplement_data_windows'] = 2
        def decode_record(row):
            chunks = row.get('chunk_byte_ranges', row.get('chunks'))
            heads = []
            for chunk in chunks:
                raw = audit(chunk)
                ea = int(chunk.get('start_va', chunk.get('va')), 16)
                insns = list(decoder.disasm(raw, ea))
                assert sum(x.size for x in insns) == len(raw)
                heads.extend(insns)
                for ins in insns:
                    decoded[ins.address] = ins
            source_asm = row.get('assembly', row.get('instructions'))
            assert [hex(x.address) for x in heads] == [x.get('site_va', x.get('va')) for x in source_asm]
            return len(heads), len(chunks)
        dependency = HERE / 'case60_dependency_raw.json'
        if dependency.exists():
            dependencies = load(dependency)
            assert dependencies['disk_sha256'] == SHA
            assert [x['va'] for x in dependencies['functions']] == ['0x6005e0', '0x600cc5', '0x60df01', '0x60ed48', '0x82e230']
            totals = [decode_record(row) for row in dependencies['functions']]
            counts['dependency_functions'] = len(totals)
            counts['dependency_instructions'] = sum(x[0] for x in totals)
            counts['dependency_chunks'] = sum(x[1] for x in totals)
            assert (decoded[0x82E253].mnemonic, decoded[0x82E253].op_str) == ('mov', 'eax, dword ptr [ebp + 8]')
            assert (decoded[0x82E25A].mnemonic, decoded[0x82E25A].op_str) == ('call', '0x6059a0')
            assert (decoded[0x82E272].mnemonic, decoded[0x82E272].op_str) == ('ret', '4')
            for ea, target in ((0x6005E0, 0x82AB80), (0x600CC5, 0x82E230), (0x60DF01, 0x82A900), (0x60ED48, 0x8976E0)):
                assert decoded[ea].mnemonic == 'jmp' and decoded[ea].operands[0].imm == target, hex(ea)
            bridge_bytes = disk(0x6059A0, 5)
            assert bridge_bytes[0] == 0xE9 and 0x6059A5 + struct.unpack_from('<i', bridge_bytes, 1)[0] == 0x8A06C0
            counts['wrapper_disk_bridge_target'] = '0x8a06c0'
        historical_path = HERE / 'historical_contracts.json'
        if historical_path.exists():
            contracts = load(historical_path)
            assert contracts['disk_sha256'] == SHA and len(contracts['contracts']) >= 4
            contract_counts = []
            for row in contracts['contracts']:
                path = DOCS / row['source_path']
                original_source = load(path)
                assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
                original = pointer(original_source, row['source_pointer'])
                assert original == row['source_record'] and original['va'] == row['va']
                contract_counts.append(decode_record(original))
            counts['reference_contracts'] = len(contract_counts)
            counts['reference_mechanical_instructions'] = sum(x[0] for x in contract_counts)
            counts['reference_mechanical_chunks'] = sum(x[1] for x in contract_counts)
        table_path = HERE / 'case60_table/bounded_raw.json'
        if table_path.exists():
            table_source = load(table_path)
            assert table_source['disk_sha256'] == SHA and not table_source['functions']
            assert len(table_source['data_windows']) == 2
            selector, target = [audit(x) for x in table_source['data_windows']]
            assert table_source['data_windows'][0]['start_va'] == hex(0x82A355 + 60)
            assert selector == bytes([0x2B])
            assert table_source['data_windows'][1]['start_va'] == hex(0x82A295 + selector[0] * 4)
            assert struct.unpack('<I', target)[0] == 0x82A1F2
            closure_anchors = {
                0x828F93: ('mov', 'eax, dword ptr [ebp + 8]'),
                0x828F9C: ('cmp', 'dword ptr [ebp - 0x520], 0x67'),
                0x828FA3: ('ja', '0x82a23c'),
                0x828FAF: ('movzx', 'edx, byte ptr [ecx + 0x82a355]'),
                0x828FB6: ('jmp', 'dword ptr [edx*4 + 0x82a295]'),
                0x82A1F2: ('mov', 'eax, dword ptr [ebp + 0xc]'),
                0x82A1F5: ('push', 'eax'), 0x82A1F6: ('call', '0x60ed48'),
                0x82A1FD: ('call', '0x6005e0'), 0x82A204: ('call', '0x60df01'),
                0x82A20B: ('call', '0x600cc5'), 0x82ABA6: ('mov', 'eax, dword ptr [eax + 0x20]'),
                0x82A926: ('mov', 'eax, dword ptr [eax + 0x50]'),
                0x89774F: ('mov', 'eax, 0xacbb30'),
                0xA198F5: ('and', 'eax, 0xfffffffe'),
            }
            for ea, expected in closure_anchors.items():
                assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
            counts['closure_semantic_anchors'] = len(closure_anchors)
            counts['case60_table_windows'] = 2
    if args.show:
        start, end = (int(value, 16) for value in args.show)
        for ea, ins in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X} {ins.mnemonic:8} {ins.op_str}')
        return
    if not args.preparation_only and not args.evidence_only:
        ledger = load(TOPIC / '函数审阅清单.json')
        assert ledger['disk_sha256'] == SHA
        assert len({x['va'] for x in ledger['functions']}) == len(ledger['functions'])
        assert {x['va'] for x in ledger['functions']} == set(SEEDS) | {
            '0x6005e0', '0x600cc5', '0x60df01', '0x60ed48', '0x82e230'}
        ledger_anchor_count = 0
        for row in ledger['functions']:
            assert row['conclusion'] and row['unknown'] and row['evidence_refs']
            assert row['status'] in ('完整审阅', '局部审阅')
            for reference in row['evidence_refs']:
                evidence = load(HERE / reference['file'])
                original = pointer(evidence, reference['pointer'])
                assert original.get('va', original.get('seed_va')) == row['va']
            for anchor in row['semantic_anchors']:
                ins = decoded[int(anchor['va'], 16)]
                text = ins.mnemonic + ' ' + ins.op_str
                assert all(token in text for token in anchor['tokens']), (row['va'], anchor)
                ledger_anchor_count += 1
        for row in ledger['owner_windows']:
            evidence = load(HERE / row['evidence_file'])
            window = pointer(evidence, row['evidence_pointer'])
            assert row['owner_va'] == window['owner_va'] and row['site_va'] == window['site_va']
            assert row['start_va'] == window['assembly'][0]['site_va']
            item = window['assembly'][-1]
            assert int(row['end_va'], 16) == int(item['site_va'], 16) + item['bytes']['size']
        counts['ledger_functions'] = len(ledger['functions'])
        counts['ledger_semantic_anchors'] = ledger_anchor_count
        counts['ledger_owner_windows'] = len(ledger['owner_windows'])
    for path in TOPIC.glob('*.txt'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    for path in HERE.glob('*.py'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = dict(status='PREPARATION_CHECKED' if args.preparation_only else 'EVIDENCE_CHECKED' if args.evidence_only else 'PASS',
                  disk_sha256=SHA, **counts, source_sha256=hashes,
                  boundary='独立核当前PE、有限原证与终稿文件SHA；未采IDA、未运行客户端；依赖未知项以正文为界。')
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
