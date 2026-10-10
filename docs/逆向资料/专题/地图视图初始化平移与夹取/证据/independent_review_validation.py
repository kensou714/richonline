"""地图视图专题独立离线核验；不调用作者程序或 IDA。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = ('0x7b6c90', '0x7b6ef0', '0x638150', '0x650c10', '0x7b6d50', '0x7b6f60', '0x7e1600')


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
    sections = [struct.unpack_from('<4I', blob, at + index * 40 + 8)
                for index in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded, hashes, counts = {}, {}, {}

    def load(path):
        raw = path.read_bytes()
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def pointer(data, value):
        assert value.startswith('/')
        for part in value[1:].split('/'):
            key = part.replace('~1', '/').replace('~0', '~')
            data = data[int(key)] if isinstance(data, list) else data[key]
        return data

    def disk(ea, size):
        hits = [(rva, offset) for _, rva, length, offset in sections
                if base + rva <= ea and ea + size <= base + rva + length]
        assert len(hits) == 1, (hex(ea), size)
        rva, offset = hits[0]
        raw = blob[offset + ea - base - rva:offset + ea - base - rva + size]
        assert len(raw) == size
        return raw

    def audit(row, address=None):
        ea = address if address is not None else int(row.get('start_va', row.get('va')), 16)
        raw = disk(ea, row['size'])
        assert raw.hex() == row['disk_hex'].lower()
        assert raw.hex() == row.get('idb_hex', row.get('ida_hex')).lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw

    def decode_record(row):
        chunks = row.get('chunk_byte_ranges', row.get('chunks', row.get('byte_ranges')))
        heads = []
        for chunk in chunks:
            raw = audit(chunk)
            ea = int(chunk.get('start_va', chunk.get('va')), 16)
            insns = list(decoder.disasm(raw, ea))
            assert sum(ins.size for ins in insns) == len(raw)
            heads.extend(insns)
            for ins in insns:
                decoded[ins.address] = ins
        assembly = row.get('assembly', row.get('instructions'))
        assert [hex(ins.address) for ins in heads] == [item.get('site_va', item.get('va')) for item in assembly]
        return len(heads), len(chunks)

    old_specs = (
        ('专题/断线与离席恢复/ida_disconnect_fields.json', '0x7b6d50'),
        ('专题/断线与离席恢复/ida_disconnect_dependencies.json', '0x7b6f60'),
        ('专题/断线与离席恢复/ida_disconnect_fields.json', '0x7e1600'),
    )
    old_rows = {}
    counts.update(historical_functions=3, historical_chunks=0, historical_mechanical_instructions=0)
    for path, va in old_specs:
        source = load(DOCS / path)
        assert source['disk_sha256'].lower() == SHA
        matches = [(index, row) for index, row in enumerate(source['functions']) if row['va'] == va]
        assert len(matches) == 1
        index, row = matches[0]
        old_rows[va] = row
        number, chunks = decode_record(row)
        counts['historical_chunks'] += chunks
        counts['historical_mechanical_instructions'] += number
        counts[va + '_source_pointer'] = '/functions/' + str(index)
    init_source = load(DOCS / '专题/TeachMode序号生产与根对象/证据/load_source_raw.json')
    assert init_source['disk_sha256'] == SHA
    assert init_source['functions'][1]['va'] == '0x64f2a0'
    number, chunks = decode_record(init_source['functions'][1])
    counts['caller_reference_mechanical_instructions'] = number
    counts['caller_reference_chunks'] = chunks
    if not args.preparation_only:
        bounded = load(HERE / 'bounded_raw.json')
        assert bounded['disk_sha256'] == SHA and tuple(x['seed_va'] for x in bounded['seeds']) == SEEDS
        core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
        assert hashlib.sha256(core.read_bytes()).hexdigest() == bounded['exporter_sha256']
        assert [x['seed_va'] for x in bounded['functions']] == list(SEEDS[:4])
        assert [x['seed_va'] for x in bounded['reused_seeds']] == list(SEEDS[4:])
        assert len(bounded['current_chunk_audits']) == len(SEEDS)
        counts.update(new_functions=4, new_chunks=0, new_instructions=0)
        for row in bounded['current_chunk_audits']:
            for chunk in row['chunk_byte_ranges']:
                audit(chunk)
            if row['seed_va'] in old_rows:
                assert [(x['start_va'], x['size'], x['disk_hex']) for x in row['chunk_byte_ranges']] == [
                    (x.get('start_va', x.get('va')), x['size'], x['disk_hex'])
                    for x in old_rows[row['seed_va']].get('chunk_byte_ranges', old_rows[row['seed_va']].get('chunks', old_rows[row['seed_va']].get('byte_ranges')))]
        for row in bounded['functions']:
            current = next(x for x in bounded['current_chunk_audits'] if x['seed_va'] == row['seed_va'])
            assert current['chunk_byte_ranges'] == row['chunk_byte_ranges']
            number, chunks = decode_record(row)
            assert all(item['is_code'] for item in row['assembly'])
            counts['new_instructions'] += number
            counts['new_chunks'] += chunks
        bridges = {}
        for row in bounded['verified_direct_bridges']:
            raw = audit(row)
            ea = int(row['start_va'], 16)
            assert len(raw) == 5 and raw[0] == 0xE9
            target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
            assert target == int(row['target_va'], 16)
            assert ea not in bridges or bridges[ea] == target
            bridges[ea] = target
        counts.update(unique_bridges=len(bridges), direct_calls=0, owner_items=0)
        for row in bounded['calls']:
            ins = decoded[int(row['site_va'], 16)]
            assert ins.mnemonic in ('call', 'jmp') and ins.operands[0].type == X86_OP_IMM
            target = ins.operands[0].imm
            assert target == int(row['target_va'], 16)
            for bridge in row['bridges']:
                assert target == int(bridge, 16)
                target = bridges[target]
            assert target == int(row['implementation_va'], 16)
            counts['direct_calls'] += 1
        windows = bounded['explicit_owner_windows'] + [edge['owner_window']
            for edges in bounded['incoming'].values() for edge in edges if 'owner_window' in edge]
        assert [x['site_va'] for x in bounded['explicit_owner_windows']] == [
            '0x64f50a', '0x64f519', '0x64f532', '0x64f54c']
        for window in windows:
            if window['owner_va'] is None:
                assert not window['assembly']
                continue
            assert window['site_va'] in [x['site_va'] for x in window['assembly']]
            assert len(window['assembly']) <= 11
            previous_end = None
            for item in window['assembly']:
                ea = int(item['site_va'], 16)
                raw = audit(item['bytes'], ea)
                assert previous_end is None or ea == previous_end
                previous_end = ea + len(raw)
                if item['is_code']:
                    insns = list(decoder.disasm(raw, ea))
                    assert len(insns) == 1 and insns[0].size == len(raw)
                    decoded[ea] = insns[0]
                counts['owner_items'] += 1
        assert not bounded['strings'] and not bounded['data_windows']
        for row in bounded['reuse_sources']:
            path = (DOCS / row['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            load(path)
            assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
        counts['lossless_adaptations'] = 0
        if (HERE / 'dimension_getters_raw.json').exists():
            dimensions = load(HERE / 'dimension_getters_raw.json')
            assert dimensions['disk_sha256'] == SHA
            assert [row['va'] for row in dimensions['functions']] == ['0x60b044', '0x60bf9e', '0x6919f0', '0x691a20']
            dimensions_counts = [decode_record(row) for row in dimensions['functions']]
            counts['dimension_body_functions'] = 2
            counts['dimension_body_chunks'] = sum(x[1] for x in dimensions_counts[2:])
            counts['dimension_body_instructions'] = sum(x[0] for x in dimensions_counts[2:])
            counts['dimension_bridge_records'] = 2
            for row, target in zip(dimensions['functions'][:2], (0x6919F0, 0x691A20)):
                ins = decoded[int(row['va'], 16)]
                assert ins.mnemonic == 'jmp' and ins.operands[0].imm == target
            dimension_anchors = {0x691A01: ('mov', 'eax, dword ptr [eax + 0x1c]'),
                0x691A04: ('shl', 'eax, 6'), 0x691A31: ('mov', 'eax, dword ptr [eax + 0x20]'),
                0x691A34: ('imul', 'eax, eax, 0x30')}
            for ea, expected in dimension_anchors.items():
                assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected
            counts['dimension_semantic_anchors'] = len(dimension_anchors)
        for filename in ('formal_functions.json', 'formal_dependencies.json', 'reused_functions.json'):
            if not (HERE / filename).exists():
                continue
            adapted = load(HERE / filename)
            assert adapted['disk_sha256'] == SHA
            for row in adapted['functions']:
                path = DOCS / row['source_path']
                original_source = load(path)
                assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
                original = pointer(original_source, row['source_pointer'])
                assert all(row[key] == value for key, value in original.items())
                assert row['source_field_pointers'] == {key: row['source_pointer'] + '/' + key for key in original}
                assert all(pointer(original_source, ptr) == row[key] for key, ptr in row['source_field_pointers'].items())
                va = original.get('seed_va', original.get('va', original.get('address')))
                assert row['va'] == va
                chunks = original.get('chunk_byte_ranges', original.get('chunks', original.get('byte_ranges')))
                assert row['normalized_chunks'] == [dict(start_va=x.get('start_va', x.get('va', x.get('address'))),
                    **{key: value for key, value in x.items() if key not in ('start_va', 'va', 'address')}) for x in chunks]
                assembly = original.get('assembly', original.get('instructions'))
                assert row['normalized_assembly'] == [dict(site_va=x.get('site_va', x.get('va', x.get('address'))),
                    text=x['text'], is_code=x.get('is_code', True), original=x) for x in assembly]
                if 'declared_chunks' not in original:
                    assert row['declared_chunks'] == [dict(start_va=x['start_va'],
                        end_va=hex(int(x['start_va'], 16) + x['size']), is_main=x['start_va'] == va) for x in row['normalized_chunks']]
                if 'byte_ranges' not in original:
                    assert row['byte_ranges'] == chunks
                if filename == 'reused_functions.json' and va not in SEEDS:
                    number, chunk_count = decode_record(original)
                    counts['all_historical_contract_instructions'] = counts.get('all_historical_contract_instructions', 0) + number
                    counts['all_historical_contract_chunks'] = counts.get('all_historical_contract_chunks', 0) + chunk_count
                counts['lossless_adaptations'] += 1
        anchors = {
            0x7B6CA1: ('mov', 'cx, word ptr [ebp + 8]'),
            0x7B6CA5: ('mov', 'word ptr [eax], cx'),
            0x7B6CAF: ('mov', 'word ptr [edx + 2], ax'),
            0x7B6CB6: ('mov', 'word ptr [ecx + 6], 0'),
            0x7B6CCC: ('mov', 'word ptr [eax + 8], cx'),
            0x7B6CD7: ('mov', 'word ptr [edx + 0xa], ax'),
            0x7B6CDE: ('mov', 'word ptr [ecx + 0x16], 0'),
            0x7B6CE7: ('mov', 'word ptr [edx + 0x14], 0'),
            0x7B6CF4: ('mov', 'word ptr [eax + 0x18], cx'),
            0x7B6CFF: ('mov', 'word ptr [edx + 0x1a], ax'),
            0x7B6D06: ('mov', 'word ptr [ecx + 0x1c], 0x262'),
            0x7B6D0F: ('mov', 'word ptr [edx + 0x1e], 0x218'),
            0x7B6D3F: ('mov', 'word ptr [edx + 0x26], cx'),
            0x7B6D46: ('ret', '0x10'),
            0x7B6F01: ('movsx', 'ecx, word ptr [eax + 4]'),
            0x7B6F05: ('add', 'ecx, dword ptr [ebp + 8]'),
            0x7B6F0B: ('mov', 'word ptr [edx + 4], cx'),
            0x7B6F1C: ('mov', 'word ptr [edx + 6], cx'),
            0x7B6F2D: ('mov', 'word ptr [edx + 0x20], cx'),
            0x7B6F3E: ('mov', 'word ptr [edx + 0x22], cx'),
            0x7B6F45: ('call', '0x611697'),
            0x7B6F57: ('ret', '8'),
            0x638198: ('movsx', 'ecx, word ptr [eax]'),
            0x6381AD: ('cmp', 'ecx, dword ptr [edx + 0x1c]'),
            0x6381B2: ('mov', 'eax, 1'),
            0x6381C2: ('call', '0x6107f1'),
            0x6381CC: ('je', '0x6382d4'),
            0x6381DE: ('jle', '0x63820d'),
            0x6381E3: ('mov', 'edx, dword ptr [ecx + 0xc]'),
            0x638221: ('neg', 'edx'),
            0x638270: ('jle', '0x638284'),
            0x63829B: ('neg', 'ecx'),
            0x6382CF: ('call', '0x60ee10'),
            0x6382D4: ('xor', 'eax, eax'),
            0x650C2A: ('mov', 'dword ptr [ebp - 8], 0x19'),
            0x650C53: ('jle', '0x650c6a'),
            0x650C55: ('push', '0x25'),
            0x650C72: ('jmp', '0x650cad'),
            0x650C80: ('mov', 'ecx, 0x26d'),
            0x650C8D: ('jge', '0x650ca4'),
            0x650C8F: ('push', '0x27'),
            0x650CBC: ('add', 'ecx, 0x1e'),
            0x650CC1: ('jle', '0x650cd8'),
            0x650CC3: ('push', '0x26'),
            0x650CE1: ('jmp', '0x650d1c'),
            0x650CEF: ('mov', 'ecx, 0x239'),
            0x650CFE: ('push', '0x28'),
            0x650D26: ('je', '0x650d3e'),
            0x650D33: ('add', 'ecx, 0xc14'),
            0x650D39: ('call', '0x60ee10'),
            0x7B6D61: ('movsx', 'ecx, word ptr [eax + 4]'),
            0x7B6D67: ('jge', '0x7b6d72'),
            0x7B6D98: ('mov', 'word ptr [edx + 8], cx'),
            0x7B6DB6: ('movsx', 'ecx, word ptr [eax + 8]'),
            0x7B6DC3: ('jle', '0x7b6de9'),
            0x7B6E5B: ('mov', 'word ptr [ecx + 0x24], ax'),
            0x7B6FC7: ('sar', 'edx, 1'),
            0x7B6FD1: ('mov', 'word ptr [ecx + 4], ax'),
            0x7B6F9D: ('mov', 'eax, dword ptr [ebp - 0xc]'),
            0x7B6FA0: ('shl', 'eax, 6'),
            0x7B6FA9: ('imul', 'ecx, ecx, 0x30'),
            0x7E1614: ('cdq', ''),
            0x7E1615: ('idiv', 'dword ptr [ecx + 0x1c]'),
            0x7E1624: ('idiv', 'dword ptr [ecx + 0x1c]'),
            0x64F504: ('add', 'ecx, 0x65c'),
            0x64F51F: ('push', '0x239'),
            0x64F524: ('push', '0x26d'),
            0x64F52C: ('add', 'ecx, 0xc14'),
            0x64F540: ('push', 'edx'),
            0x64F541: ('push', '0'),
        }
        for ea, expected in anchors.items():
            assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, (hex(ea), decoded[ea].op_str)
        counts['independent_semantic_anchors'] = len(anchors)
        if counts['lossless_adaptations'] == 15:
            reference_anchors = {0x63E0F1: ('add', 'eax, 0xc14'),
                0x63E011: ('add', 'eax, 4'), 0x81BD43: ('jbe', '0x81bd6e'),
                0x81BD53: ('jb', '0x81bd6e'), 0x81BD67: ('mov', 'dword ptr [edx + 4], eax'),
                0x81BD6A: ('mov', 'al, 1')}
            for ea, expected in reference_anchors.items():
                assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, (hex(ea), decoded[ea].op_str)
            counts['reference_semantic_anchors'] = len(reference_anchors)
    if args.show:
        start, end = (int(value, 16) for value in args.show)
        for ea, ins in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X} {ins.mnemonic:8} {ins.op_str}')
        return
    if not args.preparation_only and not args.evidence_only:
        ledger = load(TOPIC / '函数审阅清单.json')
        assert ledger['disk_sha256'] == SHA
        expected = set(SEEDS) | {'0x6919f0', '0x691a20'}
        assert len(ledger['functions']) == 9 and {row['va'] for row in ledger['functions']} == expected
        counts['ledger_semantic_anchors'] = 0
        for row in ledger['functions'] + ledger['direct_bridges'] + ledger['historical_contracts']:
            assert row.get('conclusion', row.get('status')) and row['semantic_anchors']
            if row in ledger['functions']:
                assert row['status'] == ('部分分析' if row['va'] in ('0x638150', '0x650c10') else '完整分析')
                assert row['unknown']
            refs = row.get('evidence_refs', [row.get('evidence_ref')])
            permitted_sites = set()
            for ref in refs:
                entry = pointer(load(HERE / ref['file']), ref['pointer'])
                assert entry['va'] == row['va']
                if 'declared_chunks' in row:
                    assert row['declared_chunks'] == entry['declared_chunks']
                assert row['instruction_count'] == sum(item['is_code'] for item in entry['normalized_assembly'])
                for key in ('source_path', 'source_pointer', 'source_sha256'):
                    if key in row:
                        assert row[key] == entry[key]
                permitted_sites.update(int(item['site_va'], 16) for item in entry['normalized_assembly'] if item['is_code'])
            for anchor in row['semantic_anchors']:
                ea = int(anchor['va'], 16)
                assert ea in permitted_sites
                ins = decoded[ea]
                text = ins.mnemonic + ' ' + ins.op_str
                assert anchor['tokens'] and all(token in text for token in anchor['tokens'])
                counts['ledger_semantic_anchors'] += 1
        for row in ledger['owner_windows']:
            assert row['status'] == '局部窗口分析' and row['conclusion'] and row['unknown']
            ref = row['evidence_ref']
            source = pointer(load(HERE / ref['file']), ref['pointer'])
            assert (row['owner_va'], row['site_va']) == (source['owner_va'], source['site_va'])
            assert row['start_va'] == source['assembly'][0]['site_va']
            last = source['assembly'][-1]
            assert int(row['end_va'], 16) == int(last['site_va'], 16) + last['bytes']['size']
        assert ledger['summary'] == dict(reviewed_functions=9, complete=7, partial=2,
            new_seed_bodies=4, deepened_historical_bodies=3, new_dimension_bodies=2,
            direct_bridges=2, owner_windows=4, historical_contracts=4,
            reviewed_instructions=565, historical_contract_instructions=308)
        assert counts['lossless_adaptations'] == 15 and counts['all_historical_contract_instructions'] == 308
        assert counts['ledger_semantic_anchors'] == 63
        author = load(HERE / 'validation.json')
        assert author['status'] == 'PASS' and author['disk_sha256'] == SHA
    for path in TOPIC.glob('*.txt'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    for path in HERE.glob('*.py'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in HERE.glob('*.txt'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status='PREPARATION_CHECKED' if args.preparation_only else 'EVIDENCE_CHECKED' if args.evidence_only else 'PASS',
                  disk_sha256=SHA, **counts, source_sha256=hashes,
                  boundary='当前PE、有限原证与终稿独审；窗口不扩大owner业务认领；未调用IDA或运行游戏。')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
