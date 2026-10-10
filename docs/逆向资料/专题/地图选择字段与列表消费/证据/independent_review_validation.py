"""地图选择字段专题独立离线审计；不调用 IDA 或作者校验器。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = ('0x73fc70', '0x6aa840', '0x6aa8c0', '0x6aa940', '0x6aa960', '0x6aa9c0', '0x73f420')


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
        raw = disk(ea, row['size'])
        if row['disk_hex'] is None:
            assert raw is None and row['matching'] is None
            assert sum(base + rva <= ea and ea + row['size'] <= base + rva + virtual
                       for virtual, rva, _, _ in sections) == 1
            return None
        assert raw is not None and raw.hex() == row['disk_hex'].lower()
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
            assert sum(x.size for x in insns) == len(raw)
            heads.extend(insns)
            for ins in insns:
                decoded[ins.address] = ins
        assembly = row.get('assembly', row.get('instructions'))
        assert [hex(x.address) for x in heads] == [x.get('site_va', x.get('va')) for x in assembly]
        return len(heads), len(chunks)

    historical_source = load(DOCS / '专题/MapView配置记录与预览消费/证据/closure_raw.json')
    assert historical_source['disk_sha256'] == SHA
    historical = pointer(historical_source, '/functions/1')
    assert historical['va'] == '0x73f420' and historical['end_va'] == '0x73fb59'
    instruction_count, chunk_count = decode_record(historical)
    counts.update(historical_functions=1, historical_chunks=chunk_count,
                  historical_mechanical_instructions=instruction_count)
    if not args.preparation_only:
        bounded = load(HERE / 'bounded_raw.json')
        assert bounded['disk_sha256'] == SHA and tuple(x['seed_va'] for x in bounded['seeds']) == SEEDS
        core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
        assert hashlib.sha256(core.read_bytes()).hexdigest() == bounded['exporter_sha256']
        assert {x['seed_va'] for x in bounded['functions']} == set(SEEDS[:-1])
        assert [x['seed_va'] for x in bounded['reused_seeds']] == ['0x73f420']
        counts.update(new_functions=6, new_chunks=0, new_instructions=0, data_items=0)
        for row in bounded['current_chunk_audits']:
            for chunk in row['chunk_byte_ranges']:
                audit(chunk)
        assert len(bounded['current_chunk_audits']) == len(SEEDS)
        reused_current = next(x for x in bounded['current_chunk_audits'] if x['seed_va'] == '0x73f420')
        assert [(x['start_va'], x['size'], x['disk_hex']) for x in reused_current['chunk_byte_ranges']] == [
            (x.get('start_va', x.get('va')), x['size'], x['disk_hex']) for x in historical['chunk_byte_ranges']]
        for row in bounded['functions']:
            current = [x for x in bounded['current_chunk_audits'] if x['seed_va'] == row['seed_va']]
            assert len(current) == 1 and current[0]['chunk_byte_ranges'] == row['chunk_byte_ranges']
            heads = set()
            for chunk in row['chunk_byte_ranges']:
                audit(chunk)
                ea, end = int(chunk['start_va'], 16), int(chunk['start_va'], 16) + chunk['size']
                items = [x for x in row['assembly'] if ea <= int(x['site_va'], 16) < end]
                assert items and int(items[0]['site_va'], 16) == ea
                for index, item in enumerate(items):
                    start = int(item['site_va'], 16)
                    stop = int(items[index + 1]['site_va'], 16) if index + 1 < len(items) else end
                    assert start not in heads and stop > start
                    heads.add(start)
                    if item['is_code']:
                        insns = list(decoder.disasm(disk(start, stop - start), start))
                        assert len(insns) == 1 and insns[0].size == stop - start
                        decoded[start] = insns[0]
                        counts['new_instructions'] += 1
                    else:
                        counts['data_items'] += 1
                counts['new_chunks'] += 1
            assert heads == {int(x['site_va'], 16) for x in row['assembly']}
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
        counts['direct_calls'] = 0
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
        counts['owner_items'] = 0
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
        counts['strict_strings'] = 0
        for row in bounded['strings']:
            raw = audit(row['byte_audit'])
            width = row['unit_width']
            assert width in (1, 2) and row['ida_string_type'] == (0 if width == 1 else 1)
            payload = bytes.fromhex(row['payload_hex'])
            assert raw == payload + bytes(width) and bytes.fromhex(row['nul_hex']) == bytes(width)
            assert len(payload) % width == 0
            assert all(payload[i:i + width] != bytes(width) for i in range(0, len(payload), width))
            counts['strict_strings'] += 1
        for row in bounded['data_windows']:
            audit(row)
        for row in bounded['reuse_sources']:
            path = (DOCS / row['path']).resolve()
            assert path.is_relative_to(DOCS.resolve())
            load(path)
            assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
        anchors = {
            0x6AA86C: ('mov', 'ecx, dword ptr [eax]'),
            0x6AA888: ('mov', 'eax, dword ptr [edx + 0x520]'),
            0x6AA893: ('mov', 'eax, dword ptr [eax + 0x52c]'),
            0x6AA89E: ('mov', 'eax, dword ptr [ecx + 0x538]'),
            0x6AA8A6: ('xor', 'eax, eax'),
            0x6AA908: ('mov', 'eax, dword ptr [edx + 0x524]'),
            0x6AA913: ('mov', 'eax, dword ptr [eax + 0x530]'),
            0x6AA91E: ('mov', 'eax, dword ptr [ecx + 0x53c]'),
            0x6AA926: ('xor', 'eax, eax'),
            0x6AA951: ('mov', 'eax, dword ptr [eax + 0x514]'),
            0x6AA991: ('cmp', 'dword ptr [ebp - 0xc], 2'),
            0x6AA995: ('je', '0x6aa999'), 0x6AA997: ('jmp', '0x6aa9a4'),
            0x6AA99C: ('mov', 'eax, dword ptr [edx + 0x51c]'),
            0x6AA9A7: ('mov', 'eax, dword ptr [eax + 0x518]'),
            0x6AAA08: ('mov', 'eax, dword ptr [edx + 0x528]'),
            0x6AAA13: ('mov', 'eax, dword ptr [eax + 0x534]'),
            0x6AAA1E: ('mov', 'eax, dword ptr [ecx + 0x540]'),
            0x6AAA26: ('xor', 'eax, eax'),
            0x73FC9A: ('mov', 'byte ptr [ebp - 0x129], 0'),
            0x73FCB3: ('mov', 'ecx, dword ptr [eax + 0x38]'),
            0x73FCD2: ('mov', 'byte ptr [ebp - 0x129], 1'),
            0x73FD9A: ('cmp', 'byte ptr [ebp - 0x129], 0'),
            0x73FDA1: ('jne', '0x73fdb0'), 0x73FDA3: ('push', '0x73fe40'),
            0x73FDA8: ('call', '0x6104db'), 0x73FDB0: ('push', '0'),
            0x73FDB2: ('lea', 'eax, [ebp - 0x128]'),
            0x73FDB9: ('mov', 'ecx, dword ptr [ebp - 0x10]'),
            0x73FDBC: ('call', '0x60e712'), 0x73FDC1: ('push', 'eax'),
            0x73FDC5: ('add', 'ecx, 0xd0'), 0x73FDCC: ('call', '0x61040e'),
            0x73FDD4: ('mov', 'dword ptr [ebp - 0xa4], 4'),
            0x73FDE0: ('lea', 'edx, [ebp - 0xa4]'),
            0x73FDEF: ('call', 'dword ptr [edx + 0x10]'),
            0x73F56B: ('mov', 'eax, dword ptr [edx + 0x4c]'),
            0x73F62C: ('cmp', 'byte ptr [ebp - 0x39], 0'),
            0x73F637: ('call', '0x6104db'), 0x73F642: ('call', '0x6075b6'),
            0x73F659: ('mov', 'ecx, dword ptr [eax + 0x150]'),
            0x73F692: ('cmp', 'eax, dword ptr [ebp - 0x10]'),
            0x73F695: ('jge', '0x73f876'),
            0x73F69B: ('cmp', 'dword ptr [ebp - 0x18], 0x1e'),
        }
        for ea, expected in anchors.items():
            assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
        counts['independent_semantic_anchors'] = len(anchors)
        assert len(bounded['data_windows']) == 1
        assert bounded['data_windows'][0]['start_va'] == '0x73fe40'
        assert audit(bounded['data_windows'][0]) == b'pMapList\0'
        if (HERE / 'dependency_raw.json').exists():
            dependency = load(HERE / 'dependency_raw.json')
            assert dependency['disk_sha256'] == SHA
            assert [x['va'] for x in dependency['functions']] == ['0x79a1e0', '0x79ca40', '0x79cad0']
            totals = [decode_record(row) for row in dependency['functions']]
            counts['dependency_functions'] = len(totals)
            counts['dependency_instructions'] = sum(x[0] for x in totals)
            counts['dependency_chunks'] = sum(x[1] for x in totals)
            for row in dependency['functions']:
                for call in row['calls']:
                    ins = decoded[int(call['site'], 16)]
                    assert ins.mnemonic == 'call' and ins.operands[0].imm == int(call['target'], 16)
                    target = ins.operands[0].imm
                    for bridge in call['thunks']:
                        assert target == int(bridge, 16)
                        raw = disk(target, 5)
                        assert raw[0] == 0xE9
                        target = target + 5 + struct.unpack_from('<i', raw, 1)[0]
                    assert target == int(call['implementation'], 16)
            dependency_anchors = {
                0x79A1F1: ('mov', 'eax, dword ptr [eax + 8]'),
                0x79CA6A: ('mov', 'ecx, dword ptr [eax]'),
                0x79CA6F: ('cmp', 'dword ptr [ebp - 0xc], 0'),
                0x79CA73: ('je', '0x79ca96'),
                0x79CA78: ('cmp', 'edx, dword ptr [ebp + 0xc]'),
                0x79CA82: ('mov', 'ecx, dword ptr [eax + 0x80]'),
                0x79CA96: ('mov', 'esi, dword ptr [ebp - 0xc]'),
                0x79CA99: ('mov', 'ecx, 0x20'),
                0x79CA9E: ('mov', 'edi, dword ptr [ebp + 8]'),
                0x79CAA1: ('rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
                0x79CAA3: ('mov', 'eax, dword ptr [ebp + 8]'),
                0x79CAAB: ('ret', '8'),
                0x79CB01: ('je', '0x79cb24'),
                0x79CB06: ('cmp', 'edx, dword ptr [ebp + 8]'),
                0x79CB10: ('mov', 'ecx, dword ptr [eax + 0x80]'),
                0x79CB24: ('mov', 'eax, dword ptr [ebp - 0xc]'),
                0x79CB2A: ('ret', '4'),
            }
            for ea, expected in dependency_anchors.items():
                assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
            counts['dependency_semantic_anchors'] = len(dependency_anchors)
        counts['lossless_adaptations'] = 0
        counts['reference_mechanical_instructions'] = 0
        counts['reference_mechanical_chunks'] = 0
        for filename in ('formal_functions.json', 'formal_dependencies.json', 'reused_functions.json'):
            if not (HERE / filename).exists():
                continue
            adapted = load(HERE / filename)
            assert adapted['disk_sha256'] == SHA
            if filename == 'formal_functions.json':
                assert len(adapted['functions']) == 6
            for row in adapted['functions']:
                path = DOCS / row['source_path']
                original_source = load(path)
                assert hashlib.sha256(path.read_bytes()).hexdigest() == row['source_sha256']
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
                counts['lossless_adaptations'] += 1
                if filename == 'reused_functions.json' and va != '0x73f420':
                    number, chunks_count = decode_record(original)
                    counts['reference_mechanical_instructions'] += number
                    counts['reference_mechanical_chunks'] += chunks_count
        reference_anchors = {
            0x629DD5: ('cmp', 'dword ptr [ebp + 8], 0'),
            0x629DF5: ('cmp', 'dword ptr [ebp + 8], 1'),
            0x629E15: ('cmp', 'dword ptr [ebp + 8], 4'),
            0x629E71: ('mov', 'eax, dword ptr [eax + 0x5e0]'),
            0x629E77: ('imul', 'eax, eax, 0x7c'),
            0x629E7D: ('add', 'eax, dword ptr [ecx + 0x5d8]'),
            0x922574: ('mov', 'ebx, dword ptr [0xa693e4]'),
            0x92257A: ('cmp', 'ebx, -1'), 0x92257F: ('je', '0x922647'),
            0x92264E: ('ret', ''),
            0x7E963F: ('cmp', 'edx, dword ptr [ecx + 4]'),
            0x7E964B: ('imul', 'ecx, ecx, 0x114'),
            0x7E9671: ('mov', 'eax, dword ptr [edx + eax + 0x108]'),
            0x7E967C: ('or', 'eax, 0xffffffff'),
            0x6AAABB: ('mov', 'edx, dword ptr [ecx]'),
            0x6AAAC0: ('cmp', 'dword ptr [ebp - 0x10], 3'),
            0x6AAAC4: ('ja', '0x6aab22'),
            0x6AAB22: ('xor', 'al, al'),
            0x9204C1: ('mov', 'edi, dword ptr [esp + 8]'),
            0x9204C5: ('jmp', '0x920535'),
            0x920535: ('mov', 'ecx, dword ptr [esp + 0xc]'),
            0x920541: ('mov', 'dl, byte ptr [ecx]'),
            0x920548: ('je', '0x9205b0'),
            0x920559: ('mov', 'dword ptr [edi], edx'),
            0x9205B0: ('mov', 'byte ptr [edi], dl'),
            0x9205B2: ('mov', 'eax, dword ptr [esp + 8]'),
            0x9205B7: ('ret', ''),
        }
        if (HERE / 'reused_functions.json').exists():
            for ea, expected in reference_anchors.items():
                assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, hex(ea)
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
        expected = set(SEEDS) | {'0x79a1e0', '0x79ca40', '0x79cad0'}
        assert len(ledger['functions']) == len(expected)
        assert {row['va'] for row in ledger['functions']} == expected
        counts['ledger_functions'] = len(expected)
        counts['ledger_semantic_anchors'] = 0
        for row in ledger['functions']:
            assert row['conclusion'] and row['unknown']
            assert row['status'] == ('部分分析' if row['va'] in ('0x73fc70', '0x73f420') else '完整分析')
            assert row['evidence_refs'] and row['semantic_anchors']
            permitted_sites = set()
            for ref in row['evidence_refs']:
                source = load(HERE / ref['file'])
                entry = pointer(source, ref['pointer'])
                assert entry['va'] == row['va']
                assert row['declared_chunks'] == entry['declared_chunks']
                assert row['instruction_count'] == sum(item['is_code'] for item in entry['normalized_assembly'])
                permitted_sites.update(int(item['site_va'], 16) for item in entry['normalized_assembly'] if item['is_code'])
            for anchor in row['semantic_anchors']:
                ea = int(anchor['va'], 16)
                assert ea in permitted_sites
                ins = decoded[ea]
                text = ins.mnemonic + ' ' + ins.op_str
                assert anchor['tokens'] and all(token in text for token in anchor['tokens'])
                counts['ledger_semantic_anchors'] += 1
        assert len(ledger['owner_windows']) == 7
        for row in ledger['owner_windows']:
            assert row['status'] == '局部窗口分析' and row['conclusion'] and row['unknown']
            ref = row['evidence_ref']
            source = pointer(load(HERE / ref['file']), ref['pointer'])
            assert (row['owner_va'], row['site_va']) == (source['owner_va'], source['site_va'])
            assert row['start_va'] == source['assembly'][0]['site_va']
            last = source['assembly'][-1]
            assert int(row['end_va'], 16) == int(last['site_va'], 16) + last['bytes']['size']
        reused_rows = load(HERE / 'reused_functions.json')['functions'][1:]
        assert len(ledger['historical_contracts']) == len(reused_rows) == 12
        for row, adapted in zip(ledger['historical_contracts'], reused_rows):
            assert row['status'] == '既有局部契约复用'
            assert all(row[key] == adapted[key] for key in ('va', 'source_path', 'source_pointer', 'source_sha256'))
            assert row['instruction_count'] == sum(item['is_code'] for item in adapted['normalized_assembly'])
        assert ledger['summary'] == dict(reviewed_functions=10, complete=8, partial=2,
            owner_windows=7, historical_contracts=12, historical_contract_instructions=counts['reference_mechanical_instructions'])
        counts['ledger_owner_windows'] = 7
        counts['ledger_historical_contracts'] = 12
        author_result = load(HERE / 'validation.json')
        assert author_result['status'] == 'PASS' and author_result['disk_sha256'] == SHA
    for path in TOPIC.glob('*.txt'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    for path in HERE.glob('*.py'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = dict(status='PREPARATION_CHECKED' if args.preparation_only else 'EVIDENCE_CHECKED' if args.evidence_only else 'PASS',
                  disk_sha256=SHA, **counts, source_sha256=hashes,
                  boundary='当前PE与有限原证独核；旧73F420不自动升级完整语义；未调用IDA或运行游戏。')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
