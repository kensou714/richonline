"""股票数值专题独立离线核验；不调用作者程序、IDA或游戏。"""
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
RAW_SHA = 'f3eaa46e1dbb7b7549a9c0779e65387ce4fee25a93a1baddc238ec44c0aa4c04'
SEEDS = ('0x6c1c80', '0x6c1d00', '0x6c1d80', '0x6c08b0', '0x6c0960', '0x6c0bf0', '0x6c0ce0')


def main():
    parser = argparse.ArgumentParser()
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
    decoded, hashes, counts = {}, {}, {'byte_records': 0}

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
        counts['byte_records'] += 1
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

    bounded = load(HERE / 'bounded_raw.json')
    assert hashes[(HERE / 'bounded_raw.json').relative_to(ROOT).as_posix()] == RAW_SHA
    assert bounded['disk_sha256'] == SHA and tuple(x['seed_va'] for x in bounded['seeds']) == SEEDS
    core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    assert hashlib.sha256(core.read_bytes()).hexdigest() == bounded['exporter_sha256']
    hashes[core.relative_to(ROOT).as_posix()] = hashlib.sha256(core.read_bytes()).hexdigest()
    assert [x['seed_va'] for x in bounded['functions']] == list(SEEDS)
    assert not bounded['reused_seeds'] and len(bounded['current_chunk_audits']) == len(SEEDS)
    counts.update(new_functions=7, new_chunks=0, new_instructions=0)
    for row in bounded['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']:
            audit(chunk)
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
    assert [x['site_va'] for x in bounded['explicit_owner_windows']] == ['0x77ef93', '0x77efd3', '0x77efe4']
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
    assert not bounded['strings'] and not bounded['data_windows'] and not bounded['data_references']
    for row in bounded['reuse_sources']:
        path = (DOCS / row['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        load(path)
        assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
    root_source = load(DOCS / '专题/股票与交易流程/证据/stock_core.json')
    root = pointer(root_source, '/functions/2')
    assert root['va'] == '0x6283e0'
    counts['historical_root_instructions'], counts['historical_root_chunks'] = decode_record(root)
    conversion_source = load(DOCS / '专题/高扇入界面操作辅助/证据/dependency_raw.json')
    conversion = pointer(conversion_source, '/functions/2')
    assert conversion['va'] == '0x922798' and conversion_source['disk_sha256'] == SHA
    counts['conversion_instructions'], counts['conversion_chunks'] = decode_record(conversion)
    if args.show:
        start, end = (int(value, 16) for value in args.show)
        for ea, ins in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X} {ins.mnemonic:8} {ins.op_str}')
        return
    assert counts['byte_records'] == 642 and counts['owner_items'] == 616
    assert counts['new_instructions'] == 366 and counts['new_chunks'] == 7
    assert counts['historical_root_instructions'] == 39 and counts['conversion_instructions'] == 37
    assert len(bridges) == 10 and counts['direct_calls'] == 34
    sources = {'bounded_raw.json': bounded}
    for filename, expected in (('formal_functions.json', SEEDS),
                               ('reused_functions.json', ('0x6283e0', '0x922798'))):
        adapted = load(HERE / filename)
        sources[filename] = adapted
        assert adapted['disk_sha256'] == SHA
        assert tuple(row['va'] for row in adapted['functions']) == expected
        for row in adapted['functions']:
            source_path = (DOCS / row['source_path']).resolve()
            assert source_path.is_relative_to(DOCS.resolve())
            source = load(source_path)
            assert hashes[source_path.relative_to(ROOT).as_posix()] == row['source_sha256']
            original = pointer(source, row['source_pointer'])
            assert all(row[key] == value for key, value in original.items())
            assert row['source_field_pointers'] == {key: row['source_pointer'] + '/' + key for key in original}
            assert all(pointer(source, ptr) == row[key] for key, ptr in row['source_field_pointers'].items())
            va = original.get('seed_va', original.get('va'))
            assert row['va'] == va
            chunks = original.get('chunk_byte_ranges', original.get('chunks', original.get('byte_ranges')))
            normalized = [dict(start_va=x.get('start_va', x.get('va')),
                **{key: value for key, value in x.items() if key not in ('start_va', 'va', 'address')}) for x in chunks]
            assert row['normalized_chunks'] == normalized
            assembly = original.get('assembly', original.get('instructions'))
            assert row['normalized_assembly'] == [dict(site_va=x.get('site_va', x.get('va')),
                text=x['text'], is_code=x.get('is_code', True), original=x) for x in assembly]
            declared = original.get('declared_chunks', [dict(start_va=x['start_va'],
                end_va=hex(int(x['start_va'], 16) + x['size']), is_main=x['start_va'] == va) for x in normalized])
            assert row['declared_chunks'] == declared
            if 'byte_ranges' not in original:
                assert row['byte_ranges'] == chunks
            for call in original.get('calls', []):
                site = int(call.get('site_va', call.get('site')), 16)
                target = int(call.get('target_va', call.get('target')), 16)
                ins = decoded[site]
                assert ins.mnemonic in ('call', 'jmp')
                if ins.operands[0].type == X86_OP_IMM:
                    assert ins.operands[0].imm == target
                else:
                    assert ins.bytes[:2] == b'\xff\x15' and struct.unpack_from('<I', ins.bytes, 2)[0] == target
                for bridge in call.get('bridges', call.get('thunks', [])):
                    assert target == int(bridge, 16)
                    payload = disk(target, 5)
                    assert payload[0] == 0xE9
                    target += 5 + struct.unpack_from('<i', payload, 1)[0]
                assert target == int(call.get('implementation_va', call.get('implementation')), 16)
            counts['lossless_adaptations'] = counts.get('lossless_adaptations', 0) + 1
    helper = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
    assert sources['formal_functions.json']['adapter_helper_sha256'] == hashlib.sha256(helper.read_bytes()).hexdigest()
    hashes[helper.relative_to(ROOT).as_posix()] = hashlib.sha256(helper.read_bytes()).hexdigest()
    anchors = {
        0x6C1D91: ('mov', 'eax, dword ptr [eax + 0x34c]'),
        0x6C1D9A: ('ret', '4'),
        0x6C08CD: ('call', '0x60fd8d'),
        0x6C08DB: ('mov', 'edx, dword ptr [eax + 0x1c]'),
        0x6C08DE: ('imul', 'edx, dword ptr [ecx + 0x10]'),
        0x6C08EB: ('mov', 'edx, dword ptr [eax + 0x1c]'),
        0x6C08EE: ('imul', 'edx, dword ptr [ecx + 0x10]'),
        0x6C090F: ('add', 'esi, eax'), 0x6C091D: ('add', 'esi, eax'),
        0x6C0939: ('add', 'edi, eax'), 0x6C0947: ('add', 'edi, eax'),
        0x6C0949: ('cmp', 'esi, edi'), 0x6C094B: ('sbb', 'eax, eax'),
        0x6C094D: ('neg', 'eax'), 0x6C095E: ('ret', ''),
        0x6C097D: ('call', '0x60fd8d'),
        0x6C098E: ('imul', 'edx, dword ptr [ecx + 0x10]'),
        0x6C099E: ('imul', 'edx, dword ptr [ecx + 0x10]'),
        0x6C09F9: ('cmp', 'edi, esi'), 0x6C09FB: ('sbb', 'eax, eax'),
        0x6C09FD: ('neg', 'eax'), 0x6C0A0E: ('ret', ''),
        0x628410: ('cmp', 'dword ptr [0xa76744], 0'),
        0x628417: ('jne', '0x628460'), 0x628419: ('push', '0xca0'),
        0x628434: ('je', '0x628443'), 0x628439: ('call', '0x6125bf'),
        0x628443: ('mov', 'dword ptr [ebp - 0x18], 0'),
        0x62845A: ('mov', 'dword ptr [0xa76744], ecx'),
        0x628460: ('mov', 'eax, dword ptr [0xa76744]'),
        0x9227A1: ('fld', 'st(0)'), 0x9227A3: ('fst', 'dword ptr [esp + 0x18]'),
        0x9227A7: ('fistp', 'qword ptr [esp + 0x10]'),
        0x9227AB: ('fild', 'qword ptr [esp + 0x10]'),
        0x9227B9: ('je', '0x9227f7'), 0x9227BB: ('fsubp', 'st(1)'),
        0x9227BF: ('jns', '0x9227df'), 0x9227C7: ('xor', 'ecx, 0x80000000'),
        0x9227CD: ('add', 'ecx, 0x7fffffff'), 0x9227D3: ('adc', 'eax, 0'),
        0x9227DA: ('adc', 'edx, 0'), 0x9227E5: ('add', 'ecx, 0x7fffffff'),
        0x9227EB: ('sbb', 'eax, 0'), 0x9227F2: ('sbb', 'edx, 0'),
        0x9227FB: ('test', 'edx, 0x7fffffff'), 0x922801: ('jne', '0x9227bb'),
        0x922803: ('fstp', 'dword ptr [esp + 0x18]'),
        0x922807: ('fstp', 'dword ptr [esp + 0x18]'), 0x92280C: ('ret', ''),
        0x77EF8C: ('mov', 'edx, dword ptr [ecx + 0x4c]'),
        0x77EF93: ('call', '0x6070f7'),
        0x77EFBF: ('imul', 'edx, dword ptr [ecx + 0x54]'),
        0x77EFC3: ('mov', 'dword ptr [ebp - 0x9c], edx'),
        0x77EFD0: ('mov', 'ecx, dword ptr [ebp - 0x10]'),
        0x77EFD3: ('call', '0x610468'), 0x77EFE4: ('call', '0x60d263'),
        0x77EFE9: ('add', 'esi, eax'), 0x77EFF5: ('call', '0x605ce3'),
        0x77EFFA: ('add', 'esi, eax'), 0x77EFFD: ('push', '0xa2b094'),
    }
    for base_va, coefficient, threshold in ((0x6C1C80, 0x33C, 0x340), (0x6C1D00, 0x344, 0x348)):
        for offset, expected in {
            0x20: ('mov', 'eax, dword ptr [ebp + 8]'), 0x23: ('xor', 'edx, edx'),
            0x25: ('mov', 'ecx, 0x64'), 0x2A: ('div', 'ecx'),
            0x2F: ('mov', 'dword ptr [ebp - 0xc], 0'),
            0x36: ('fild', 'qword ptr [ebp - 0x10]'),
            0x39: ('fstp', 'dword ptr [ebp - 0x14]'),
            0x3F: ('fld', 'dword ptr [ebp - 0x14]'),
            0x42: ('fmul', f'dword ptr [edx + {hex(coefficient)}]'),
            0x48: ('call', '0x60c4c6'), 0x4D: ('mov', 'dword ptr [ebp - 8], eax'),
            0x56: ('cmp', f'ecx, dword ptr [eax + {hex(threshold)}]'),
            0x5C: ('jbe', hex(base_va + 0x66)), 0x78: ('ret', '4'),
        }.items():
            anchors[base_va + offset] = expected
    for base_va, reverse in ((0x6C0BF0, False), (0x6C0CE0, True)):
        for offset, expected in {
            0x1B: ('call', '0x60fd8d'),
            0x29: ('mov', 'edx, dword ptr [eax + 0xc]'),
            0x2C: ('imul', 'edx, dword ptr [ecx + 8]'),
            0x3C: ('imul', 'edx, dword ptr [ecx + 8]'),
            0x84: ('cmp', 'dword ptr [ecx + 4], 1'),
            0x88: ('je', hex(base_va + 0x93)),
            0x8D: ('cmp', 'dword ptr [edx + 4], 2'),
            0x91: ('jne', hex(base_va + 0xA5)),
            0x9A: ('call', '0x605ce3'),
            0xA8: ('cmp', 'dword ptr [ecx + 4], 1'),
            0xAC: ('je', hex(base_va + 0xB7)),
            0xB1: ('cmp', 'dword ptr [edx + 4], 2'),
            0xB5: ('jne', hex(base_va + 0xC9)),
            0xBE: ('call', '0x605ce3'),
            0xCC: ('cmp', 'dword ptr [ebp - 0x14], ecx' if reverse else 'ecx, dword ptr [ebp - 0x14]'),
            0xCF: ('sbb', 'eax, eax'), 0xD1: ('neg', 'eax'), 0xE1: ('ret', ''),
        }.items():
            anchors[base_va + offset] = expected
    for ea, expected in anchors.items():
        assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, (hex(ea), expected)
    counts['independent_semantic_anchors'] = len(anchors)
    ledger = load(TOPIC / '函数审阅清单.json')
    assert ledger['disk_sha256'] == SHA and tuple(x['va'] for x in ledger['functions']) == SEEDS
    assert tuple(x['va'] for x in ledger['historical_contracts']) == ('0x6283e0', '0x922798')
    counts['ledger_semantic_anchors'] = 0
    for historical, rows in ((False, ledger['functions']), (True, ledger['historical_contracts'])):
        for row in rows:
            assert row['status'] == ('既有局部契约复用' if historical else '完整分析')
            refs = [row['evidence_ref']] if historical else row['evidence_refs']
            assert len(refs) == 1
            ref = refs[0]
            original = pointer(sources[ref['file']], ref['pointer'])
            assert row['va'] == original['va']
            assert row['instruction_count'] == sum(x['is_code'] for x in original['normalized_assembly'])
            if historical:
                assert all(row[key] == original[key] for key in ('source_path', 'source_pointer', 'source_sha256'))
            else:
                assert row['declared_chunks'] == original['declared_chunks'] and row['conclusion'] and row['unknown']
            for anchor in row['semantic_anchors']:
                ins = decoded[int(anchor['va'], 16)]
                assert all(token in ins.mnemonic + ' ' + ins.op_str for token in anchor['tokens'])
                assert any(int(c['start_va'], 16) <= ins.address < int(c['end_va'], 16) for c in original['declared_chunks'])
                counts['ledger_semantic_anchors'] += 1
    assert counts['ledger_semantic_anchors'] == 48
    assert ledger['summary'] == dict(reviewed_functions=7, complete=7, partial=0, new_seed_bodies=7,
        reviewed_instructions=366, historical_contracts=2, historical_contract_instructions=76,
        owner_windows=3, direct_bridges=10)
    assert len(ledger['owner_windows']) == 3
    for row in ledger['owner_windows']:
        ref = row['evidence_ref']
        original = pointer(sources[ref['file']], ref['pointer'])
        assert row['status'] == '局部窗口分析' and row['unknown']
        assert row['owner_va'] == original['owner_va'] and row['site_va'] == original['site_va']
        items = original['assembly']
        assert row['start_va'] == items[0]['site_va']
        assert int(row['end_va'], 16) == int(items[-1]['site_va'], 16) + items[-1]['bytes']['size']
    author_validation = load(HERE / 'validation.json')
    assert author_validation['status'] == 'PASS' and author_validation['disk_sha256'] == SHA
    for filename, digest in author_validation['source_sha256'].items():
        assert hashlib.sha256((HERE / filename).read_bytes()).hexdigest() == digest
    assert all(author_validation[key] == value for key, value in dict(byte_records=642, owner_items=616,
        functions=9, decoded_instructions=442, semantic_anchors=48).items())
    if not args.evidence_only:
        report = (TOPIC / '独立审阅.txt').read_text('utf-8')
        assert '// 终审结论：PASS。' in report
        assert SHA in report and RAW_SHA in report
    for path in list(TOPIC.glob('*.txt')) + list(HERE.glob('*.txt')):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    for path in HERE.glob('*.py'):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = dict(status='EVIDENCE_CHECKED' if args.evidence_only else 'PASS', disk_sha256=SHA,
                  **counts, source_sha256=hashes,
                  boundary='七新本体完整局部审阅366指令；历史根与转换76指令分列；616有限窗口项不认整个owner。特殊FPU、字段producer及真实用户触发未实测；不调用作者程序、IDA或游戏。')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
