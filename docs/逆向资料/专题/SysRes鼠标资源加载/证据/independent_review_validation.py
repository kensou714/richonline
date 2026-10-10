"""鼠标资源加载独立离线复核；不调用作者程序、IDA或游戏。"""
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
RAW_SHA = 'daf27638a4dab260e7e3c119247001fa9d5a767428b7241d2d4b6e8f09d123ff'
RTC_SHA = 'bb785578339a37508b3bd8b4de00af2e5e8dff47e826fb1ba6f9877bcf133051'
SEEDS = ('0x6bab70', '0x6db9d0')
HISTORICAL = ('0x627760', '0x6278f0', '0x6baac0', '0x6bad80', '0x6bab00',
              '0x629890', '0x629ed0', '0x91f6d0', '0x9206d0', '0x91fbb0')


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
    sections = [struct.unpack_from('<4I', blob, at + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
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
    assert tuple(x['seed_va'] for x in bounded['functions']) == SEEDS and not bounded['reused_seeds']
    core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    hashes[core.relative_to(ROOT).as_posix()] = hashlib.sha256(core.read_bytes()).hexdigest()
    assert hashes[core.relative_to(ROOT).as_posix()] == bounded['exporter_sha256']
    counts['new_functions'] = 2
    counts['new_instructions'] = counts['new_chunks'] = 0
    for row in bounded['functions']:
        current = next(x for x in bounded['current_chunk_audits'] if x['seed_va'] == row['seed_va'])
        assert current['chunk_byte_ranges'] == row['chunk_byte_ranges']
        for chunk in current['chunk_byte_ranges']:
            audit(chunk)
        number, chunks = decode_record(row)
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
        assert ins.mnemonic in ('call', 'jmp')
        target = int(row['target_va'], 16)
        if ins.operands[0].type == X86_OP_IMM:
            assert ins.operands[0].imm == target
        else:
            assert ins.bytes[:2] == b'\xff\x15' and struct.unpack_from('<I', ins.bytes, 2)[0] == target
        for bridge in row['bridges']:
            assert target == int(bridge, 16)
            target = bridges[target]
        assert target == int(row['implementation_va'], 16)
        counts['direct_calls'] += 1
    windows = bounded['explicit_owner_windows'] + [edge['owner_window']
        for edges in bounded['incoming'].values() for edge in edges if 'owner_window' in edge]
    assert [x['site_va'] for x in bounded['explicit_owner_windows']] == ['0x623ced']
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
    assert not bounded['data_windows']
    for row in bounded['strings']:
        raw = audit(row['byte_audit'])
        width, payload = row['unit_width'], bytes.fromhex(row['payload_hex'])
        assert width in (1, 2) and raw == payload + bytes(width)
        assert bytes.fromhex(row['nul_hex']) == bytes(width)
        assert all(payload[i:i + width] != bytes(width) for i in range(0, len(payload), width))
    assert {row['target_va']: bytes.fromhex(row['payload_hex']).decode('ascii') for row in bounded['strings']} == {
        '0xa23bcc': 'SysRes\\04_%02d.ms', '0xa23be0': 'Init Cursor Failed!'}
    for row in bounded['reuse_sources']:
        path = (DOCS / row['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        load(path)
        assert hashes[path.relative_to(ROOT).as_posix()] == row['source_sha256']
    sources = {'bounded_raw.json': bounded}
    counts.update(lossless_adaptations=0, historical_instructions=0, historical_chunks=0, historical_data_items=0)
    mechanical_counts = {row['seed_va']: len(row['assembly']) for row in bounded['functions']}
    for filename, expected in (('formal_functions.json', SEEDS), ('reused_functions.json', HISTORICAL)):
        adapted = load(HERE / filename)
        sources[filename] = adapted
        assert adapted['disk_sha256'] == SHA and tuple(row['va'] for row in adapted['functions']) == expected
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
            normalized_assembly = []
            for item in assembly:
                norm = dict(site_va=item.get('site_va', item.get('va')), text=item['text'],
                            is_code=item.get('is_code', True), original=item)
                if filename == 'reused_functions.json':
                    norm['normalized_item_kind'] = 'data' if item['text'].split()[0].lower() in ('db', 'dw', 'dd', 'dq') else 'code'
                normalized_assembly.append(norm)
            assert row['normalized_assembly'] == normalized_assembly
            declared = original.get('declared_chunks', [dict(start_va=x['start_va'],
                end_va=hex(int(x['start_va'], 16) + x['size']), is_main=x['start_va'] == va) for x in normalized])
            assert row['declared_chunks'] == declared and len(declared) == len(normalized)
            if 'byte_ranges' not in original:
                assert row['byte_ranges'] == chunks
            if filename == 'reused_functions.json':
                number = 0
                covered = []
                for declaration, chunk in zip(declared, normalized):
                    raw = audit(chunk)
                    start = int(chunk['start_va'], 16)
                    end = start + len(raw)
                    assert declaration['start_va'] == chunk['start_va'] and int(declaration['end_va'], 16) == end
                    items = [x for x in normalized_assembly if start <= int(x['site_va'], 16) < end]
                    assert items and int(items[0]['site_va'], 16) == start
                    for i, item in enumerate(items):
                        ea = int(item['site_va'], 16)
                        stop = int(items[i + 1]['site_va'], 16) if i + 1 < len(items) else end
                        payload = disk(ea, stop - ea)
                        assert len(payload) > 0
                        covered.append(item['site_va'])
                        if item['normalized_item_kind'] == 'data' or not item['is_code']:
                            assert va == '0x91fbb0' and ea == 0x91FBBE and payload == b'\xcc'
                            counts['historical_data_items'] += 1
                        else:
                            insns = list(decoder.disasm(payload, ea))
                            assert len(insns) == 1 and insns[0].size == len(payload)
                            decoded[ea] = insns[0]
                            number += 1
                assert covered == [x['site_va'] for x in normalized_assembly]
                mechanical_counts[va] = number
                counts['historical_instructions'] += number
                counts['historical_chunks'] += len(normalized)
            counts['lossless_adaptations'] += 1
    helper = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
    hashes[helper.relative_to(ROOT).as_posix()] = hashlib.sha256(helper.read_bytes()).hexdigest()
    assert sources['formal_functions.json']['adapter_helper_sha256'] == hashes[helper.relative_to(ROOT).as_posix()]
    # 旧调用链单独核机器码；不复用IDA导入槽的内容作为磁盘字节。
    historical_call_count = 0
    for row in sources['reused_functions.json']['functions']:
        for call in row.get('calls', []):
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
            historical_call_count += 1
    counts['historical_call_records'] = historical_call_count
    startup = pointer(load(DOCS / '专题/股票与交易流程/证据/stock_core.json'), '/functions/0')
    call = next(x for x in startup['calls'] if x.get('site_va', x.get('site')) == '0x623ce6')
    assert decoded[0x623CE6].mnemonic == 'call'
    target = decoded[0x623CE6].operands[0].imm
    assert target == int(call.get('target_va', call.get('target')), 16)
    for bridge in call.get('bridges', call.get('thunks', [])):
        assert target == int(bridge, 16)
        payload = disk(target, 5)
        assert payload[0] == 0xE9
        target += 5 + struct.unpack_from('<i', payload, 1)[0]
    assert target == 0x6278F0
    anchors = {
        0x6BAB97: ('mov', 'dword ptr [ebp - 8], ecx'),
        0x6BAB9A: ('call', '0x60554a'), 0x6BAB9F: ('mov', 'ecx, eax'),
        0x6BABA1: ('call', '0x604de8'), 0x6BABA6: ('mov', 'dword ptr [ebp - 0x10], eax'),
        0x6BABAC: ('mov', 'byte ptr [eax], 1'), 0x6BABB2: ('mov', 'byte ptr [ecx + 1], 0'),
        0x6BABB6: ('mov', 'dword ptr [ebp - 0xc], 0'),
        0x6BABCB: ('cmp', 'eax, dword ptr [ebp - 0x10]'), 0x6BABCE: ('jge', '0x6bac77'),
        0x6BABD8: ('push', '0xa23bcc'), 0x6BABDD: ('lea', 'edx, [ebp - 0x94]'),
        0x6BABE4: ('call', '0x60361e'), 0x6BABE9: ('add', 'esp, 0xc'),
        0x6BABEE: ('push', '0x10'), 0x6BABF0: ('push', '0'), 0x6BABF2: ('push', '0'),
        0x6BABF4: ('push', '2'), 0x6BABFD: ('push', '0'),
        0x6BABFF: ('call', 'dword ptr [0xad3f38]'),
        0x6BAC12: ('mov', 'dword ptr [edx + ecx*4 + 0xc], eax'),
        0x6BAC1C: ('cmp', 'dword ptr [ecx + eax*4 + 0xc], 0'),
        0x6BAC21: ('jne', '0x6bac72'), 0x6BAC25: ('push', '0x7f00'),
        0x6BAC2A: ('push', '0'), 0x6BAC2C: ('call', 'dword ptr [0xad3f3c]'),
        0x6BAC3F: ('mov', 'dword ptr [ecx + edx*4 + 0xc], eax'),
        0x6BAC49: ('cmp', 'dword ptr [eax + edx*4 + 0xc], 0'),
        0x6BAC4E: ('jne', '0x6bac72'), 0x6BAC52: ('push', '0'), 0x6BAC54: ('push', '0'),
        0x6BAC56: ('push', '0xa23be0'), 0x6BAC5B: ('call', '0x60c179'),
        0x6BAC61: ('call', 'dword ptr [0xad3f8c]'),
        0x6BAC6E: ('xor', 'eax, eax'), 0x6BAC70: ('jmp', '0x6bacd7'),
        0x6BAC7D: ('mov', 'eax, dword ptr [edx + 0xc]'),
        0x6BAC80: ('mov', 'dword ptr [ecx + 0x19c], eax'),
        0x6BAC92: ('mov', 'dword ptr [ecx + 0x1a4], eax'),
        0x6BAC9E: ('mov', 'eax, dword ptr [edx + 0x10]'),
        0x6BACA1: ('mov', 'dword ptr [ecx + 0x1a0], eax'),
        0x6BACB3: ('mov', 'dword ptr [ecx + 0x1a8], eax'),
        0x6BACBE: ('mov', 'edx, dword ptr [ecx + 0x19c]'),
        0x6BACC5: ('call', 'dword ptr [0xad3f88]'), 0x6BACD2: ('mov', 'eax, 1'),
        0x6BACDA: ('push', 'eax'), 0x6BACDB: ('lea', 'edx, [0x6bad03]'),
        0x6BACE1: ('call', '0x6127bd'), 0x6BACE6: ('pop', 'eax'),
        0x6BACEB: ('call', '0x60849d'), 0x6BAD02: ('ret', ''),
        0x6DB9EE: ('mov', 'dword ptr [ebp - 8], 0'),
        0x6DB9F5: ('mov', 'dword ptr [ebp - 0xc], 0'),
        0x6DBA07: ('cmp', 'dword ptr [ebp - 0xc], 0x64'), 0x6DBA0B: ('jge', '0x6dba31'),
        0x6DBA10: ('mov', 'edx, dword ptr [ecx + 0x3ac00]'),
        0x6DBA19: ('imul', 'eax, eax, 0xc'),
        0x6DBA1C: ('cmp', 'dword ptr [edx + eax + 0x12c4], -1'),
        0x6DBA24: ('je', '0x6dba2f'), 0x6DBA29: ('add', 'ecx, 1'),
        0x6DBA31: ('mov', 'eax, dword ptr [ebp - 8]'), 0x6DBA37: ('ret', ''),
        0x627790: ('cmp', 'dword ptr [0xa766b0], 0'), 0x627799: ('push', '0x99fe8'),
        0x6277E0: ('mov', 'eax, dword ptr [0xa766b0]'),
        0x627920: ('cmp', 'dword ptr [0xa766c0], 0'), 0x627929: ('push', '0x1ac'),
        0x627949: ('call', '0x60046e'), 0x627970: ('mov', 'eax, dword ptr [0xa766c0]'),
        0x6BAACE: ('push', '0x190'), 0x6BAAD3: ('push', '0'),
        0x6BAAD8: ('add', 'eax, 0xc'), 0x6BAADC: ('call', '0x60ffdb'),
        0x6BAD9E: ('cmp', 'eax, dword ptr [edx + ecx*4 + 0xc]'),
        0x6BADA2: ('je', '0x6bade3'), 0x6BADB1: ('mov', 'dword ptr [ecx + 0x19c], edx'),
        0x6BADC4: ('mov', 'dword ptr [eax + 0x1a0], ecx'),
        0x6BADD6: ('call', 'dword ptr [0xad3f88]'), 0x6BADF1: ('ret', '4'),
        0x6BAB2A: ('cmp', 'dword ptr [ebp - 8], 0x64'), 0x6BAB2E: ('jae', '0x6bab59'),
        0x6BAB36: ('cmp', 'dword ptr [edx + ecx*4 + 0xc], 0'),
        0x6BAB4A: ('call', 'dword ptr [0xad3acc]'),
        0x6298A1: ('call', '0x604627'), 0x6298A9: ('and', 'eax, 1'),
        0x6298AC: ('je', '0x6298ba'), 0x6298B2: ('call', '0x604cfd'),
        0x6298BA: ('mov', 'eax, dword ptr [ebp - 4]'), 0x6298CA: ('ret', '4'),
        0x629ED3: ('mov', 'eax, dword ptr [0xa76500]'),
        0x91F6D0: ('jne', '0x91f6d3'), 0x91F6D2: ('ret', ''),
        0x92072D: ('mov', 'dword ptr [ecx + 4], 0x7fffffff'),
        0x92075B: ('call', '0x602ed5'), 0x920789: ('mov', 'byte ptr [eax], 0'),
        0x91FBB0: ('cmp', 'ecx, dword ptr [0xa69330]'),
        0x91FBB6: ('jne', '0x91fbb9'), 0x91FBB8: ('ret', ''),
        0x623CE6: ('call', '0x5ffccb'), 0x623CEB: ('mov', 'ecx, eax'),
        0x623CED: ('call', '0x6062a6'), 0x623CF2: ('test', 'eax, eax'),
        0x623CF4: ('jne', '0x623cfd'), 0x623CF6: ('xor', 'eax, eax'),
    }
    for ea, expected in anchors.items():
        assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, (hex(ea), expected)
    counts['independent_semantic_anchors'] = len(anchors)
    rtc = load(HERE / 'rtc_buffer_raw.json')
    assert hashes[(HERE / 'rtc_buffer_raw.json').relative_to(ROOT).as_posix()] == RTC_SHA
    assert rtc['disk_sha256'] == SHA
    assert hashlib.sha256((HERE / 'export_rtc_buffer.py').read_bytes()).hexdigest() == rtc['exporter_sha256']
    assert rtc['frame_descriptor']['start_va'] == '0x6bad03'
    frame_count, vars_va = struct.unpack('<II', audit(rtc['frame_descriptor']))
    assert frame_count == rtc['declared_variable_count'] == 1 and vars_va == 0x6BAD0B
    assert rtc['variable_descriptor']['start_va'] == hex(vars_va)
    frame_offset, capacity, name_va = struct.unpack('<iII', audit(rtc['variable_descriptor']))
    assert frame_offset == rtc['ebp_relative_offset'] == -148
    assert capacity == rtc['declared_buffer_size'] == 128 and name_va == 0x6BAD17
    assert rtc['variable_name']['start_va'] == hex(name_va) and audit(rtc['variable_name']) == b'szTmp\0'
    assert decoded[0x6BACDB].operands[1].mem.disp == 0x6BAD03
    assert decoded[0x6BABDD].operands[1].mem.disp == frame_offset
    counts['rtc_metadata_records'] = 3
    counts['rtc_metadata_bytes'] = 26

    def cstring(ea):
        result = bytearray()
        for i in range(512):
            value = disk(ea + i, 1)[0]
            if not value:
                return result.decode('ascii')
            result.append(value)
        raise AssertionError('导入名称未终止')

    imports = {}
    import_rva, import_size = struct.unpack_from('<II', blob, pe + 24 + 104)
    for offset in range(0, import_size, 20):
        original, stamp, chain, name, first = struct.unpack('<5I', disk(base + import_rva + offset, 20))
        if not (original or stamp or chain or name or first):
            break
        dll = cstring(base + name)
        index = 0
        while True:
            value = struct.unpack('<I', disk(base + (original or first) + index * 4, 4))[0]
            if not value:
                break
            symbol = '#' + str(value & 0xFFFF) if value & 0x80000000 else cstring(base + value + 2)
            imports[base + first + index * 4] = dll + '!' + symbol
            index += 1
    expected_imports = {0xAD3F38: 'USER32.dll!LoadImageA', 0xAD3F3C: 'USER32.dll!LoadCursorA',
        0xAD3F88: 'USER32.dll!SetCursor', 0xAD3F8C: 'USER32.dll!MessageBoxA', 0xAD3ACC: 'GDI32.dll!DeleteObject'}
    assert all(imports[ea].lower() == value.lower() for ea, value in expected_imports.items())
    selected_imports = [dict(va=hex(ea), name=imports[ea], disk_slot_hex=disk(ea, 4).hex()) for ea in expected_imports]
    resources = []
    resource_paths = sorted((ROOT / 'SysRes').glob('04_*.ms'))
    assert [path.name for path in resource_paths] == [f'04_{i:02d}.ms' for i in range(39)]
    for path in resource_paths:
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        reserved, kind, entries = struct.unpack_from('<HHH', raw)
        assert (reserved, kind, entries) == (0, 2, 1)
        width, height, colors, zero, hot_x, hot_y, size, offset = struct.unpack_from('<BBBBHHII', raw, 6)
        assert zero == 0 and (width, height, colors, hot_x, hot_y) == (32, 32, 0, 1, 1)
        assert offset == 22 and offset + size == len(raw) == 2238
        header, dib_width, dib_height, planes, bits, compression, image_size, xppm, yppm, used, important = struct.unpack_from('<IiiHHIIiiII', raw, offset)
        assert (header, dib_width, dib_height, planes, bits, compression) == (40, 32, 64, 1, 8, 0)
        palette_count = used if used else 1 << bits
        xor_size = ((dib_width * bits + 31) // 32) * 4 * height
        and_size = ((dib_width + 31) // 32) * 4 * height
        assert header + palette_count * 4 + xor_size + and_size == size
        assert palette_count == 256 and image_size == xor_size == 1024 and and_size == 128
        resources.append(dict(path=path.relative_to(ROOT).as_posix(), sha256=digest, size=len(raw),
            header_hex=raw[:22].hex(), directory_type=kind, entries=entries, width=width, height=height,
            hot_x=hot_x, hot_y=hot_y, dib_bits=bits, palette_entries=palette_count,
            image_offset=offset, image_bytes=size, xor_bytes=xor_size, and_bytes=and_size))
        hashes[path.relative_to(ROOT).as_posix()] = digest
    author_resources = load(HERE / 'resource_audit.json')
    assert author_resources['status'] == 'PASS' and author_resources['disk_sha256'] == SHA
    assert author_resources['resource_count'] == len(author_resources['resources']) == 39
    for author, independent in zip(author_resources['resources'], resources):
        assert all(author[key] == independent[key] for key in ('path', 'sha256', 'size', 'header_hex'))
        assert author['cursor_type'] == 2 and author['filename_index'] == int(Path(author['path']).stem[3:])
        assert author['entries'] == [dict(width=32, height=32, hotspot=[1, 1], resource_size=2216,
            resource_offset=22, dib_header_size=40, dib_height=64, bits_per_pixel=8, compression=0,
            palette_entries=256, xor_bytes=1024, and_bytes=128)]
    assert len(author_resources['imports']) == 5
    for entry in author_resources['imports']:
        ea = int(entry['iat_va'], 16)
        assert imports[ea] == entry['dll'] + '!' + entry['symbol']
        assert disk(ea, 4).hex() == entry['disk_iat_hex']
        lookup = struct.unpack('<I', disk(base + int(entry['lookup_rva'], 16), 4))[0]
        assert lookup + 2 == int(entry['name_rva'], 16)
        descriptor = struct.unpack('<5I', disk(base + int(entry['descriptor_rva'], 16), 20))
        assert cstring(base + descriptor[3]) == entry['dll']
    assert counts['byte_records'] == 63 and counts['new_instructions'] == 150
    assert counts['historical_instructions'] == 333 and counts['historical_data_items'] == 1
    assert counts['lossless_adaptations'] == 12 and counts['owner_items'] == 33
    ledger = load(TOPIC / '函数审阅清单.json')
    assert ledger['disk_sha256'] == SHA
    assert tuple(row['va'] for row in ledger['functions']) == SEEDS
    assert tuple(row['va'] for row in ledger['historical_contracts']) == HISTORICAL
    counts['ledger_semantic_anchors'] = 0
    for historical, rows in ((False, ledger['functions']), (True, ledger['historical_contracts'])):
        for row in rows:
            assert row['status'] == ('既有窄契约复用' if historical else '完整局部分析')
            assert row['conclusion'] and row['unknown']
            ref = row['evidence_ref']
            source = pointer(sources[ref['file']], ref['pointer'])
            assert all(row[key] == source[key] for key in ('va', 'source_path', 'source_pointer', 'source_sha256', 'declared_chunks'))
            assert row['mechanical_instructions'] == mechanical_counts[row['va']]
            for anchor in row['semantic_anchors']:
                ea = int(anchor['va'], 16)
                ins = decoded[ea]
                assert any(int(c['start_va'], 16) <= ea < int(c['end_va'], 16) for c in source['declared_chunks'])
                assert all(token in ins.mnemonic + ' ' + ins.op_str for token in anchor['tokens'])
                counts['ledger_semantic_anchors'] += 1
    assert counts['ledger_semantic_anchors'] == 73
    assert ledger['summary'] == dict(new_bodies=2, new_instructions=150, historical_records=10,
        historical_mechanical_instructions=333, explicit_owner_windows=1, direct_bridges=8)
    assert len(ledger['owner_windows']) == 1
    window = ledger['owner_windows'][0]
    original = pointer(sources[window['evidence_ref']['file']], window['evidence_ref']['pointer'])
    assert window['owner_va'] == original['owner_va'] and window['site_va'] == original['site_va']
    assert window['status'] == '局部窗口分析' and window['conclusion'] and window['unknown']
    # 退出语义仅选旧原证的三条指令，不新增整个624080机械或语义覆盖。
    shutdown = pointer(load(DOCS / '专题/事件文字记录器/证据/shutdown.json'), '/functions/0')
    assert shutdown['va'] == '0x624080'
    exit_anchors = {0x624A14: ('push', '1'), 0x624A1C: ('call', '0x60def7'),
                    0x624A33: ('mov', 'dword ptr [0xa766c0], 0')}
    assembly = shutdown['assembly']
    for ea, expected in exit_anchors.items():
        index = next(i for i, item in enumerate(assembly) if int(item['va'], 16) == ea)
        stop = int(assembly[index + 1]['va'], 16)
        chunk = next(c for c in shutdown['chunk_byte_ranges'] if int(c['va'], 16) <= ea < int(c['va'], 16) + c['size'])
        offset = ea - int(chunk['va'], 16)
        payload = disk(ea, stop - ea)
        assert payload == bytes.fromhex(chunk['disk_hex'])[offset:offset + len(payload)]
        assert payload == bytes.fromhex(chunk['idb_hex'])[offset:offset + len(payload)]
        ins = list(decoder.disasm(payload, ea))
        assert len(ins) == 1 and ins[0].size == len(payload)
        assert (ins[0].mnemonic, ins[0].op_str) == expected
    wrapper = disk(0x60DEF7, 5)
    assert wrapper[0] == 0xE9 and 0x60DEFC + struct.unpack_from('<i', wrapper, 1)[0] == 0x629890
    counts['historical_exit_window_instructions'] = len(exit_anchors)
    author_validation = load(HERE / 'validation.json')
    assert author_validation['status'] == 'PASS' and author_validation['disk_sha256'] == SHA
    for filename, digest in author_validation['source_sha256'].items():
        assert hashlib.sha256((HERE / filename).read_bytes()).hexdigest() == digest
    assert all(author_validation[key] == value for key, value in dict(byte_records=63, owner_items=33,
        data_items=1, adapted_records=12, mechanical_instructions=483, semantic_anchors=73,
        resource_files=39, imports=5).items())
    if args.show:
        start, end = (int(value, 16) for value in args.show)
        for ea, ins in sorted(decoded.items()):
            if start <= ea < end:
                print(f'{ea:08X} {ins.mnemonic:8} {ins.op_str}')
        return
    if not args.evidence_only:
        report = (TOPIC / '独立审阅.txt').read_text('utf-8')
        assert '// 终审结论：PASS。' in report and SHA in report and RAW_SHA in report and RTC_SHA in report
    for path in list(TOPIC.glob('*.txt')) + list(HERE.glob('*.txt')) + list(HERE.glob('*.py')):
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.suffix == '.txt':
            assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status='EVIDENCE_CHECKED' if args.evidence_only else 'PASS', disk_sha256=SHA, **counts,
        strict_strings=len(bounded['strings']), rejected_strings=len(bounded['rejected_string_candidates']),
        imports=selected_imports, resources=resources, mechanical_counts=mechanical_counts, source_sha256=hashes,
        boundary='两新本体150完整局部指令；历史333机械指令、退出3条旧局部指令另计；39资源结构、RTC128B及5PE导入独立核验。未运行API或客户端，不认整个owner及特殊诊断路径闭合。')
    (HERE / 'independent_review_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('source_sha256', 'resources')}, ensure_ascii=True))


if __name__ == '__main__':
    main()
