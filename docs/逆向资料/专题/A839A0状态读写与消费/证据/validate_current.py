"""作者离线核验；按 IDA code/data 边界解码，避免把函数范围中的数据当指令。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def pointer(value, path):
    for key in path.strip('/').split('/'):
        key = key.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, at + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    sources, hashes, maps, transcript, counts = {}, {}, {}, [], dict(byte_records=0, virtual_records=0, owner_items=0)

    def disk(va, size):
        hits = [(rva, off) for _, rva, raw, off in sections if base + rva <= va and va + size <= base + rva + raw]
        assert len(hits) <= 1
        if not hits:
            return None
        rva, off = hits[0]
        return blob[off + va - base - rva:off + va - base - rva + size]

    def audit(row, address=None):
        va = int(row.get('start_va', row.get('va')), 16) if address is None else address
        raw = disk(va, row['size'])
        if row['disk_hex'] is None:
            assert raw is None and row['matching'] is None
            assert sum(base + rva <= va and va + row['size'] <= base + rva + virtual for virtual, rva, _, _ in sections) == 1
            counts['virtual_records'] += 1
            return None
        assert raw is not None and raw.hex() == row['disk_hex'].lower()
        if 'idb_hex' in row:
            assert raw.hex() == row['idb_hex'].lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        counts['byte_records'] += 1
        return raw

    def load(filename):
        raw = (HERE / filename).read_bytes()
        hashes[filename] = hashlib.sha256(raw).hexdigest()
        value = json.loads(raw)
        assert value['disk_sha256'] == SHA
        sources[filename] = value
        return value

    bounded = load('bounded_raw.json')
    formal = load('formal_functions.json')
    reused = load('reused_functions.json')
    dependency = load('case60_dependency_raw.json')
    supplement = load('navigation_supplement/bounded_raw.json')
    table = load('case60_table/bounded_raw.json')
    contracts = load('historical_contracts.json')
    for row in contracts['contracts']:
        raw = (DOCS / row['source_path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row['source_sha256']
        assert pointer(json.loads(raw), row['source_pointer']) == row['source_record']
        for chunk in row['chunk_byte_ranges']:
            raw_chunk = audit(chunk)
            instructions = list(decoder.disasm(raw_chunk, int(chunk['start_va'], 16)))
            if not row['windows']:
                assert sum(ins.size for ins in instructions) == len(raw_chunk)
            transcript.append('// 历史局部契约 ' + row['va'] + ' / ' + row['source_path'] + '#' + row['source_pointer'])
            for ins in instructions:
                if not row['windows'] or any(int(window['start_va'], 16) <= ins.address < int(window['end_va'], 16) for window in row['windows']):
                    transcript.append('// ' + hex(ins.address) + ' ' + ins.mnemonic + ' ' + ins.op_str)
    for row in dependency['functions']:
        decoded = {}
        transcript.append('// 补充函数 ' + row['va'] + ' / case60_dependency_raw.json')
        for chunk in row['chunk_byte_ranges']:
            raw = audit(chunk)
            va = int(chunk.get('start_va', chunk.get('va')), 16)
            instructions = list(decoder.disasm(raw, va))
            assert sum(ins.size for ins in instructions) == len(raw)
            for ins in instructions:
                decoded[ins.address] = dict(text=ins.mnemonic + ' ' + ins.op_str, bytes_hex=ins.bytes.hex(), size=ins.size)
                transcript.append('// ' + hex(ins.address) + ' ' + decoded[ins.address]['text'])
        assert {int(item['va'], 16) for item in row['assembly']} == set(decoded)
        maps[int(row['va'], 16)] = decoded
    assert formal['source_sha256'] == hashes['bounded_raw.json']
    for i, row in enumerate(formal['functions']):
        original = bounded['functions'][i]
        assert row['source_pointer'] == '/functions/' + str(i) and row['va'] == original['seed_va']
        for key, value in original.items():
            assert row[key] == value and pointer(bounded, row['source_field_pointers'][key]) == value
        assert row['byte_ranges'] == original['chunk_byte_ranges']
    for row in reused['functions']:
        raw = (DOCS / row['source_path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row['source_sha256']
        original = pointer(json.loads(raw), row['source_pointer'])
        for key, value in original.items():
            assert row[key] == value and pointer(json.loads(raw), row['source_field_pointers'][key]) == value
    for filename, value in [('formal_functions.json', formal), ('reused_functions.json', reused)]:
        for row in value['functions']:
            decoded = {}
            transcript.append('// 函数 ' + row['va'] + ' / ' + filename)
            for chunk in row['chunk_byte_ranges']:
                raw = audit(chunk)
                start, stop = int(chunk['start_va'], 16), int(chunk['start_va'], 16) + chunk['size']
                items = [item for item in row['assembly'] if start <= int(item['site_va'], 16) < stop]
                assert items and int(items[0]['site_va'], 16) == start
                for i, item in enumerate(items):
                    va = int(item['site_va'], 16)
                    end = int(items[i + 1]['site_va'], 16) if i + 1 < len(items) else stop
                    payload = disk(va, end - va)
                    if item['is_code']:
                        instructions = list(decoder.disasm(payload, va))
                        assert len(instructions) == 1 and instructions[0].size == len(payload)
                        ins = instructions[0]
                        decoded[va] = dict(text=ins.mnemonic + ' ' + ins.op_str, bytes_hex=ins.bytes.hex(), size=ins.size)
                        if 'bytes_hex' in item:
                            assert item['bytes_hex'] == ins.bytes.hex() and item['size'] == ins.size
                        transcript.append('// ' + hex(va) + ' ' + decoded[va]['text'])
                    else:
                        transcript.append('// ' + hex(va) + ' 静态数据 ' + payload.hex())
                assert row['declared_chunks'][row['chunk_byte_ranges'].index(chunk)] == dict(start_va=chunk['start_va'], end_va=hex(stop), is_main=chunk['start_va'] == row['va'])
            maps[int(row['va'], 16)] = decoded
    for row in bounded['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']:
            audit(chunk)
    bridges = {}
    for row in bounded['verified_direct_bridges']:
        raw = audit(row)
        va = int(row['start_va'], 16)
        assert raw[0] == 0xe9 and row['size'] == 5
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == int(row['target_va'], 16)
        bridges[va] = target
    for row in bounded['calls']:
        va = int(row['site_va'], 16)
        ins = next(decoder.disasm(disk(va, 16), va, count=1))
        target = int(row['target_va'], 16)
        if ins.bytes[:2] == b'\xff\x15':
            assert struct.unpack_from('<I', ins.bytes, 2)[0] == target
        else:
            assert ins.bytes[0] in (0xe8, 0xe9) and va + 5 + struct.unpack_from('<i', ins.bytes, 1)[0] == target
        for bridge in row['bridges']:
            assert target == int(bridge, 16)
            target = bridges[target]
        assert target == int(row['implementation_va'], 16)
    windows = bounded['explicit_owner_windows'] + supplement['explicit_owner_windows'] + [edge['owner_window'] for rows in bounded['incoming'].values() for edge in rows if 'owner_window' in edge]
    for window in windows:
        if window['owner_va'] is None:
            assert not window['assembly']
            continue
        transcript.append('// 局部窗口 owner=' + window['owner_va'] + ' site=' + window['site_va'])
        previous = None
        for item in window['assembly']:
            va = int(item['site_va'], 16)
            raw = audit(item['bytes'], va)
            assert previous is None or previous == va
            previous = va + len(raw)
            if item['is_code']:
                instructions = list(decoder.disasm(raw, va))
                assert len(instructions) == 1 and instructions[0].size == len(raw)
                transcript.append('// ' + hex(va) + ' ' + instructions[0].mnemonic + ' ' + instructions[0].op_str)
            else:
                transcript.append('// ' + hex(va) + ' 静态数据 ' + raw.hex())
            counts['owner_items'] += 1
    for row in bounded['data_windows'] + supplement['data_windows'] + table['data_windows']:
        audit(row)
    assert struct.unpack('<4I', bytes.fromhex(supplement['data_windows'][0]['disk_hex'])) == (0x7680e2, 0x7681ef, 0x7682f3, 0x768399)
    assert struct.unpack_from('<I', bytes.fromhex(supplement['data_windows'][1]['disk_hex']), 16)[0] == 0x60058b
    table_data = {int(row['start_va'], 16): bytes.fromhex(row['disk_hex']) for row in table['data_windows']}
    assert table_data[0x82a391] == bytes([0x2b])
    assert 0x82a295 + 0x2b * 4 == 0x82a341
    assert struct.unpack('<I', table_data[0x82a341])[0] == 0x82a1f2
    for row in bounded['strings']:
        raw = audit(row['byte_audit'])
        width = row['unit_width']
        payload = bytes.fromhex(row['payload_hex'])
        assert width in (1, 2) and row['ida_string_type'] == (0 if width == 1 else 1)
        assert raw == payload + bytes(width) and bytes.fromhex(row['nul_hex']) == bytes(width)
        assert len(payload) % width == 0
        assert all(payload[index:index + width] != bytes(width) for index in range(0, len(payload), width))
    for row in bounded['reuse_sources']:
        assert hashlib.sha256((DOCS / row['path']).read_bytes()).hexdigest() == row['source_sha256']
    (HERE / 'review_assembly.txt').write_text('\n'.join(transcript) + '\n', 'utf-8')
    anchors = 0
    ledger_path = HERE.parent / '函数审阅清单.json'
    status = 'EVIDENCE_ONLY'
    if ledger_path.exists():
        ledger = json.loads(ledger_path.read_text('utf-8'))
        assert ledger['disk_sha256'] == SHA
        assert len(ledger['functions']) == len(set(row['va'] for row in ledger['functions']))
        for row in ledger['functions']:
            assert row['status'] and row['conclusion'] and row['unknown']
            for ref in row['evidence_refs']:
                evidence = pointer(sources[ref['file']], ref['pointer'])
                assert int(evidence.get('seed_va', evidence.get('va')), 16) == int(row['va'], 16)
            for anchor in row['semantic_anchors']:
                text = maps[int(row['va'], 16)][int(anchor['va'], 16)]['text']
                assert all(token in text for token in anchor['tokens']), (row['va'], anchor, text)
                anchors += 1
        for window in ledger['owner_windows']:
            original = pointer(sources[window['evidence_file']], window['evidence_pointer'])
            items = original['assembly']
            assert window['owner_va'] == original['owner_va'] and window['site_va'] == original['site_va']
            assert window['start_va'] == items[0]['site_va']
            assert int(window['end_va'], 16) == int(items[-1]['site_va'], 16) + items[-1]['bytes']['size']
        status = 'PASS'
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status=status, disk_sha256=SHA, source_sha256=hashes, **counts,
                  functions=len(maps), decoded_instructions=sum(len(value) for value in maps.values()),
                  semantic_anchors=anchors, boundary='作者离线原证核验；不替代独审；未运行客户端或修改IDB/EXE。')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
