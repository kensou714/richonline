"""作者离线核验：原证、调用桥、逐指令转录与人工清单相互约束。"""
from pathlib import Path
import hashlib
import json
import struct
import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    assert blob[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10b
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, at + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(va, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= raw]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        start = off + va - base - rva
        return blob[start:start + size]

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    bytes_checked, virtual_checked = 0, 0
    transcript, instruction_maps, sources, ranges, source_hashes = [], {}, {}, [], {}

    def compare(value):
        nonlocal bytes_checked, virtual_checked
        if isinstance(value, dict):
            if 'size' in value and 'disk_hex' in value and ('start_va' in value or 'va' in value):
                address = int(value.get('start_va', value.get('va')), 16)
                if value['disk_hex'] is None:
                    virtual = [1 for length, rva, _, _ in sections
                               if base + rva <= address and address + value['size'] <= base + rva + length]
                    assert len(virtual) == 1 and value.get('matching') is None
                    assert '不是运行时' in value['pending_status']
                    virtual_checked += 1
                else:
                    raw = disk(address, value['size'])
                    assert raw.hex() == value['disk_hex'].lower(), hex(address)
                    if 'idb_hex' in value:
                        assert value['matching'] and raw.hex() == value['idb_hex'].lower()
                    if 'sha256' in value:
                        assert hashlib.sha256(raw).hexdigest() == value['sha256']
                    bytes_checked += 1
            for child in value.values():
                compare(child)
        elif isinstance(value, list):
            for child in value:
                compare(child)

    def function_transcript(function, filename):
        address = int(function.get('seed_va', function.get('va')), 16)
        decoded = {}
        for chunk in function['chunk_byte_ranges']:
            start = int(chunk.get('start_va', chunk.get('va')), 16)
            raw = disk(start, chunk['size'])
            instructions = list(decoder.disasm(raw, start))
            assert sum(item.size for item in instructions) == len(raw), hex(start)
            for item in instructions:
                assert item.address not in decoded
                decoded[item.address] = dict(va=hex(item.address), size=item.size,
                                            bytes_hex=item.bytes.hex(),
                                            text=item.mnemonic + ' ' + item.op_str)
        for item in function['assembly']:
            ea = int(item.get('site_va', item.get('va')), 16)
            assert ea in decoded, (filename, hex(ea))
            if 'bytes_hex' in item:
                assert item['bytes_hex'] == decoded[ea]['bytes_hex']
                assert item['size'] == decoded[ea]['size']
                assert item['text'] == decoded[ea]['text']
        if address in instruction_maps:
            assert instruction_maps[address] == decoded, hex(address)
        instruction_maps[address] = decoded
        transcript.append('// 函数 ' + hex(address) + ' / ' + filename)
        transcript.extend('// ' + item['va'] + ' ' + item['text'] for item in decoded.values())
        ranges.append(dict(va=hex(address), source=filename, chunks=len(function['chunk_byte_ranges']),
                           decoded_instructions=len(decoded)))

    names = ['reused_preparation.json', 'bounded_raw.json', 'formal_functions.json',
             'dependency_raw.json', 'dependency_helpers_raw.json',
             'dependency_leaf_raw.json', 'closure_raw.json',
             'owner_context_raw.json']
    for filename in names:
        path = HERE / filename
        if not path.exists():
            continue
        raw = path.read_bytes()
        source_hashes[filename] = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        assert data['disk_sha256'] == SHA
        sources[filename] = data
        if filename == 'formal_functions.json':
            original = sources['bounded_raw.json']
            assert data['source_sha256'] == source_hashes['bounded_raw.json']
            for i, function in enumerate(data['functions']):
                source = original['functions'][i]
                assert function['source_pointer'] == '/functions/' + str(i)
                assert function['va'] == source['seed_va']
                for key, value in source.items():
                    assert function[key] == value, (i, key)
                assert function['byte_ranges'] == source['chunk_byte_ranges']
                assert function['declared_chunks'] == [
                    dict(start_va=chunk['start_va'],
                         end_va=hex(int(chunk['start_va'], 16) + chunk['size']),
                         is_main=chunk['start_va'] == source['seed_va'])
                    for chunk in source['chunk_byte_ranges']]
        compare(data)
        for source in data.get('sources', []) + data.get('reuse_sources', []):
            content = (DOCS / source['path']).read_bytes()
            assert hashlib.sha256(content).hexdigest() == source['source_sha256'], source['path']
        for function in data.get('functions', []):
            function_transcript(function, filename)
        for function in data.get('historical_contracts', []):
            function_transcript(function, filename + ' / 历史局部契约')
        for bridge in data.get('verified_direct_bridges', []) + data.get('thunks', []):
            address = int(bridge.get('start_va', bridge.get('va')), 16)
            raw = disk(address, 5)
            assert raw[0] == 0xe9 and bridge['size'] == 5
            assert address + 5 + struct.unpack_from('<i', raw, 1)[0] == int(bridge.get('target_va', bridge.get('target')), 16)
        calls = data.get('calls', []) + [call for function in data.get('functions', [])
                                       for call in function.get('calls', [])]
        for call in calls:
            address = int(call.get('site_va', call.get('site')), 16)
            ins = next(decoder.disasm(disk(address, 16), address, count=1))
            target = int(call.get('target_va', call.get('target')), 16)
            if ins.bytes[:2] == b'\xff\x15':
                assert ins.size == 6 and struct.unpack_from('<I', ins.bytes, 2)[0] == target
            else:
                assert ins.bytes[0] in (0xe8, 0xe9) and ins.size == 5, hex(address)
                assert address + 5 + struct.unpack_from('<i', ins.bytes, 1)[0] == target
        windows = data.get('explicit_owner_windows', []) + data.get('windows', [])
        windows += [row['owner_window'] for rows in data.get('incoming', {}).values()
                    for row in rows if 'owner_window' in row]
        for window in windows:
            assert window['owner_va'] is not None
            transcript.append('// 局部窗口 owner=' + window['owner_va'] + ' site=' + window.get('site_va', window.get('start_va')))
            previous_end = None
            for item in window['assembly']:
                ea = int(item['site_va'], 16)
                compare(dict(va=item['site_va'], **item['bytes']))
                ins = next(decoder.disasm(disk(ea, item['bytes']['size']), ea, count=1))
                assert ins.size == item['bytes']['size']
                assert previous_end is None or previous_end == ea
                previous_end = ea + ins.size
                transcript.append('// ' + hex(ea) + ' ' + ins.mnemonic + ' ' + ins.op_str)

    (HERE / 'review_assembly.txt').write_text('\n'.join(transcript) + '\n', 'utf-8')
    manifest_path = HERE.parent / '函数审阅清单.json'
    anchors = 0
    status = 'EVIDENCE_ONLY'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text('utf-8'))
        assert manifest['disk_sha256'] == SHA
        addresses = [int(row['va'], 16) for row in manifest['functions']]
        assert len(addresses) == len(set(addresses))
        for row in manifest['functions']:
            assert row['status'] and row['conclusion'] and row['unknown']
            for evidence in row['evidence_refs']:
                payload = sources[evidence['file']]
                for part in evidence['pointer'].strip('/').split('/'):
                    payload = payload[int(part)] if isinstance(payload, list) else payload[part]
                assert int(payload.get('seed_va', payload.get('va')), 16) == int(row['va'], 16)
            for anchor in row['semantic_anchors']:
                ins = instruction_maps[int(row['va'], 16)][int(anchor['va'], 16)]
                assert all(token in ins['text'] for token in anchor['tokens']), anchor
                anchors += 1
        status = 'PASS'
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines()), path
    result = dict(status=status, disk_sha256=SHA, source_sha256=source_hashes,
                  checked_byte_records=bytes_checked, virtual_snapshots=virtual_checked,
                  functions=ranges, semantic_anchors=anchors,
                  scope='作者离线核验；状态不替代人工审阅或独立审阅；未启动游戏或修改客户端')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(status=status, byte_records=bytes_checked,
                          functions=len(instruction_maps), anchors=anchors)))


if __name__ == '__main__':
    main()
