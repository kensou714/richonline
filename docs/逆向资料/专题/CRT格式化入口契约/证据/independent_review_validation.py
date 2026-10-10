"""从磁盘独立解码并核对本专题原证；不调用游戏或原 CRT。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = TOPIC.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    optional = pe + 24
    assert struct.unpack_from('<H', blob, optional)[0] == 0x10B
    base = struct.unpack_from('<I', blob, optional + 28)[0]
    table = optional + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(ea, size):
        candidates = [(rva, offset) for _, rva, raw_size, offset in sections
                      if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(candidates) == 1, (hex(ea), size)
        rva, offset = candidates[0]
        start = offset + ea - base - rva
        result = blob[start:start + size]
        assert len(result) == size
        return result

    def check_range(row):
        actual = disk(int(row['va'], 16), row['size'])
        assert row['matching'] is True
        assert actual == bytes.fromhex(row['disk_hex']) == bytes.fromhex(row['idb_hex'])

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoded, functions, chunks, spans, bridges, source_hashes = {}, {}, 0, 0, {}, {}
    for name in ('sprintf_raw.json', 'dependencies_raw.json', 'helpers_raw.json'):
        path = HERE / name
        source_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = json.loads(path.read_text('utf-8'))
        assert data['disk_sha256'] == EXPECTED_SHA
        for function in data['functions']:
            assert function['va'] not in functions and function['bytes_match_disk']
            functions[function['va']] = function
            sites = []
            assert len(function['declared_chunks']) == len(function['chunk_byte_ranges'])
            for declared, row in zip(function['declared_chunks'], function['chunk_byte_ranges']):
                check_range(row)
                ea, end = int(declared['start_va'], 16), int(declared['end_va'], 16)
                assert ea == int(row['va'], 16) and end - ea == row['size']
                instructions = list(decoder.disasm(disk(ea, end - ea), ea))
                assert sum(i.size for i in instructions) == end - ea
                for instruction in instructions:
                    assert instruction.address not in decoded
                    decoded[instruction.address] = instruction
                    sites.append(instruction.address)
                chunks += 1
            assert sites == [int(row['va'], 16) for row in function['assembly']]
            for row in function['byte_ranges']:
                check_range(row)
                spans += 1
        for row in data['thunks']:
            check_range(row)
            ea = int(row['va'], 16)
            actual = disk(ea, 5)
            assert actual[0] == 0xE9
            target = ea + 5 + struct.unpack_from('<i', actual, 1)[0]
            assert target == int(row['target'], 16)
            if row['va'] in bridges:
                assert bridges[row['va']] == hex(target)
            bridges[row['va']] = hex(target)

    windows = []
    for name in ('tables_raw.json', 'labels_raw.json'):
        path = HERE / name
        source_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = json.loads(path.read_text('utf-8'))
        assert data['disk_sha256'] == EXPECTED_SHA
        for row in data['ranges']:
            check_range(row)
            windows.append({'va': row['va'], 'size': row['size']})

    anchors = {
        0x9206DC: ('lea', 'ecx, [ebp + 0x10]'),
        0x92072D: ('mov', 'dword ptr [ecx + 4], 0x7fffffff'),
        0x920737: ('mov', 'dword ptr [edx + 0xc], 0x42'),
        0x920766: ('cmp', 'dword ptr [ebp + 8], 0'),
        0x92076A: ('je', '0x9207b7'),
        0x9207B7: ('mov', 'eax, dword ptr [ebp - 8]'),
        0x93410A: ('and', 'ecx, 0x40'),
        0x93410D: ('je', '0x934127'),
        0x934112: ('cmp', 'dword ptr [edx + 8], 0'),
        0x934116: ('jne', '0x934127'),
        0x93411D: ('add', 'ecx, 1'),
        0x934125: ('jmp', '0x934197'),
        0x93423D: ('add', 'ecx, dword ptr [ebp + 0xc]'),
        0x934245: ('jmp', '0x934288'),
        0x934308: ('add', 'ecx, 4'),
        0x934315: ('mov', 'ax, word ptr [ecx - 4]'),
        0x932D03: ('mov', 'eax, dword ptr [edx + 0x10]'),
        0x932D0F: ('and', 'edx, 0x82'),
        0x932D15: ('je', '0x932d22'),
        0x932D1D: ('and', 'ecx, 0x40'),
        0x932D20: ('je', '0x932d39'),
        0x932D28: ('or', 'eax, 0x20'),
        0x932D31: ('or', 'eax, 0xffffffff'),
        0x932D34: ('jmp', '0x932f1d'),
        0x9335E9: ('sub', 'edx, 1'),
        0x9335F2: ('test', 'ecx, ecx'),
        0x9335F4: ('je', '0x933614'),
        0x9335FC: ('movsx', 'ecx, byte ptr [eax]'),
        0x93363A: ('and', 'edx, 0x20'),
        0x93364C: ('mov', 'word ptr [eax], cx'),
        0x93365D: ('mov', 'dword ptr [edx], eax'),
        0x93365F: ('mov', 'dword ptr [ebp - 0x28], 1'),
        0x933710: ('add', 'ecx, 8'),
        0x933746: ('call', 'dword ptr [0xa69db0]'),
        0x933764: ('call', 'dword ptr [0xa69dbc]'),
        0x933788: ('call', 'dword ptr [0xa69db4]'),
        0x9337C0: ('jmp', '0x933a9d'),
    }
    anchor_results = []
    for ea, expected in anchors.items():
        instruction = decoded[ea]
        assert (instruction.mnemonic, instruction.op_str) == expected, hex(ea)
        anchor_results.append({'va': hex(ea), 'bytes': instruction.bytes.hex(),
                               'decoded': ' '.join(expected)})

    assert struct.unpack('<4I', disk(0xA69DB0, 16)) == (0x60A284,) * 4
    assert bridges['0x60a284'] == '0x948dc0'
    assert struct.unpack('<2I', disk(0xA69DA4, 8)) == (0xA33FFC, 0xA33FEC)
    assert disk(0xA33FFC, 7) == b'(null)\0'
    assert disk(0xA33FEC, 14) == '(null)\0'.encode('utf-16le')
    switch_tables = {}
    for ea, table_ea, count in ((0x9330A6, 0x933C88, 8), (0x9331AA, 0x933CA8, 6),
                                (0x9332C0, 0x933CD1, 5), (0x9333DB, 0x933D14, 15)):
        instruction = decoded[ea]
        assert instruction.mnemonic == 'jmp' and instruction.bytes[:2] == b'\xff\x24'
        assert struct.unpack_from('<I', instruction.bytes, 3)[0] == table_ea
        targets = struct.unpack('<' + 'I' * count, disk(table_ea, count * 4))
        assert all(target in decoded for target in targets)
        switch_tables[hex(ea)] = {'table_va': hex(table_ea), 'targets': list(map(hex, targets))}
    assert switch_tables['0x9330a6']['targets'] == list(map(hex, (
        0x9330AD, 0x933145, 0x933178, 0x9331EE,
        0x93323B, 0x933247, 0x93328A, 0x9333A5)))
    categories = {chr(c): disk(0xA33F60 + c, 1)[0] & 15 for c in range(32, 121)}
    assert ''.join(c for c, category in categories.items() if category == 7) == 'FILNhlw'
    assert ''.join(c for c, category in categories.items() if category == 8) == 'BCEGSXZcdefginopsux'
    assert (decoded[0x93329D].mnemonic, decoded[0x93329D].op_str) == ('sub', 'edx, 0x49')
    assert (decoded[0x9333B8].mnemonic, decoded[0x9333B8].op_str) == ('sub', 'eax, 0x43')
    modifier_targets = switch_tables['0x9332c0']['targets']
    assert all(modifier_targets[disk(0x933CE5 + ord(c) - 0x49, 1)[0]] == '0x9333a0'
               for c in 'LN')
    assert struct.unpack('<I', disk(0xA69D74, 4))[0] == 0xA33590
    documents = {}
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in path.read_text('utf-8').splitlines()), path.name
        documents[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    reviews = json.loads((TOPIC / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert {r['va'] for r in reviews} == set(functions)
    result = {
        'status': 'PASS', 'disk_sha256': EXPECTED_SHA, 'decoder': 'Capstone x86 32-bit',
        'functions': len(functions), 'declared_chunk_records': chunks,
        'instruction_span_records': spans, 'decoded_instructions': len(decoded),
        'unique_bridges': len(bridges), 'constant_windows': windows,
        'semantic_anchor_checks': len(anchors), 'anchors': anchor_results,
        'source_sha256': source_hashes, 'blocking_findings': [],
        'switch_tables': switch_tables, 'document_sha256': documents,
        'scope': '独立磁盘字节/指令边界/桥/静态关键契约核验；不运行CRT，不证明未审依赖',
    }
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('anchors', 'source_sha256', 'constant_windows')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
