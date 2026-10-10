"""独立从 PE 解码关键契约；不调用作者验证器，不增加声明函数覆盖。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[5]
BASE = Path(__file__).resolve().parent
DOCS = ROOT / 'docs/逆向资料'
EXPECTED_HASH = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == EXPECTED_HASH
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', blob, pe + 4)[0] == 0x14C
    optional = pe + 24
    assert struct.unpack_from('<H', blob, optional)[0] == 0x10B
    image_base = struct.unpack_from('<I', blob, optional + 28)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    table = optional + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, table + n * 40 + 8)
                for n in range(count)]

    def disk(va, length):
        address = int(va, 16) if isinstance(va, str) else va
        for virtual_size, rva, raw_size, offset in sections:
            delta = address - image_base - rva
            if 0 <= delta and delta + length <= raw_size:
                result = blob[offset + delta:offset + delta + length]
                assert len(result) == length
                return result
        raise AssertionError(f'VA 不在磁盘节范围内: {address:#x}')

    records, bridges, inputs = {}, {}, {}
    for filename in ('generation_raw.json', 'lifecycle_dependencies_raw.json',
                     'lifecycle_leaves_raw.json'):
        path = BASE / filename
        inputs[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = json.loads(path.read_text('utf-8'))
        assert data['disk_sha256'] == digest
        for row in data['functions']:
            assert row['va'] not in records
            records[row['va']] = row
        bridges.update({row['va']: row for row in data['thunks']})
    fresh_count = len(records)
    reused = json.loads((BASE / 'reused_evidence.json').read_text('utf-8'))
    for source, source_hash in reused['source_hashes'].items():
        assert hashlib.sha256((DOCS / source).read_bytes()).hexdigest() == source_hash
    for row in reused['reused']:
        assert row['va'] not in records and row['va'] == row['record']['va']
        records[row['va']] = row['record']
    bridges.update({row['va']: row for row in reused['thunks']})
    range_count = 0
    for record in records.values():
        assert record['byte_ranges']
        for key in ('byte_ranges', 'chunk_byte_ranges'):
            for row in record.get(key, []):
                actual = disk(row['va'], row['size'])
                assert actual == bytes.fromhex(row['idb_hex'])
                assert row['size'] == len(actual)
                if row.get('disk_hex') is not None:
                    assert actual == bytes.fromhex(row['disk_hex'])
                range_count += 1

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    anchors = []

    def decode(start, end):
        raw = disk(start, end - start)
        result = list(decoder.disasm(raw, start))
        assert sum(row.size for row in result) == len(raw)
        return {row.address: row for row in result}

    def check(code, address, mnemonic, operands):
        row = code[address]
        assert (row.mnemonic, row.op_str) == (mnemonic, operands), (
            hex(address), row.mnemonic, row.op_str)
        anchors.append(dict(va=hex(address), mnemonic=row.mnemonic,
                            operands=row.op_str, disk_hex=row.bytes.hex()))

    window = json.loads((BASE / 'unowned_npc_window.json').read_text('utf-8'))
    window_raw = disk(window['start_va'], int(window['end_va'], 16) - int(window['start_va'], 16))
    assert window_raw == bytes.fromhex(window['idb_hex']) == bytes.fromhex(window['disk_hex'])
    assert len(window_raw) == 503 and all(row['owner'] is None for row in window['assembly'])
    code = decode(0x807560, 0x80772E)
    expectations = (
        (0x807578, 'mov', 'dword ptr [ebp - 4], ecx'),
        (0x807589, 'call', '0x611313'),
        (0x807591, 'cmp', 'dword ptr [ebp - 0xc], 0'),
        (0x807595, 'je', '0x807709'),
        (0x80759E, 'mov', 'dl, byte ptr [ecx + 0x21e]'),
        (0x8075A4, 'mov', 'byte ptr [ebp - 0x14], dl'),
        (0x8075AA, 'mov', 'cl, byte ptr [eax + 0x21c]'),
        (0x8075B0, 'mov', 'byte ptr [ebp - 0x13], cl'),
        (0x8075B6, 'mov', 'al, byte ptr [edx + 0x21d]'),
        (0x8075BC, 'mov', 'byte ptr [ebp - 0x12], al'),
        (0x8075C2, 'mov', 'dl, byte ptr [ecx + 0x21f]'),
        (0x8075C8, 'mov', 'byte ptr [ebp - 0x11], dl'),
        (0x8075CB, 'call', '0x60ae14'),
        (0x8075D3, 'cdq', ''),
        (0x8075D4, 'idiv', 'dword ptr [ecx + 0x224]'),
        (0x8075DA, 'add', 'edx, 1'),
        (0x8075EC, 'jge', '0x8075fa'),
        (0x807612, 'jge', '0x807709'),
        (0x80761D, 'and', 'eax, 0x80000003'),
        (0x80763D, 'jne', '0x807664'),
        (0x80763F, 'cmp', 'dword ptr [ebp - 0x28], 0x14'),
        (0x807643, 'jge', '0x807664'),
        (0x807645, 'call', '0x60ae14'),
        (0x80765C, 'add', 'ecx, 1'),
        (0x807662, 'jmp', '0x807633'),
        (0x80766E, 'jne', '0x80769e'),
        (0x807682, 'cmp', 'dword ptr [ebp - 0x2c], 4'),
        (0x807686, 'jge', '0x80769e'),
        (0x807692, 'je', '0x80769c'),
        (0x807697, 'mov', 'dword ptr [ebp - 0x24], ecx'),
        (0x80769C, 'jmp', '0x807679'),
        (0x80769E, 'cmp', 'dword ptr [ebp - 0x24], 0'),
        (0x8076AB, 'call', '0x60d3f8'),
        (0x8076C5, 'call', '0x5ff843'),
        (0x8076DF, 'call', '0x609fe1'),
        (0x8076F9, 'call', '0x6059aa'),
        (0x80772B, 'ret', '4'),
    )
    for address, mnemonic, operands in expectations:
        check(code, address, mnemonic, operands)

    six = json.loads((BASE / 'window_bridges.json').read_text('utf-8'))['bridges']
    expected_bridges = {0x603DDF: 0x807560, 0x60D3F8: 0x807830,
                        0x5FF843: 0x807860, 0x609FE1: 0x807890,
                        0x6059AA: 0x8078C0, 0x611313: 0x807440}
    assert len(six) == 6
    for row in six:
        va = int(row['va'], 16)
        raw = disk(va, 5)
        assert raw == bytes.fromhex(row['idb_hex']) and raw[0] == 0xE9
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == expected_bridges[va] == int(row['target'], 16)
        bridges[row['va']] = row
    for row in bridges.values():
        raw = disk(row['va'], row['size'])
        assert raw == bytes.fromhex(row['idb_hex'])
        assert len(raw) == 5 and raw[0] == 0xE9
        assert int(row['va'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)

    for va in (0x807830, 0x807860, 0x807890, 0x8078C0):
        stub = decode(va, va + 0x27)
        assert not any(row.mnemonic in ('call', 'jmp') for row in stub.values())
        check(stub, va + 0x17, 'mov', 'dword ptr [ebp - 8], 0')
        check(stub, va + 0x1E, 'mov', 'eax, dword ptr [ebp - 8]')
        check(stub, va + 0x24, 'ret', '4')

    life_checks = {
        (0x628010, 0x6280AD): ((0x628040, 'cmp', 'dword ptr [0xa7671c], 0'),
                              (0x628049, 'push', '0x4588'), (0x628069, 'call', '0x6016cf')),
        (0x624148, 0x62418B): ((0x624165, 'push', '1'), (0x62416A, 'call', '0x5ff59b'),
                              (0x624181, 'mov', 'dword ptr [0xa7671c], 0')),
        (0x6290C0, 0x6290FD): ((0x6290D1, 'call', '0x61278b'), (0x6290D9, 'and', 'eax, 1'),
                              (0x6290EA, 'mov', 'eax, dword ptr [ebp - 4]')),
        (0x8054E0, 0x80554E): ((0x8054F3, 'push', '0x1e'), (0x8054F5, 'push', '0x238'),
                              (0x8054FD, 'add', 'eax, 0x2e0'), (0x80550B, 'add', 'ecx, 0x4570')),
        (0x805550, 0x80565A): ((0x8055B0, 'push', '3'), (0x8055B5, 'call', '0x6032e0'),
                              (0x8055C9, 'mov', 'dword ptr [ecx + 0x4580], 0'),
                              (0x8055EB, 'cmp', 'ecx, dword ptr [eax + 0x4584]'),
                              (0x8055F6, 'imul', 'edx, edx, 0x238'),
                              (0x8055FF, 'cmp', 'dword ptr [eax + edx + 0x50c], 0'),
                              (0x805637, 'add', 'ecx, 0x4570')),
        (0x808BD0, 0x808C4E): ((0x808BE1, 'and', 'eax, 2'), (0x808BEE, 'mov', 'edx, dword ptr [ecx - 4]'),
                              (0x808BF2, 'push', '0x1a4'), (0x808C03, 'and', 'ecx, 1'),
                              (0x808C0B, 'sub', 'edx, 4'), (0x808C22, 'call', '0x607557')),
    }
    for (start, end), expected in life_checks.items():
        decoded = decode(start, end)
        for address, mnemonic, operands in expected:
            check(decoded, address, mnemonic, operands)

    loader = decode(0x806EA3, 0x806FCC)
    tokens = {}
    for push_site, write_site, token, offset in (
        (0x806EA3, 0x806ECD, 'bomb', 0x4FC),
        (0x806EDA, 0x806F04, 'missile', 0x4FD),
        (0x806F0E, 0x806F38, 'fire', 0x4FE),
        (0x806F42, 0x806F6C, 'frost', 0x4FF),
        (0x806F79, 0x806FC5, 'num', 0x504),
    ):
        push = loader[push_site]
        assert push.mnemonic == 'push'
        text_va = int(push.op_str, 16)
        assert disk(text_va, len(token) + 1) == token.encode('ascii') + b'\0'
        write = loader[write_site]
        assert write.mnemonic == 'mov' and f'0x{offset:x}' in write.op_str
        tokens[token] = dict(token_va=hex(text_va), write_va=hex(write_site),
                             record_offset=hex(offset - 0x2E0))

    false_hit = decode(0x9DAE3E, 0x9DAE44)
    check(false_hit, 0x9DAE3E, 'jl', '0x9daf8b')
    assert disk(0x9DAE3F, 4) == struct.pack('<I', 0x1478C)
    candidates = set()
    for n, (_, rva, size, offset) in enumerate(sections):
        flags = struct.unpack_from('<I', blob, table + n * 40 + 36)[0]
        if not flags & 0x20000000:
            continue
        section = blob[offset:offset + size]
        for displacement in (0x14788, 0x1478C, 0x4584):
            pattern, cursor = struct.pack('<I', displacement), 0
            while (found := section.find(pattern, cursor)) >= 0:
                candidates.add((image_base + rva + found, displacement))
                cursor = found + 1
    saved_candidates = json.loads((BASE / 'operand_candidates.json').read_text('utf-8'))
    assert candidates == {(int(row['operand_va'], 16), int(row['candidate_displacement'], 16))
                          for row in saved_candidates}
    assert len(candidates) == 37
    for va, site, mnemonic, operands in (
        (0x808CB0, 0x808CC1, 'mov', 'eax, dword ptr [eax + 0x14788]'),
        (0x808CE0, 0x808CF4, 'mov', 'dword ptr [eax + 0x14788], ecx'),
        (0x808D10, 0x808D24, 'mov', 'dword ptr [eax + 0x1478c], ecx'),
    ):
        record = records[hex(va)]
        check(decode(va, int(record['end_va'], 16)), site, mnemonic, operands)
    neighbor_path = DOCS / '专题/KoNews记录与消费者/证据/closure_raw.json'
    neighbor = next(row for row in json.loads(neighbor_path.read_text('utf-8'))['functions']
                    if row['va'] == '0x808d40')
    for row in neighbor['byte_ranges']:
        assert disk(row['va'], row['size']) == bytes.fromhex(row['idb_hex'])
    neighbor_decode = decode(int(neighbor['va'], 16), int(neighbor['end_va'], 16))
    for site, mnemonic, operands in (
        (0x808D62, 'call', '0x6059dc'), (0x808D6C, 'call', '0x60078e'),
        (0x808D71, 'cmp', 'esi, eax'), (0x808D73, 'jae', '0x808d92'),
        (0x808D7E, 'mov', 'edx, dword ptr [ecx + 8]'),
        (0x808D85, 'call', '0x5ffe2e'), (0x808D8D, 'mov', 'dword ptr [ecx + 8], eax'),
    ):
        check(neighbor_decode, site, mnemonic, operands)
    manifest = json.loads((BASE.parent / '函数审阅清单.json').read_text('utf-8'))
    assert len(records) == 34 and fresh_count == 12 and len(reused['reused']) == 22
    assert {row['va'] for row in manifest['functions']} == set(records)
    assert all(row.get('unknown') for row in manifest['functions'])
    assert '0x808d40' not in records and '0x807560' not in records
    assert len(manifest['unrecognized_ranges']) == 1
    assert manifest['unrecognized_ranges'][0]['start_va'] == '0x807560'
    assert manifest['unrecognized_ranges'][0].get('unknown')
    for path in BASE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    output = dict(result='PASS', disk_sha256=digest, new_functions=fresh_count,
                  reused_functions=len(reused['reused']), unique_functions=len(records),
                  range_records_checked=range_count, unique_bridges_checked=len(bridges),
                  six_window_bridges_checked=len(six), unowned_window_bytes=len(window_raw),
                  unowned_code_instructions=len(code), capstone_anchors=anchors,
                  loader_tokens=tokens, raw_operand_candidates=len(candidates), inputs=inputs,
                  unknown_contracts_checked=len(manifest['functions']) + 1,
                  manifest_sha256=hashlib.sha256((BASE.parent / '函数审阅清单.json').read_bytes()).hexdigest(),
                  neighbor_reuse_sha256=hashlib.sha256(neighbor_path.read_bytes()).hexdigest(),
                  boundary='静态独立审阅；未声明范围不计函数；局部一致不代表整个 IDB 一致；未运行游戏')
    (BASE / 'independent_review_validation.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in output.items()
                      if key not in ('capstone_anchors', 'inputs', 'loader_tokens')}, ensure_ascii=True))


if __name__ == '__main__':
    main()
