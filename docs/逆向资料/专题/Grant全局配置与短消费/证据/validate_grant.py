"""作者离线核验：PE、声明块、调用桥、复用、字符串门、正文与清单。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    optional = pe + 24
    assert struct.unpack_from('<H', blob, optional)[0] == 0x10B
    base = struct.unpack_from('<I', blob, optional + 28)[0]
    table = optional + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    sources, decoded, bridges, coverage, complete = {}, {}, {}, set(), []
    counters = dict(ranges=0, instructions=0, calls=0, declared_chunks=0,
                    navigation_items=0, strict_string_xrefs=0)

    def load(path):
        path = path if isinstance(path, Path) else HERE / path
        sources[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text('utf-8'))

    def disk(ea, size):
        matches = [(rva, offset) for _, rva, size_raw, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + size_raw]
        assert len(matches) <= 1
        if not matches:
            return None
        rva, offset = matches[0]
        at = offset + ea - base - rva
        raw = blob[at:at + size]
        assert len(raw) == size
        return raw

    def check_range(row, has_idb=True):
        ea, size = int(row['va'], 16), row['size']
        raw = disk(ea, size)
        assert raw is not None and raw.hex() == row['disk_hex'], hex(ea)
        if has_idb:
            assert row['matching'] is True and raw.hex() == row['idb_hex']
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        counters['ranges'] += 1
        return raw

    def decode(ea, raw):
        result = list(decoder.disasm(raw, ea))
        assert sum(row.size for row in result) == len(raw), hex(ea)
        for row in result:
            assert row.address not in decoded or decoded[row.address].bytes == row.bytes
            decoded[row.address] = row
        return result

    def call(row):
        site = decoded[int(row['site'], 16)]
        assert site.mnemonic in ('call', 'jmp') and site.op_str == row['target']
        at = int(row['target'], 16)
        chain = row.get('thunks', [])
        for index, bridge in enumerate(chain):
            assert at == int(bridge, 16)
            destination = int(chain[index + 1] if index + 1 < len(chain) else row['implementation'], 16)
            raw = disk(at, 5)
            assert raw[0] == 0xE9 and at + 5 + struct.unpack_from('<i', raw, 1)[0] == destination
            assert at not in bridges or bridges[at] == destination
            bridges[at] = destination
            at = destination
        assert at == int(row['implementation'], 16)
        counters['calls'] += 1

    for name in ('grant_core_raw.json', 'grant_supplement_raw.json', 'grant_reused_raw.json'):
        payload = load(name)
        assert payload['disk_sha256'] == EXPECTED
        for function in payload['functions']:
            assert function['va'] not in complete and function['bytes_match_disk'] is True
            complete.append(function['va'])
            chunks = function['chunk_byte_ranges']
            assert [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']] == [
                (int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks]
            addresses = []
            for chunk in chunks:
                raw = check_range(chunk)
                ea = int(chunk['va'], 16)
                instructions = decode(ea, raw)
                addresses.extend(row.address for row in instructions)
                coverage.update(range(ea, ea + len(raw)))
                counters['declared_chunks'] += 1
                counters['instructions'] += len(instructions)
            assert addresses == [int(row['va'], 16) for row in function['assembly']]
            for row in function['byte_ranges']:
                check_range(row)
            for row in function['calls']:
                call(row)
        for thunk in payload.get('thunks', []):
            raw = check_range(thunk)
            assert raw[0] == 0xE9
            assert int(thunk['va'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == int(thunk['target'], 16)
        for source in payload.get('provenance', []):
            original = load(ROOT / source['source'])
            assert sources[source['source']] == source['source_sha256']
            original_functions = {row['va']: row for row in original['functions']}
            for va in source['functions']:
                assert next(row for row in payload['functions'] if row['va'] == va) == original_functions[va]
    reused = load('grant_reused_raw.json')
    declarations = load('grant_reuse_declarations_raw.json')
    for row in reused['legacy_rechecked_functions']:
        load(ROOT / row['source'])
        assert sources[row['source']] == row['source_sha256']
        assert row['normalized_text_matching'] is True
        declaration = next(c for c in declarations['reused_declarations'] if c['va'] == row['va'])
        assert row['declared_chunks'] == declaration['declared_chunks']
        actual = []
        for chunk in row['disk_ranges']:
            actual.extend(decode(int(chunk['va'], 16), check_range(chunk, False)))
        assert [r.address for r in actual] == [int(r['ea'], 16) for r in row['old_assembly']]
        assert [r.bytes.hex() for r in actual] == [r['hex'] for r in row['instructions']]
    for row in reused['consumer_windows']:
        original = load(ROOT / row['source'])
        assert sources[row['source']] == row['source_sha256']
        raw = check_range(row['raw_range'])
        actual = decode(int(row['start_va'], 16), raw)
        assert int(row['start_va'], 16) + len(raw) == int(row['end_va'], 16)
        assert [r.address for r in actual] == [int(r.get('va', r.get('ea')), 16) for r in row['assembly']]
        assert [r.bytes.hex() for r in actual] == [r['hex'] for r in row['instructions']]
        for edge in row['calls']:
            call(edge)
    for row in reused['reference_sources']:
        load(ROOT / row['source'])
        assert sources[row['source']] == row['source_sha256']
    navigation = load('grant_navigation_raw.json')
    for window in navigation['windows']:
        raw = check_range(window['raw_range'])
        instructions = decode(int(window['start_va'], 16), raw)
        assert [r.address for r in instructions] == [int(r['va'], 16) for r in window['items']]
        for item in window['items']:
            assert item['is_code'] is True and item['declared_owner'] == window['expected_owner']
            assert decoded[int(item['va'], 16)].bytes == check_range(item)
            counters['navigation_items'] += 1
        for edge in window['calls']:
            call(edge)
    for item in navigation['data_refs']:
        if item['raw']['disk_hex'] is None:
            assert disk(int(item['raw']['va'], 16), item['raw']['size']) is None
            assert not item['raw']['matching']
            continue
        raw = check_range(item['raw'])
        if item['confirmed_c_string']:
            assert item['string_type'] == 0
            assert raw == bytes.fromhex(item['string_hex']) + b'\0'
            counters['strict_string_xrefs'] += 1
    for item in navigation['global_slots']:
        assert check_range(item) == b'\0' * 4
    literal = declarations['key_literal']
    assert disk(0xA2D500, 4).hex() == literal['idb_hex'] == '6e756d00'
    assert decoded[0x7D96F0].mnemonic == 'push' and decoded[0x7D96F0].op_str == '0xa2d500'
    resource = load('grant_resource_raw.json')
    assert resource['exists'] is False and not (ROOT / resource['source']).exists()
    assert sorted(resource['data_filenames']) == sorted(p.name for p in (ROOT / 'Data').iterdir() if p.is_file())
    ledger = load(TOPIC / '函数审阅清单.json')
    assert len(ledger['functions']) == 15 and len({r['va'] for r in ledger['functions']}) == 15
    for row in ledger['functions']:
        assert all(row.get(field) for field in ('va', 'status', 'conclusion', 'unknown', 'evidence'))
        assert (TOPIC / row['document']).is_file()
        for evidence in row['evidence'].split('；'):
            relative, _, pointer = evidence.partition('#')
            path = TOPIC / relative
            value = load(path)
            for component in pointer.strip('/').split('/') if pointer else []:
                value = value[int(component)] if isinstance(value, list) else value[component]
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines()), path
    result = dict(status='PASS', disk_sha256=EXPECTED, complete_raw_functions=len(complete),
                  new_complete_raw_functions=11, reused_complete_raw_functions=1,
                  legacy_text_rechecked_functions=1, consumer_windows=2,
                  unique_complete_raw_bytes=len(coverage), unique_decoded_instructions=len(decoded),
                  unique_bridges=len(bridges), manual_num_gate=True, resource_exists=False,
                  ledger_records=15, counters=counters, source_sha256=sources,
                  boundary='纯离线静态核；字节不等于业务语义，窗口/复用不计新增全文覆盖')
    (HERE / 'author_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_sha256'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
