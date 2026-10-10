"""独立重读PE和所有原证，核验ABI锚点、状态表与格式分派；不运行原CRT。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe+4] == b'PE\0\0'
    base = struct.unpack_from('<I', blob, pe+52)[0]
    table = pe+24+struct.unpack_from('<H', blob, pe+20)[0]
    sections = [struct.unpack_from('<4I', blob, table+40*i+8)
                for i in range(struct.unpack_from('<H', blob, pe+6)[0])]

    def at(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base+rva <= ea and ea+size <= base+rva+raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return blob[off+ea-base-rva:off+ea-base-rva+size]

    def identity(row):
        assert row['matching'] is True
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == row['size']
        assert raw == bytes.fromhex(row['disk_hex']) == at(int(row['va'], 16), row['size'])

    functions, bridges, blocks, spans, instructions = {}, {}, 0, 0, 0
    for name in ('sprintf_raw.json', 'dependencies_raw.json', 'helpers_raw.json'):
        data = json.loads((HERE/'证据'/name).read_text('utf-8'))
        assert data['disk_sha256'] == EXPECTED_SHA
        for f in data['functions']:
            assert f['va'] not in functions and f['bytes_match_disk']
            functions[f['va']] = f
            assert len(f['declared_chunks']) == len(f['chunk_byte_ranges'])
            bounds = []
            for c, r in zip(f['declared_chunks'], f['chunk_byte_ranges']):
                identity(r)
                start, end = int(c['start_va'], 16), int(c['end_va'], 16)
                assert start == int(r['va'], 16) and end-start == r['size']
                bounds.append((start, end))
                blocks += 1
            for r in f['byte_ranges']:
                identity(r)
                spans += 1
            sites = [int(a['va'], 16) for a in f['assembly']]
            assert len(sites) == len(set(sites)) and sites
            assert all(any(start <= ea < end for start, end in bounds) for ea in sites)
            instructions += len(sites)
        for r in data['thunks']:
            identity(r)
            ea = int(r['va'], 16)
            raw = at(ea, 5)
            assert raw[0] == 0xE9
            assert ea+5+struct.unpack_from('<i', raw, 1)[0] == int(r['target'], 16)
            bridges[r['va']] = r
    constants = []
    for name in ('tables_raw.json', 'labels_raw.json'):
        data = json.loads((HERE/'证据'/name).read_text('utf-8'))
        assert data['disk_sha256'] == EXPECTED_SHA
        for r in data['ranges']:
            identity(r)
            constants.append(r)
    raw = at(0x60361E, 5)
    assert raw[0] == 0xE9 and 0x603623+struct.unpack_from('<i', raw, 1)[0] == 0x9206D0
    assert struct.unpack('<2I', at(0xA69DA4, 8)) == (0xA33FFC, 0xA33FEC)
    assert at(0xA33FEC, 14) == '(null)\0'.encode('utf-16le')
    assert at(0xA33FFC, 7) == b'(null)\0'
    assert struct.unpack('<4I', at(0xA69DB0, 16)) == (0x60A284,)*4

    anchors = {
        0x9206DC: '8d4d10', 0x92072D: 'c74104ffffff7f',
        0x920737: 'c7420c42000000', 0x920789: 'c60000',
        0x9207B7: '8b45f8', 0x93410A: '83e140',
        0x934112: '837a0800', 0x934147: '8802',
        0x93417F: '8b4d10', 0x934182: 'c701ffffffff',
        0x9342B8: '83c104', 0x9342D8: '83c108',
        0x934308: '83c104', 0x934315: '668b41fc',
        0x932D0F: '81e282000000', 0x932D1D: '83e140',
        0x933525: 'c78548fdffffffffff7f', 0x93364C: '668908',
        0x93365D: '8902', 0x933710: '83c108',
    }
    for ea, expected in anchors.items():
        assert at(ea, len(bytes.fromhex(expected))).hex() == expected, hex(ea)

    packed = at(0xA33F80, 128)
    categories = {chr(c): packed[c-32] & 15 for c in range(32, 121)}
    assert max(categories.values()) == 8
    assert {c: categories[c] for c in '%.*01+-#slI'} == {
        '%': 1, '.': 2, '*': 3, '0': 4, '1': 5, '+': 6,
        '-': 6, '#': 6, 's': 8, 'l': 7, 'I': 7}

    def states(text):
        state, result = 0, []
        for c in text:
            category = categories.get(c, 0)
            value = packed[category*8+state]
            state = (value if value < 128 else value-256) >> 4
            result.append(state)
        return result

    witnesses = {'%s': [1, 7], '%08x': [1, 2, 3, 7],
                 '%.3s': [1, 4, 5, 7], '%n': [1, 7],
                 '%ld': [1, 6, 7], '%%': [1, 0]}
    for text, expected in witnesses.items():
        assert states(text) == expected, text
    # 这些间接跳转的操作数地址来自机器码，独立于IDA的自动表名。
    switch_targets = {}
    for ea, count in ((0x9330A6, 8), (0x9331AA, 6), (0x9332C0, 5), (0x9333DB, 15)):
        raw = at(ea, 7)
        assert raw[:2] == b'\xff\x24'
        target = struct.unpack_from('<I', raw, 3)[0]
        assert 0x933C88 <= target < 0x933E08
        switch_targets[hex(ea)] = list(struct.unpack('<'+'I'*count, at(target, count*4)))
    assert switch_targets['0x9330a6'] == [0x9330AD, 0x933145, 0x933178, 0x9331EE,
                                       0x93323B, 0x933247, 0x93328A, 0x9333A5]
    reviews = json.loads((HERE/'函数审阅清单.json').read_text('utf-8'))['functions']
    assert {r['va'] for r in reviews} == set(functions)
    for r in reviews:
        for name in r['evidence']:
            assert (HERE/name).is_file(), name
    for p in HERE.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in p.read_text('utf-8').splitlines()), p.name
    result = dict(status='PASS', disk_sha256=EXPECTED_SHA, functions=len(functions),
                  declared_chunk_records=blocks, instruction_span_records=spans,
                  assembly_sites=instructions, unique_outgoing_bridges=len(bridges),
                  constant_window_records=len(constants), independent_anchor_checks=len(anchors),
                  state_witnesses=witnesses, switch_targets=switch_targets,
                  review_counts=dict(Counter(r['status'] for r in reviews)),
                  scope='PE/原证/状态表/分派及ABI锚点校验；未运行原CRT，不表示全部依赖完成')
    (HERE/'证据/validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
