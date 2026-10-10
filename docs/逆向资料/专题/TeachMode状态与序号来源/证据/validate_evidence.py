"""离线复核原字节、桥、候选上下文和显式分级，不启动客户端。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(va, size):
        matches = [(rva, off) for _, rva, raw_size, off in sections
                   if base + rva <= va and va + size <= base + rva + raw_size]
        assert len(matches) == 1, hex(va)
        rva, off = matches[0]
        start = off + va - base - rva
        return image[start:start + size]

    counts = Counter()
    functions, instructions, bridges = {}, {}, {}
    for file in sorted(HERE.glob('*_raw.json')):
        raw = json.loads(file.read_text(encoding='utf-8'))
        assert raw['disk_sha256'] == sha
        for function in raw['functions']:
            assert function['va'] not in functions
            functions[function['va']] = function
            for key in ('byte_ranges', 'chunk_byte_ranges'):
                for row in function[key]:
                    data = disk(int(row['va'], 16), row['size'])
                    assert row['matching'] and data.hex() == row['idb_hex'] == row['disk_hex']
                    counts[key] += 1
            for row in function['assembly']:
                instructions[row['va']] = row['text']
                counts['assembly_sites'] += 1
        for bridge in raw['thunks']:
            va = int(bridge['va'], 16)
            data = disk(va, 5)
            assert bridge['matching'] and data.hex() == bridge['idb_hex'] == bridge['disk_hex']
            assert data[0] == 0xE9 and va + 5 + struct.unpack_from('<i', data, 1)[0] == int(bridge['target'], 16)
            bridges[bridge['va']] = bridge
    candidate_counts = {}
    for file in sorted(HERE.glob('*_candidates.json')):
        raw = json.loads(file.read_text(encoding='utf-8'))
        candidate_counts[file.name] = len(raw['candidates'])
        for row in raw['candidates']:
            assert row['status'].startswith('候选')
            for item in row['context']:
                assert disk(int(item['va'], 16), item['size']).hex() == item['hex']
                counts['candidate_context_records'] += 1
    anchors = {
        '0x69dffc': 'mov     dword ptr [ecx+25Ch], 0',
        '0x6a122e': 'mov     [ecx+25Ch], eax',
        '0x82bca6': "add     ecx, 68h ; 'h'",
        '0x62bb9a': 'cmp     dword ptr [eax+18h], 10h',
        '0x62bb9e': 'jb      short loc_62BBAB',
        '0x6a1688': 'mov     eax, [eax]',
        '0x6a18f2': 'jbe     short loc_6A1931',
        '0x6a191f': 'cmp     ecx, 1',
        '0x63e221': 'add     eax, 65Ch',
        '0x7284c1': 'mov     eax, [eax+68h]',
    }
    for va, text in anchors.items():
        assert instructions[va] == text, va
    reviews = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert len(reviews['functions']) == len(functions) == 24
    assert {r['va'] for r in reviews['functions']} == set(functions)
    for row in reviews['functions']:
        assert all(row.get(key) for key in ('va', 'status', 'conclusion', 'unknown', 'evidence'))
    assert dict(Counter(r['status'] for r in reviews['functions'])) == reviews['status_counts']
    for file in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in file.read_text(encoding='utf-8').splitlines()), file.name
    result = dict(checks='pass', pe_sha256=sha, functions=len(functions),
                  bridges=len(bridges), counts=dict(counts), candidates=candidate_counts,
                  anchors=len(anchors), status_counts=reviews['status_counts'])
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
