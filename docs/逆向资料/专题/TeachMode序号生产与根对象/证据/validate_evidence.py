"""离线验证有限语义闭环的PE字节、直接桥、原证引用与三份EMP头样本。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    assert sha == EXPECTED_SHA
    assert image[:2] == b'MZ'
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
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

    def check_function(function, prefix):
        for key in ('byte_ranges', 'chunk_byte_ranges'):
            for row in function[key]:
                actual = disk(int(row['va'], 16), row['size']).hex()
                assert row['matching'] and actual == row['idb_hex'] == row['disk_hex']
                counts[prefix + key] += 1
        for row in function['assembly']:
            instructions[row['va']] = row['text']
            assert any(int(r['va'], 16) <= int(row['va'], 16) < int(r['va'], 16) + r['size']
                       for r in function['byte_ranges']), row['va']
            counts[prefix + 'assembly_sites'] += 1

    for name in ('roots_raw.json', 'load_source_raw.json'):
        raw = load(HERE / name)
        assert raw['disk_sha256'] == sha
        for function in raw['functions']:
            assert function['va'] not in functions
            functions[function['va']] = function
            check_function(function, '')
        for bridge in raw['thunks']:
            va = int(bridge['va'], 16)
            data = disk(va, 5)
            assert bridge['matching'] and data.hex() == bridge['idb_hex'] == bridge['disk_hex']
            assert data[0] == 0xE9
            assert va + 5 + struct.unpack_from('<i', data, 1)[0] == int(bridge['target'], 16)
            if bridge['va'] in bridges:
                assert bridges[bridge['va']] == bridge
            bridges[bridge['va']] = bridge

    # 复用函数单独计量，不并入本批五函数或新增覆盖。
    reused = {}
    dependencies = (('角色1416字段来源', 'functions.json', ('0x7f3c70',)),
                    ('TeachMode状态与序号来源', 'seed_raw.json', ('0x63e210', '0x7284b0')),
                    ('文件访问与路径契约', 'file_wrappers.json', ('0x923f60',)))
    for topic, name, targets in dependencies:
        path = HERE.parents[1] / topic / '证据' / name
        raw = load(path)
        assert raw['disk_sha256'] == sha
        selected = {f['va']: f for f in raw['functions'] if f['va'] in targets}
        assert set(selected) == set(targets), name
        for function in selected.values():
            check_function(function, 'reused_')
        reused[topic + '/' + name] = list(targets)

    incoming = load(HERE / 'roots_incoming.json')['incoming']
    assert len(incoming) == 13
    for row in incoming:
        assert row['status'].startswith('调用者导航')
        for item in row['context']:
            assert disk(int(item['va'], 16), item['size']).hex() == item['hex']
            counts['incoming_context_records'] += 1

    anchors = {
        '0x629cc9': ('push    14794h; Size', '6894470100'),
        '0x629ce6': ('mov     ecx, [ebp+var_14]', '8b4dec'),
        '0x629d0a': ('mov     dword_A7672C, ecx', '890d2c67a700'),
        '0x7baf06': ('mov     ecx, [ebp+var_10]', '8b4df0'),
        '0x7baf09': ('add     ecx, 65Ch', '81c15c060000'),
        '0x7de3be': ('mov     edx, [ebp+var_10]', '8b55f0'),
        '0x7de3c1': ('mov     dword ptr [edx+68h], 0', 'c7426800000000'),
        '0x64f2b6': ('mov     [ebp+var_4], ecx', '894dfc'),
        '0x64f2e1': ('mov     ecx, 16h', 'b916000000'),
        '0x64f2e8': ('rep movsd', 'f3a5'),
        '0x64f32a': ('mov     ecx, [ebp+var_4]', '8b4dfc'),
        '0x64f32d': ('add     ecx, 65Ch', '81c15c060000'),
        '0x7df04b': ('mov     [ebp+var_14], ecx', '894dec'),
        '0x7df0c4': ('push    1; Origin', '6a01'),
        '0x7df0c6': ('push    10h; Offset', '6a10'),
        '0x7df0f1': ('push    1; Origin', '6a01'),
        '0x7df0f3': ('push    5AE4h; Offset', '68e45a0000'),
        '0x7df124': ('cmp     dword ptr [ecx+4], 2', '83790402'),
        '0x7df128': ('jl      short loc_7DF15E', '7c34'),
        '0x7df131': ('push    1; ElementCount', '6a01'),
        '0x7df133': ('push    4; ElementSize', '6a04'),
        '0x7df138': ("add     eax, 68h ; 'h'", '83c068'),
        '0x7df141': ('add     esp, 10h', '83c410'),
        '0x7df144': ('mov     ecx, [ebp+Stream]', '8b8d78ffffff'),
        '0x7df161': ('cmp     dword ptr [eax+4], 3', '83780403'),
        '0x7df165': ('jl      short loc_7DF181', '7c1a'),
        '0x63e221': ('add     eax, 65Ch', '055c060000'),
        '0x7284c1': ('mov     eax, [eax+68h]', '8b4068'),
        '0x7f3cad': ('mov     [eax+57Ch], ecx', '89887c050000'),
    }
    for va, (text, expected_hex) in anchors.items():
        assert instructions[va] == text, va
        assert disk(int(va, 16), len(bytes.fromhex(expected_hex))).hex() == expected_hex, va
    direct_calls = {0x629CE9: 0x600C43, 0x7BAF0F: 0x60700C,
                    0x64F333: 0x60469A, 0x7DF13C: 0x5FF1EA}
    for va, target in direct_calls.items():
        data = disk(va, 5)
        assert data[0] == 0xE8
        assert va + 5 + struct.unpack_from('<i', data, 1)[0] == target
    assert bridges['0x600c43']['target'] == '0x7bae60'
    assert bridges['0x60700c']['target'] == '0x7de310'
    assert bridges['0x60469a']['target'] == '0x7df010'
    assert bridges['0x5ff1ea']['target'] == '0x923f60'

    samples = load(HERE / 'emp_header_samples.json')['samples']
    assert {s['path'] for s in samples} == {'Map/BS_1_1.emp', 'Map/CM_CS_2.emp', 'Map/TC_CM_1.emp'}
    for sample in samples:
        data = (ROOT / sample['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sample['sha256']
        assert len(data) == sample['length']
        assert sample['version_offset'] == 16
        assert data[16:20].hex() == sample['version_hex']
        version = struct.unpack_from('<i', data, 16)[0]
        assert version == sample['version_int32']
        assert [(r['file_offset'], r['map_offset_if_gate_passes']) for r in sample['fields']] == [
            (23288, 24), (23292, 104), (23296, 108), (23300, 112)]
        for row in sample['fields']:
            raw = data[row['file_offset']:row['file_offset'] + row['width']]
            assert row['width'] == 4 and raw.hex() == row['hex']
            assert struct.unpack('<I', raw)[0] == row['uint32']
            minimum = row['signed_version_minimum']
            assert row['read_by_proven_header_path'] == (minimum is None or version >= minimum)
            counts['emp_observed_fields'] += 1
    # signed边界仅是分支模型校验，不是合成资源的客户端加载测试。
    gates = [(v, v >= 2, v >= 3) for v in (-2147483648, -1, 0, 1, 2, 3, 4)]
    assert gates == [(-2147483648, False, False), (-1, False, False),
                     (0, False, False), (1, False, False), (2, True, False),
                     (3, True, True), (4, True, True)]

    review = load(HERE.parent / '函数审阅清单.json')
    assert len(review['functions']) == len(functions) == 5
    assert {r['va'] for r in review['functions']} == set(functions)
    assert review['new_unique_va'] == 0 and review['existing_constructor_rechecks'] == 2
    for row in review['functions']:
        assert all(row.get(k) for k in ('va', 'status', 'conclusion', 'unknown', 'evidence', 'reuse'))
        for start, end in row['reviewed_ranges']:
            assert int(start, 16) < int(end, 16)
            assert any(int(r['va'], 16) <= int(start, 16) and
                       int(end, 16) <= int(r['va'], 16) + r['size']
                       for r in functions[row['va']]['byte_ranges']), (row['va'], start, end)
    assert dict(Counter(r['status'] for r in review['functions'])) == review['status_counts']
    for file in HERE.parent.glob('*.txt'):
        lines = file.read_text(encoding='utf-8').splitlines()
        assert all(not line.strip() or line.startswith('//') for line in lines), file.name
        assert all(line == line.rstrip() for line in lines), file.name
    for file in HERE.glob('*.py'):
        assert all(line == line.rstrip() for line in file.read_text(encoding='utf-8').splitlines()), file.name
    result = dict(checks='pass', pe_sha256=sha, functions=len(functions),
                  new_unique_va=0, existing_constructor_rechecks=2,
                  bridges=len(bridges), counts=dict(counts), reused=reused,
                  anchors=len(anchors), direct_calls=len(direct_calls),
                  incoming=len(incoming), emp_samples=len(samples), signed_gate_model=gates,
                  status_counts=review['status_counts'])
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
