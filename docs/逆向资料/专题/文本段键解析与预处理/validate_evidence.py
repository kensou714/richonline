"""离线核验文本解析原证、完整声明块、入口桥和精确分支；不启动游戏。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def at(ea, size):
        for _, rva, raw_size, offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return image[offset + relative:offset + relative + size]
        raise AssertionError('无磁盘对应范围：' + hex(ea))

    def identity(row):
        raw = bytes.fromhex(row['idb_hex'])
        assert row['matching'] is True
        assert len(raw) == row['size']
        assert raw == bytes.fromhex(row['disk_hex']) == at(int(row['va'], 16), row['size'])

    def bridge(row):
        identity(row)
        ea, raw = int(row['va'], 16), bytes.fromhex(row['idb_hex'])
        assert len(raw) == 5 and raw[0] == 0xE9
        assert ea + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)

    evidence = json.loads((HERE / '证据/functions_raw.json').read_text('utf-8'))
    assert evidence['disk_sha256'] == SHA
    functions = {f['va']: f for f in evidence['functions']}
    assert set(functions) == {'0x8191d0', '0x819220', '0x819250', '0x8193f0',
                              '0x819470', '0x819660', '0x819fb0'}
    chunks = spans = 0
    for f in functions.values():
        assert f['bytes_match_disk'] and f['assembly'] and f['pseudocode']
        assert len(f['declared_chunks']) == len(f['chunk_byte_ranges'])
        bounds = []
        for declared, row in zip(f['declared_chunks'], f['chunk_byte_ranges']):
            identity(row)
            start, end = int(declared['start_va'], 16), int(declared['end_va'], 16)
            assert start == int(row['va'], 16) and end - start == row['size']
            bounds.append((start, end))
            chunks += 1
        for row in f['byte_ranges']:
            identity(row)
            spans += 1
        sites = [int(row['va'], 16) for row in f['assembly']]
        assert len(sites) == len(set(sites))
        assert all(any(start <= ea < end for start, end in bounds) for ea in sites)
    thunks = {}
    for row in evidence['thunks']:
        bridge(row)
        thunks[row['va']] = row
    extra = json.loads((HERE / '证据/bridges_constants_raw.json').read_text('utf-8'))
    assert extra['disk_sha256'] == SHA and len(extra['bridges']) == 7
    for row in extra['bridges']:
        bridge(row)
        thunks[row['va']] = row
    for row in extra['constant_windows']:
        identity(row)
    assert {r['va'] for r in extra['shared_buffers']} == {'0xabaa60', '0xabab00'}
    assert all(r['storage'] == 'BSS' and r['capacity'] == '未知' for r in extra['shared_buffers'])
    assert all(not any(base + rva <= int(r['va'], 16) < base + rva + raw_size
                       for _, rva, raw_size, _ in sections)
               for r in extra['shared_buffers'])
    assert at(0xA2EA6C, 3) == b'rt\0'

    # 比对机器码与导出的分支文本，保持负长度/失败状态等结论可复核。
    anchors = {0x819356: '837d0802', 0x81935A: '753b', 0x81939D: '7408',
               0x8193D2: 'b801000000', 0x8194A5: '0f8d', 0x8196AA: '0f8d',
               0x8196BE: '0f84', 0x81A010: '7d31', 0x81A01F: '83f80d'}
    for ea, expected in anchors.items():
        assert at(ea, len(bytes.fromhex(expected))).hex() == expected, hex(ea)
    sites = {int(a['va'], 16): a['text'] for f in functions.values() for a in f['assembly']}
    for ea, text in {0x81935A: 'loc_819397', 0x81939D: 'loc_8193A7',
                     0x8194A5: 'jge', 0x8196AA: 'jge', 0x81A010: 'jge'}.items():
        assert text in sites[ea], (hex(ea), sites[ea])
    preprocess = '\n'.join(a['text'] for a in functions['0x819fb0']['assembly'])
    assert '[eax+4], ecx' in preprocess and '[edx+88h], eax' in preprocess
    assert all(offset not in preprocess for offset in ('+8Ch]', '+90h]', '+94h]'))
    clean = '\n'.join(a['text'] for a in functions['0x8193f0']['assembly'])
    assert all(offset not in clean for offset in ('+88h]', '+98h]', '+9Ch]'))
    load = functions['0x819250']
    assert len([r for r in load['calls'] if r['site'] == '0x819335']) == 1
    assert next(r for r in load['calls'] if r['site'] == '0x8193a2')['implementation'] == '0x819fb0'

    reviews = json.loads((HERE / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert {r['va'] for r in reviews} == set(functions)
    counts = {}
    for r in reviews:
        counts[r['status']] = counts.get(r['status'], 0) + 1
        assert r['evidence']
    for path in HERE.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in path.read_text('utf-8').splitlines()), path.name
    result = dict(status='PASS', disk_sha256=SHA, functions=len(functions),
                  declared_chunks=chunks, instruction_spans=spans, bridges=len(thunks),
                  constant_windows=len(extra['constant_windows']), review_counts=counts,
                  scope='当前PE局部字节与契约锚点校验；不含实机、畸形输入或全部CRT语义验证')
    (HERE / '证据/validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
