"""离线复算当前PE、完整块、跳板、导入表与关键指令；不启动客户端。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def at(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    def dword(ea):
        return struct.unpack('<I', at(ea, 4))[0]

    def cstring(ea):
        result = bytearray()
        for i in range(512):
            b = at(ea + i, 1)[0]
            if not b:
                return bytes(result).decode('ascii')
            result.append(b)
        raise AssertionError('未在上限内终止：' + hex(ea))

    def identity(r):
        raw = bytes.fromhex(r['idb_hex'])
        assert r['matching'] is True
        assert raw == bytes.fromhex(r['disk_hex']) == at(int(r['va'], 16), r['size'])
        assert len(raw) == r['size']

    def bridge(r):
        identity(r)
        ea = int(r['va'], 16)
        raw = at(ea, 5)
        assert raw[0] == 0xE9
        assert ea + 5 + struct.unpack_from('<i', raw, 1)[0] == int(r['target'], 16)

    functions, chunks, spans, thunks, assembly_sites = {}, 0, 0, {}, 0
    for name in ('functions_raw.json', 'consumers_raw.json', 'short_helpers_raw.json'):
        raw = json.loads((HERE / '证据' / name).read_text('utf-8'))
        assert raw['disk_sha256'] == EXPECTED_SHA
        for f in raw['functions']:
            assert f['bytes_match_disk'] and f['assembly']
            functions.setdefault(f['va'], f)
            assert len(f['declared_chunks']) == len(f['chunk_byte_ranges'])
            bounds = []
            for declared, r in zip(f['declared_chunks'], f['chunk_byte_ranges']):
                identity(r)
                start, end = int(declared['start_va'], 16), int(declared['end_va'], 16)
                assert start == int(r['va'], 16) and end - start == r['size']
                bounds.append((start, end))
                chunks += 1
            for r in f['byte_ranges']:
                identity(r)
                spans += 1
            sites = [int(a['va'], 16) for a in f['assembly']]
            assert len(sites) == len(set(sites))
            assert all(any(start <= ea < end for start, end in bounds) for ea in sites)
            assembly_sites += len(sites)
        for r in raw['thunks']:
            bridge(r)
            thunks.setdefault(r['va'], r)

    incoming = json.loads((HERE / '证据/incoming.json').read_text('utf-8'))
    for r in incoming['bridges']:
        r = dict(r, size=5, disk_hex=at(int(r['va'], 16), 5).hex(), matching=True)
        bridge(r)
        thunks.setdefault(r['va'], r)

    constants = json.loads((HERE / '证据/constants_raw.json').read_text('utf-8'))
    assert constants['disk_sha256'] == EXPECTED_SHA
    identity(constants['ranges'][0])
    # 导入槽差异保留为观察；不伪造匹配，不纳入代码或常量匹配量。
    iat_observation = constants['ranges'][1]
    assert iat_observation['matching'] is False
    assert at(0xAD4004, 20).hex() == iat_observation['disk_hex']
    assert iat_observation['idb_hex'] != iat_observation['disk_hex']
    keys = {0xA2202C: 'num', 0xA22058: 'reg', 0xA22074: 'win', 0xA220A0: '%s%hu'}
    for ea, expected in keys.items():
        assert cstring(ea) == expected

    import_rva, import_size = struct.unpack_from('<II', image, pe + 24 + 104)
    imports = {}
    for offset in range(0, import_size, 20):
        desc = struct.unpack('<5I', at(base + import_rva + offset, 20))
        if not any(desc):
            break
        original, _, _, name_rva, first = desc
        dll = cstring(base + name_rva)
        source = original or first
        for i in range(4096):
            entry = dword(base + source + 4 * i)
            if not entry:
                break
            name = ('ordinal:' + str(entry & 0xFFFF)) if entry & 0x80000000 else cstring(base + entry + 2)
            imports[base + first + 4 * i] = dict(dll=dll, name=name)
        else:
            raise AssertionError('导入项未终止')
    expected_imports = {
        0xAD4004: 'InternetOpenUrlA', 0xAD4008: 'HttpQueryInfoA',
        0xAD400C: 'InternetReadFile', 0xAD4010: 'InternetCloseHandle',
        0xAD4014: 'InternetOpenA',
    }
    for ea, expected in expected_imports.items():
        assert imports[ea]['name'] == expected
        assert imports[ea]['dll'].lower() == 'wininet.dll'

    anchors = {
        0x81E10E: '8b4dfc',          # 包装器重新恢复this到ECX。
        0x81E34A: 'ff150440ad00',    # InternetOpenUrlA。
        0x81E398: '6a05',           # 查询级别5。
        0x81E3A1: 'ff150840ad00',    # HttpQueryInfoA。
        0x81E3F6: '7670',           # 容量比较jbe，非signed jle。
        0x81E48E: 'ff150c40ad00',    # 唯一InternetReadFile。
        0x819988: 'c60200',          # 在断言之前写终止NUL。
        0x8199F4: '3b550c',          # 比较累计字节与实参上限。
        0x8199F7: '7e17',           # 比较后条件跳转。
    }
    for ea, expected in anchors.items():
        assert at(ea, len(bytes.fromhex(expected))).hex() == expected, hex(ea)
    reader_calls = [a for a in functions['0x81e290']['assembly'] if 'InternetReadFile' in a['text']]
    assert len(reader_calls) == 1 and reader_calls[0]['va'] == '0x81e48e'
    assert at(0x623030, 2339).count(struct.pack('<I', 0xA2202C)) == 1
    assert at(0x623030, 2339).count(struct.pack('<I', 0xA22058)) == 1
    assert at(0x623030, 2339).count(struct.pack('<I', 0xA22074)) == 1

    reviews = json.loads((HERE / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert {r['va'] for r in reviews} == set(functions)
    counts = {}
    for r in reviews:
        counts[r['status']] = counts.get(r['status'], 0) + 1
    for p in HERE.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in p.read_text('utf-8').splitlines()), p.name
    result = dict(status='PASS', disk_sha256=EXPECTED_SHA, unique_functions=len(functions),
                  declared_chunk_records=chunks, instruction_span_records=spans,
                  assembly_sites=assembly_sites, unique_bridges=len(thunks),
                  scope='字节/桥/关键锚点与导入表校验；不等于全部指令语义完成',
                  iat_mismatch_observation=iat_observation,
                  imports={hex(ea): imports[ea] for ea in expected_imports},
                  keys={hex(ea): value for ea, value in keys.items()}, review_counts=counts)
    (HERE / '证据/validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'iat_mismatch_observation'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
