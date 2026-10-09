"""独立按PE映射核字节，检查每个声明块原证完全覆盖，重复范围另计。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    imagebase = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40*i + 8)
                for i in range(count)]

    def disk(va, size):
        for _, rva, rawsize, rawoffset in sections:
            offset = va - imagebase - rva
            if 0 <= offset and offset + size <= rawsize:
                return blob[rawoffset + offset:rawoffset + offset + size]
        raise ValueError('未映射到磁盘的范围 ' + hex(va))

    comparisons = 0
    unique = {}
    functions = {}
    chunks = 0
    source_hashes = {}
    for path in sorted((HERE / '证据').glob('string_*.json')):
        raw = path.read_bytes()
        source_hashes[path.name] = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        assert data['disk_sha256'] == hashlib.sha256(blob).hexdigest()
        for f in data['functions']:
            assert f['va'] not in functions
            functions[f['va']] = path.name
            declared = {(int(c['start_va'],16), int(c['end_va'],16)-int(c['start_va'],16))
                        for c in f['declared_chunks']}
            ranges = {(int(r['va'],16),r['size']) for r in f['chunk_byte_ranges']}
            assert declared == ranges
            chunks += len(declared)
            for r in f['byte_ranges'] + f['chunk_byte_ranges']:
                va, size = int(r['va'],16),r['size']
                actual = disk(va,size)
                assert len(bytes.fromhex(r['idb_hex'])) == size
                assert bytes.fromhex(r['idb_hex']) == bytes.fromhex(r['disk_hex']) == actual
                unique[(va,size)] = actual
                comparisons += 1
        for t in data['thunks']:
            va = int(t['va'],16)
            actual = disk(va,5)
            assert actual == bytes.fromhex(t['idb_hex']) == bytes.fromhex(t['disk_hex'])
            assert actual[0] == 0xE9
            assert va + 5 + int.from_bytes(actual[1:],'little',signed=True) == int(t['target'],16)
            unique[(va,5)] = actual
            comparisons += 1
    reviews = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert set(functions) == {r['va'] for r in reviews['functions']}
    assert all(r.get('status') and r.get('conclusion') and r.get('unknown') and
               (HERE / r['evidence']).is_file() for r in reviews['functions'])
    result = dict(functions=len(functions), chunks=chunks, comparisons=comparisons,
                  unique_ranges=len(unique), unique_range_bytes=sum(map(len,unique.values())),
                  note='相同范围去重；部分不同长度的重叠范围仍不作为覆盖总字节。',
                  disk_sha256=hashlib.sha256(blob).hexdigest(), source_sha256=source_hashes,
                  errors=[])
    (HERE / '验证记录.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__ == '__main__':
    main()

