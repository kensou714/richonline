"""独立PE映射核验原证和12张跳表；仅向本专题写验证结果。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def load_pe():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 60)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    n = struct.unpack_from('<H', blob, pe + 6)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt + i * 40 + 8) for i in range(n)]
    return blob, base, sections


def main():
    blob, base, sections = load_pe()
    def disk(va, size):
        for _, rva, rawsize, off in sections:
            delta = va - base - rva
            if 0 <= delta and delta + size <= rawsize:
                return blob[off + delta:off + delta + size]
        raise ValueError(hex(va))
    evidence = json.loads((HERE / '证据/crt_copy.json').read_text(encoding='utf-8'))
    assert evidence['disk_sha256'] == hashlib.sha256(blob).hexdigest()
    spans = {}
    comparisons = 0
    for f in evidence['functions']:
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in f['declared_chunks']}
        assert declared == {(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['chunk_byte_ranges']}
        for r in f['byte_ranges'] + f['chunk_byte_ranges']:
            a, n = int(r['va'], 16), r['size']
            assert disk(a, n) == bytes.fromhex(r['idb_hex']) == bytes.fromhex(r['disk_hex'])
            spans[a, n] = disk(a, n)
            comparisons += 1
    for t in evidence['thunks']:
        a = int(t['va'], 16)
        raw = disk(a, 5)
        assert raw == bytes.fromhex(t['idb_hex']) == bytes.fromhex(t['disk_hex'])
        assert raw[0] == 0xE9 and a + 5 + struct.unpack('<i', raw[1:])[0] == int(t['target'], 16)
        spans[a, 5] = raw
        comparisons += 1
    tables = json.loads((HERE / '证据/跳表原证.json').read_text(encoding='utf-8'))['tables']
    for t in tables:
        raw = disk(int(t['va'], 16), t['size'])
        assert raw == bytes.fromhex(t['idb_hex'])
        assert list(struct.unpack('<' + 'I' * (len(raw)//4), raw)) == [int(x, 16) for x in t['targets']]
    covered = set()
    for a, n in spans:
        covered.update(range(a, a + n))
    result = dict(functions=len(evidence['functions']), chunks=sum(len(f['declared_chunks']) for f in evidence['functions']),
                  thunks=len(evidence['thunks']), comparisons=comparisons, unique_ranges=len(spans),
                  union_bytes=len(covered), tables=len(tables), table_entries=sum(t['size']//4 for t in tables),
                  note='跳表位于函数块内，不重复增加覆盖。IDA指令清单含误识别数据，不计为正确解码覆盖。',
                  disk_sha256=hashlib.sha256(blob).hexdigest(), errors=[])
    (HERE / '字节验证.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8', newline='\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
