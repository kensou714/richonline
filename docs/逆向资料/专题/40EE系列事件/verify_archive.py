"""验证 40EE 系列原证归档完整性，不执行客户端。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).parent / "证据"
EXPECTED = [*range(0x40EE, 0x40FF), *range(0x4200, 0x4215), 0x5000]

def pe_reader(disk):
    assert disk[:2] == b'MZ'
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    assert disk[pe:pe+4] == b'PE\0\0'
    count, opt_size = struct.unpack_from('<H', disk, pe+6)[0], struct.unpack_from('<H', disk, pe+20)[0]
    opt = pe+24
    assert struct.unpack_from('<H', disk, opt)[0] == 0x10B
    base = struct.unpack_from('<I', disk, opt+28)[0]
    sections = []
    for i in range(count):
        pos = opt+opt_size+40*i
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', disk, pos+8)
        sections.append((rva, raw_size, raw_offset))
    def read(va, size):
        rva = va-base
        for start, length, offset in sections:
            if start <= rva and rva+size <= start+length:
                result = disk[offset+rva-start:offset+rva-start+size]
                assert len(result) == size
                return result
        raise AssertionError(f'VA不可映射到完整磁盘范围: {va:#x}/{size}')
    return read

def main():
    review = json.loads((EVIDENCE / "function_review.json").read_text(encoding="utf-8"))
    got = [int(x["事件"], 16) for x in review["entries"]]
    assert got == EXPECTED, (len(got), [hex(x) for x in got])
    mapping = json.loads((ROOT / 'docs/逆向资料/专题/游戏分派桥接/证据/dispatch_bridges_raw.json').read_text(encoding='utf-8'))
    entries = {int(x['code'],16):x for x in mapping['entries']}
    disk = (ROOT/'RnClient.exe').read_bytes()
    read = pe_reader(disk)
    sha = hashlib.sha256(disk).hexdigest()
    funcs, thunks, ranges, total_bytes = 0, 0, 0, 0
    thunk_addresses = set()
    exported = {}
    for name in ['handlers.json', 'direct_helpers.json']:
        raw = json.loads((EVIDENCE/name).read_text(encoding='utf-8'))
        assert raw['disk_sha256'] == sha, name
        for f in raw['functions']:
            assert f['declared_chunks'] and f['byte_ranges']
            chunks = sorted((int(c['start_va'],16), int(c['end_va'],16)) for c in f['declared_chunks'])
            covered = sorted((int(r['va'],16), int(r['va'],16)+r['size']) for r in f['byte_ranges'])
            assert chunks == covered, (name,f['va'],'块覆盖不完整')
            for r in f['byte_ranges']:
                current = read(int(r['va'],16),r['size'])
                assert current.hex() == r['idb_hex'] == r['disk_hex'], (name,f['va'],r['va'])
                assert r['matching'] and f['bytes_match_disk']
                ranges += 1
                total_bytes += r['size']
            assert f['assembly'], (name,f['va'])
            exported[f['va']] = f
        for t in raw['thunks']:
            thunk_addresses.add(int(t['va'],16))
            current = read(int(t['va'],16),t['size'])
            assert current.hex() == t['idb_hex'] == t['disk_hex'] and t['matching']
        funcs += len(raw['functions'])
        thunks += len(raw['thunks'])
    for row in review['entries']:
        entry = entries[int(row['事件'],16)]
        assert row['va'] == hex(int(entry['resolved_calls'][0]['implementation'],16))
        assert row['桥接入口'] == entry['bridge']
        assert row['va'] in exported and row['conclusion']
    constants = json.loads((EVIDENCE/'numeric_constants.json').read_text(encoding='utf-8'))
    assert constants['disk_sha256'] == sha
    expected_constants = {0xA23388:100.0,0xA23394:0.5}
    assert {int(r['va'],16) for r in constants['regions']} == set(expected_constants)
    for region in constants['regions']:
        va = int(region['va'],16)
        assert region['size'] == 4 and region['matching']
        current = read(va,4)
        assert current.hex() == region['idb_hex'] == region['disk_hex']
        assert struct.unpack('<f',current)[0] == region['float32'] == expected_constants[va]
    result = dict(events=len(got),function_records=funcs,unique_functions=len(exported),thunk_records=thunks,
                  unique_thunks=len(thunk_addresses),constant_regions=2,constant_bytes=8,
                  chunks=ranges,chunk_bytes=total_bytes,source_exe_sha256=sha,
                  checks=['完整PE映射字节比对','原证哈希','全部声明函数块','分派映射','39事件顺序','4213常量原证'])
    (EVIDENCE/'archive_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))

if __name__ == "__main__":
    main()
