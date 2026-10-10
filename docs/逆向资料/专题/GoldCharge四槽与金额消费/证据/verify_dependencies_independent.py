"""独立核补充依赖声明块，不导入作者验证器。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    payload = (HERE / 'dependency_raw.json').read_bytes()
    raw = json.loads(payload)
    assert raw['disk_sha256'] == EXPECTED
    assert not raw['thunks']
    assert {int(f['va'], 16) for f in raw['functions']} == {
        0x63E080, 0x727AE0, 0x727BA0, 0x727C00, 0x727C30, 0x727C60, 0x727C90}
    by_site, results = {}, []
    for function in raw['functions']:
        heads, size = [], 0
        assert function['bytes_match_disk'] is True
        assert len(function['declared_chunks']) == len(function['chunk_byte_ranges']) == 1
        for declaration, chunk in zip(function['declared_chunks'], function['chunk_byte_ranges']):
            va = int(chunk['va'], 16)
            assert declaration == dict(start_va=chunk['va'], end_va=hex(va + chunk['size']), is_main=True)
            mappings = [(rva, offset) for _, rva, length, offset in sections
                        if 0 <= va - base - rva and va - base - rva + chunk['size'] <= length]
            assert len(mappings) == 1
            rva, offset = mappings[0]
            disk = image[offset + va - base - rva:offset + va - base - rva + chunk['size']]
            assert len(disk) == chunk['size']
            assert disk.hex() == chunk['disk_hex'] == chunk['idb_hex'] and chunk['matching'] is True
            cursor = va
            for item in cs.disasm(disk, va):
                assert cursor == item.address and item.address not in by_site
                by_site[item.address] = (item.mnemonic, item.op_str)
                heads.append(item.address)
                cursor += item.size
            assert cursor == va + len(disk)
            size += len(disk)
        assert heads == [int(row['va'], 16) for row in function['assembly']]
        assert function['byte_ranges'] == function['chunk_byte_ranges']
        assert not function['calls']
        results.append(dict(va=function['va'], bytes=size, instructions=len(heads)))
    expected = {
        0x63E093: ('cmp', 'dword ptr [eax + 0xa0], 0'),
        0x63E09A: ('setg', 'cl'),
        0x727AF1: ('mov', 'eax, dword ptr [eax + 0x134]'),
        0x727BB1: ('mov', 'eax, dword ptr [eax + 0x10c]'),
        0x727C11: ('movsx', 'eax, byte ptr [eax + 0x5da]'),
        0x727C18: ('neg', 'eax'), 0x727C1A: ('sbb', 'eax, eax'), 0x727C1C: ('neg', 'eax'),
        0x727C41: ('movsx', 'ecx, byte ptr [eax + 0x5dd]'),
        0x727C4A: ('test', 'ecx, ecx'), 0x727C4C: ('setg', 'al'),
        0x727C71: ('movsx', 'ecx, byte ptr [eax + 0x5de]'),
        0x727C7A: ('test', 'ecx, ecx'), 0x727C7C: ('setg', 'al'),
        0x727CA1: ('mov', 'word ptr [eax], 0x16'),
    }
    assert all(by_site[va] == pair for va, pair in expected.items())
    result = dict(schema='richonline-independent-goldcharge-dependencies-1', status='PASS',
                  disk_sha256=EXPECTED, source_sha256=hashlib.sha256(payload).hexdigest(),
                  functions=results, bytes=sum(f['bytes'] for f in results),
                  instructions=len(by_site), semantic_anchors=[dict(va=hex(va), mnemonic=p[0], operands=p[1])
                                                             for va, p in expected.items()],
                  boundary='仅七个补充主体；不把字段谓词命名为未经证明的游戏状态')
    (HERE / 'independent_dependencies_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {k: result[k] for k in ('status', 'bytes', 'instructions')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
