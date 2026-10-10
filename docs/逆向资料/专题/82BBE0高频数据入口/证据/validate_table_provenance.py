"""独立按磁盘 PE 复核表项、跳板与函数块字节。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    evidence = json.loads((HERE / 'table_provenance.json').read_text(encoding='utf-8'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA == evidence['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        mapped = [(rva, off) for _, rva, raw, off in sections
                  if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(mapped) == 1, hex(ea)
        rva, off = mapped[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    count = 0

    def check(block):
        nonlocal count
        ea, size = int(block['va'], 16), block['size']
        assert int(block['end_va'], 16) == ea + size
        assert disk(ea, size).hex() == block['ida_hex'] == block['disk_hex']
        assert block['equal'] is True
        count += 1

    assert [f['va'] for f in evidence['functions']] == ['0x82cad0', '0x8553f0']
    for f in evidence['functions']:
        for block in f['chunks']:
            check(block)
        for row in f['instructions']:
            ea, size = int(row['va'], 16), row['size']
            assert any(int(b['va'], 16) <= ea and ea + size <= int(b['end_va'], 16)
                       for b in f['chunks'])
            assert disk(ea, size).hex() == row['hex']
    check(evidence['table']['block'])
    assert len(evidence['table']['slots']) == 16
    for i, slot in enumerate(evidence['table']['slots']):
        assert slot['index'] == i and int(slot['slot_va'], 16) == 0xA2F050 + 4 * i
        assert struct.unpack('<I', disk(0xA2F050 + 4 * i, 4))[0] == int(slot['target'], 16)
    assert evidence['table']['slots'][2]['target'] == '0x609a05'
    assert evidence['table']['xrefs'] == [dict(from_va='0x82cb20', type=1,
                                               iscode=False, owner='0x82cad0')]
    for alias, target in zip(evidence['aliases'], (0x82D820, 0x82CAD0)):
        check(alias['block'])
        ea = int(alias['block']['va'], 16)
        assert disk(ea, 1) == b'\xe9'
        assert ea + 5 + struct.unpack('<i', disk(ea + 1, 4))[0] == target
    check(evidence['undeclared']['block'])
    assert evidence['undeclared']['block']['va'] == '0x82d820'
    assert evidence['undeclared']['block']['end_va'] == '0x82d8b9'
    assert len(evidence['undeclared']['instructions']) == 46
    for row in evidence['undeclared']['instructions']:
        assert disk(int(row['va'], 16), row['size']).hex() == row['hex']
    assert disk(0x855428, 5) == bytes.fromhex('68d0000000')
    assert disk(0x82CB20, 6) == bytes.fromhex('c70050f0a200')
    assert evidence['aliases'][0]['xrefs'] == [dict(from_va='0xa2f058', type=1,
                                                    iscode=False, owner=None)]
    assert evidence['aliases'][1]['xrefs'] == [dict(from_va='0x855451', type=17,
                                                    iscode=True, owner='0x8553f0')]
    result = dict(status='PASS', disk_sha256=digest, complete_functions=2,
                  checked_blocks=count, table_slots=16, undeclared_instructions=46,
                  boundary='静态表项与构造链；未证明运行时动态分派发生')
    (HERE / 'table_provenance_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
