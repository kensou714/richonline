"""按当前磁盘 PE 独立复核 IDA 导出的相邻表和工厂链。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
PREVIOUS = ROOT / 'docs/逆向资料/专题/82BBE0高频数据入口/证据/table_provenance.json'


def main():
    evidence = json.loads((HERE / 'a2f720_raw.json').read_text(encoding='utf-8'))
    chain = json.loads((HERE / 'constructor_chain.json').read_text(encoding='utf-8'))
    earlier = json.loads(PREVIOUS.read_text(encoding='utf-8'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA == evidence['disk_sha256'] == chain['disk_sha256'] == earlier['disk_sha256']
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

    checked_blocks = 0

    def check(block):
        nonlocal checked_blocks
        ea, size = int(block['va'], 16), block['size']
        assert int(block['end_va'], 16) == ea + size
        assert disk(ea, size).hex() == block['ida_hex'] == block['disk_hex']
        assert block['equal'] is True
        checked_blocks += 1

    for key, expected in [('function', 0x856090), ('adjacent_function', 0x856180)]:
        f = evidence[key]
        assert int(f['va'], 16) == expected and len(f['chunks']) == 1
        for block in f['chunks']:
            check(block)
        for row in f['instructions']:
            ea, size = int(row['va'], 16), row['size']
            assert any(int(b['va'], 16) <= ea and ea + size <= int(b['end_va'], 16)
                       for b in f['chunks'])
            assert disk(ea, size).hex() == row['hex']

    check(evidence['table']['block'])
    assert evidence['table']['block']['va'] == '0xa2f720'
    assert evidence['table']['block']['end_va'] == '0xa2f7a0'
    assert len(evidence['table']['slots']) == 32
    for i, slot in enumerate(evidence['table']['slots']):
        assert slot['index'] == i and int(slot['slot_va'], 16) == 0xA2F720 + 4 * i
        assert struct.unpack('<I', disk(0xA2F720 + 4 * i, 4))[0] == int(slot['target'], 16)
    assert [evidence['table']['slots'][i]['target'] for i in (0, 1, 2, 3, 4, 5)] == [
        '0x608ea7', '0x604299', '0x0', '0x601d19', '0x60ecc6', '0x0']
    assert evidence['table']['slots'][0]['xrefs'] == evidence['table']['xrefs']
    assert any(x['from_va'] == '0x8560be' and x['owner'] == '0x856090'
               for x in evidence['table']['slots'][0]['xrefs'])
    assert any(x['from_va'] == '0x8561ae' and x['owner'] == '0x856180'
               for x in evidence['table']['slots'][3]['xrefs'])
    assert any(x['from_va'] == '0xa2f730' and not x['iscode']
               for x in evidence['alias']['xrefs'])
    assert disk(0x8560BE, 6) == bytes.fromhex('c70020f7a200')
    assert disk(0x8561AE, 6) == bytes.fromhex('c7002cf7a200')

    for key, target in [('alias', 0x8553F0), ('factory_alias', 0x856090)]:
        alias = evidence[key]
        check(alias['block'])
        ea = int(alias['block']['va'], 16)
        assert disk(ea, 1) == b'\xe9'
        assert ea + 5 + struct.unpack('<i', disk(ea + 1, 4))[0] == target

    f = chain['function']
    assert f['va'] == '0x8563c0' and len(f['chunks']) == 1
    for block in f['chunks']:
        check(block)
    for row in f['instructions']:
        ea, size = int(row['va'], 16), row['size']
        assert any(int(b['va'], 16) <= ea and ea + size <= int(b['end_va'], 16)
                   for b in f['chunks'])
        assert disk(ea, size).hex() == row['hex']
    assert disk(0x8563E6, 6) == bytes.fromhex('c70038f7a200')
    assert any(x['from_va'] == '0x8563e6' and x['owner'] == '0x8563c0'
               for x in chain['table']['xrefs'])
    check(chain['alias']['block'])
    assert chain['alias']['block']['va'] == '0x60810f'
    assert 0x608114 + struct.unpack('<i', disk(0x608110, 4))[0] == 0x8563C0
    assert chain['alias']['xrefs'] == [dict(from_va='0x8561a6', type=17,
                                          iscode=True, owner='0x856180')]

    assert earlier['functions'][0]['va'] == '0x82cad0'
    assert earlier['functions'][1]['va'] == '0x8553f0'
    assert earlier['table']['block']['va'] == '0xa2f050'
    assert disk(0x855428, 5) == bytes.fromhex('68d0000000')
    assert disk(0x82CB20, 6) == bytes.fromhex('c70050f0a200')
    result = dict(status='PASS', disk_sha256=digest, checked_blocks=checked_blocks,
                  complete_functions=3, alias_thunks=3, window_dwords=32,
                  boundary='856180 路径先写 A2F738 后覆写 A2F72C；窗口不等于完整表定义，未证明类继承或动态调用')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                           encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
