"""离线验证当前 PE、声明块、复用来源、跳转表、资源与语义锚点。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = HERE / '证据'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def load(name):
    return json.loads((BASE / name).read_text('utf-8'))


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + length]
        assert len(matches) == 1, hex(ea)
        rva, offset = matches[0]
        start = offset + ea - base - rva
        return image[start:start + size]

    functions, bridges = {}, {}
    ranges = 0

    def check_row(row):
        assert row.get('matching', row.get('equal')) is True
        assert disk(int(row['va'], 16), row['size']).hex() == row['idb_hex'] == row['disk_hex']

    def check_function(function):
        nonlocal ranges
        if 'chunks' in function:
            for row in function['chunks']:
                check_row(row)
                ranges += 1
            for row in function['instructions']:
                assert disk(int(row['va'], 16), row['size']).hex() == row['hex']
        else:
            assert function['bytes_match_disk'] is True
            for row in function['byte_ranges'] + function['chunk_byte_ranges']:
                check_row(row)
                ranges += 1
        functions[function['va']] = function

    for name in ('functions_raw.json', 'helpers_raw.json'):
        raw = load(name)
        assert raw['disk_sha256'] == digest
        for function in raw['functions']:
            check_function(function)
        for row in raw['thunks']:
            bridges[row['va']] = row
    reused = load('reused_raw.json')
    for provenance in reused['provenance']:
        blob = (ROOT / provenance['source']).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == provenance['source_sha256']
        original = {item['va']: item for item in json.loads(blob)['functions']}
        assert all(item == original[item['va']] for item in reused['functions']
                   if item['va'] in provenance['functions'])
    for function in reused['functions']:
        check_function(function)
    extra = load('bridges_constants_raw.json')
    assert extra['disk_sha256'] == digest
    for row in extra['bridges']:
        bridges[row['va']] = row
    for row in bridges.values():
        check_row(row)
        raw = disk(int(row['va'], 16), 5)
        assert raw[0] == 0xE9
        assert int(row['va'], 16) + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
    for row in extra['constant_windows']:
        check_row(row)
    singleton = extra['singleton_storage']
    assert singleton['va'] == '0xa76700' and singleton['storage'] == 'raw-backed .data'
    assert singleton['size'] == 4 and singleton['disk_hex'] == disk(0xA76700, 4).hex() == '00000000'
    expected_strings = {0xA2DAA8:b'LMT_CHU', 0xA2DAB8:b'LMT_ZHONG',
                        0xA2DACC:b'LMT_GAO', 0xA2DADC:b'LMT_XIN',
                        0xA2DAEC:b'PAWN_CHU', 0xA2DB04:b'PAWN_ZHONG',
                        0xA2DB1C:b'PAWN_GAO', 0xA2DB34:b'PAWN_XIN',
                        0xA2DAB4:b'max', 0xA2DAC8:b'max', 0xA2DAD8:b'max',
                        0xA2DAE8:b'max', 0xA2DAF8:b'num', 0xA2DB10:b'num',
                        0xA2DB28:b'num', 0xA2DB40:b'num', 0xA2DAFC:b'item%d'}
    constants = {int(row['va'], 16): row for row in extra['constant_windows']}
    for ea, text in expected_strings.items():
        assert bytes.fromhex(constants[ea]['idb_hex']).startswith(text + b'\0')
    expected_tables = {0x7F265D:[0x7F2664,0x7F2673,0x7F2682,0x7F2694],
                       0x7F270D:[0x7F2714,0x7F2723,0x7F2732,0x7F2744],
                       0x7F27EE:[0x7F27F5,0x7F282F,0x7F2863,0x7F289D]}
    tables = load('jump_tables_raw.json')
    assert len(tables) == 3
    for row in tables:
        check_row(row)
        assert list(struct.unpack('<4I', bytes.fromhex(row['idb_hex']))) == expected_tables[int(row['site'], 16)]
        assert [hex(target) for target in expected_tables[int(row['site'], 16)]] == row['targets']
    anchors = {0x7F1E81:'fstp',0x7F1EBC:'[eax+8]',0x7F1F08:'[eax+10h]',
               0x7F1F44:'[eax+18h]',0x7F1F90:'[eax+20h]',0x7F1FCC:'[eax+28h]',
               0x7F2018:'[eax+30h]',0x7F2054:'[eax+38h]',0x7F20A0:'[ecx+40h]',
               0x7F2165:'[edx+64h]',0x7F222A:'[ecx+88h]',0x7F22F8:'[edx+0ACh]',
               0x7F2116:'[edx+ecx*4+44h]',0x7F21DB:'[ecx+edx*4+68h]',
               0x7F22A6:'[edx+ecx*4+8Ch]',0x7F2374:'[ecx+edx*4+0B0h]',
               0x75D0F3:'[edx+ecx*4]',0x75ED21:'[ecx+eax*4]',
               0x7BA12E:'[eax+44h]',0x7F27D4:'al, 1',0x7F2810:'jge',
               0x7B9F55:'+228h]',0x7B9FB5:'+3B4h]',0x7BA005:'+6CCh]'}
    instructions = {int(row['va'], 16): row['text'] for function in functions.values()
                    for row in function.get('assembly', function.get('instructions', []))}
    for ea, expected in anchors.items():
        assert expected in instructions[ea], (hex(ea), instructions.get(ea))
    ledger = json.loads((HERE / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert {row['va'] for row in ledger} == set(functions) and len(ledger) == len(functions) == 19
    for row in ledger:
        assert all(row.get(key) for key in ('status','conclusion','unknown','evidence'))
        assert all((HERE / path).is_file() for path in row['evidence'])
    resource = load('resource_rows.json')
    blob = (ROOT / resource['source']).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == resource['sha256'] and len(blob) == resource['size'] == 252
    key = blob[0]
    size, packed = struct.unpack('<II', bytes((value-key)&255 for value in blob[1:9]))
    decoded = lzokay.decompress(bytes((value-key)&255 for value in blob[9:9+packed]), size)
    assert decoded.hex() == resource['decoded_hex'] and len(decoded) == resource['decoded_size'] == 453
    assert hashlib.sha256(decoded).hexdigest() == resource['decoded_sha256']
    assert len(blob)-9-packed == resource['tail_size'] == 0 and key == resource['key'] == 27
    lines = decoded.splitlines()
    assert len(lines) == len(resource['rows']) == 45
    for number, (raw, row) in enumerate(zip(lines, resource['rows']), 1):
        fields = raw.split(b'\t')
        assert row['line'] == number and raw.hex() == row['raw_hex']
        assert row['field_count'] == len(fields) and [field.hex() for field in fields] == row['fields_hex']
        for encoding in ('big5','gbk'):
            assert row[encoding+'_candidate'] == [field.decode(encoding, errors='backslashreplace') for field in fields]
    for doc in HERE.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//') for line in doc.read_text('utf-8').splitlines())
    result = dict(status='PASS',disk_sha256=digest,unique_functions=19,new_functions=10,reused_functions=9,
                  semantic_status=dict(Counter(row['status'] for row in ledger)),checked_ranges=ranges,
                  unique_bridges=len(bridges),constant_windows=len(constants),jump_tables=3,
                  semantic_anchors=len(anchors),resource_rows=45,
                  boundary='完整声明块字节一致；3大函数仅局部语义；未做动态游戏验收。')
    (BASE / 'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__ == '__main__':
    main()
