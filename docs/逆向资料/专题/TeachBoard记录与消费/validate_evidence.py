"""离线核验当前 PE、完整声明块、复用身份、行资源与本批语义锚点。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import lzokay
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = HERE / '证据'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        matches = [(rva, off) for _, rva, length, off in sections
                   if base + rva <= ea and ea + size <= base + rva + length]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    def load(name):
        return json.loads((BASE / name).read_text('utf-8'))

    functions, bridges, texts = {}, {}, {}
    ranges, instructions = set(), 0
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def check_range(row):
        assert row.get('matching', row.get('equal')) is True
        assert disk(int(row['va'], 16), row['size']).hex() == row['idb_hex'] == row['disk_hex']

    def check_function(function):
        nonlocal instructions
        va = function.get('va', function.get('address'))
        assert va not in functions, va
        functions[va] = function
        if 'address' in function:
            for row in function['chunks']:
                assert disk(int(row['start'], 16), int(row['end'], 16)-int(row['start'], 16)).hex() == row['bytes_hex']
                ranges.add((row['start'], int(row['end'], 16)-int(row['start'], 16)))
        elif 'chunks' in function:
            for row in function['chunks']:
                check_range(row)
                ranges.add((row['va'], row['size']))
        else:
            assert function['bytes_match_disk'] is True
            for row in function['byte_ranges'] + function.get('chunk_byte_ranges', []):
                check_range(row)
                ranges.add((row['va'], row['size']))
        for row in function.get('assembly', function.get('instructions', [])):
            ea = int(row.get('va', row.get('ea')), 16)
            decoded = next(decoder.disasm(disk(ea, 15), ea, count=1), None)
            assert decoded is not None, hex(ea)
            if 'hex' in row:
                assert decoded.bytes.hex() == row['hex']
            instructions += 1
            texts[ea] = row['text']

    for name in ('functions_raw.json', 'consumers_raw.json', 'helpers_raw.json', 'closure_raw.json'):
        data = load(name)
        assert data['disk_sha256'] == digest
        for row in data['functions']:
            check_function(row)
        for row in data['thunks']:
            bridges[row['va']] = row
    reused = load('reused_raw.json')
    for source in reused['provenance']:
        blob = (ROOT / source['source']).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == source['source_sha256']
        original = {row.get('va', row.get('address')):row for row in json.loads(blob)['functions']}
        for row in reused['functions']:
            va = row.get('va', row.get('address'))
            if va in source['functions']:
                assert row == original[va]
    for row in reused['functions']:
        check_function(row)
    for row in bridges.values():
        check_range(row)
        raw = disk(int(row['va'],16),5)
        assert raw[0] == 0xE9
        assert int(row['va'],16)+5+struct.unpack_from('<i',raw,1)[0] == int(row['target'],16)
    constants = load('constants_raw.json')
    assert constants['disk_sha256'] == digest
    for row in constants['constant_windows']:
        check_range(row)
    singleton = constants['globals'][0]
    assert singleton['va'] == '0xa839a4' and singleton['disk_hex'] is None
    assert any(base+rva+raw <= 0xA839A4 and 0xA839A4+32 <= base+rva+virtual
               for virtual,rva,raw,_ in sections)
    scan_format = b'%[^\t]\t%[^\t]\t%[^\t]\t%[^\t]\0'
    assert disk(0xA24088,len(scan_format)) == scan_format
    imports = {entry.address: (module.dll, entry.name)
               for module in pefile.PE(data=image).DIRECTORY_ENTRY_IMPORT for entry in module.imports}
    assert imports[0xAD3CBC] == (b'KERNEL32.dll', b'GetTickCount')
    anchors = {0x6DFEC7:'add',0x6DFF07:'eax, 1',0x6DFF31:'0FFFFFFFFh',
               0x6DFF55:'unk_A839A4',0x6E0133:'jnb',0x6E01E5:'sar',
               0x6E0285:'sar',0x7684A6:'+54h]',0x7684AC:'+4Ch]',
               0x7684B3:'+48h]',0x7684E5:'eax, 1',0x7685C3:'0FFFFFFFFh',
               0x76860B:'aDD_16',0x798D9C:'[eax]',0x6C5538:'setnl',
               0x6E0AD1:'shl',0x6E0D28:'sar',0x79C861:'[eax]',
               0x81A2FA:'0Ah',0x81A332:'byte ptr [edx], 0',
               0x81A344:'+94h]',0x81A359:'+9Ch]',0x6E12D2:'10h'}
    for ea, text in anchors.items():
        assert text in texts[ea], (hex(ea),texts.get(ea))
    ledger = json.loads((HERE / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert len(ledger) == len(functions) == 35 and {row['va'] for row in ledger} == set(functions)
    for row in ledger:
        assert all(row.get(key) for key in ('status','conclusion','unknown','evidence'))
        assert all((HERE/path).is_file() for path in row['evidence'])
    resource = load('resource_rows.json')
    blob = (ROOT/resource['source']).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == resource['sha256'] and len(blob) == 64
    key = blob[0]
    size, packed = struct.unpack('<II',bytes((value-key)&255 for value in blob[1:9]))
    decoded = lzokay.decompress(bytes((value-key)&255 for value in blob[9:9+packed]),size)
    assert len(decoded) == size == resource['decoded_size'] == 82 and decoded.hex() == resource['decoded_hex']
    assert hashlib.sha256(decoded).hexdigest() == resource['decoded_sha256']
    assert key == resource['key'] == 90 and packed == resource['packed_size'] == 55 and len(blob)-9-packed == 0
    assert len(resource['rows']) == 4
    for n,(raw,row) in enumerate(zip(decoded.splitlines(),resource['rows']),1):
        assert n == row['line'] and raw.hex() == row['raw_hex']
        fields = raw.split(b'\t')
        assert len(fields) == row['field_count'] == 4 and [field.hex() for field in fields] == row['fields_hex']
        for encoding in ('big5','gbk'):
            assert row[encoding+'_candidate'] == [field.decode(encoding,errors='backslashreplace') for field in fields]
    for doc in HERE.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//') for line in doc.read_text('utf-8').splitlines())
    result = dict(status='PASS',disk_sha256=digest,unique_functions=35,new_functions=26,reused_functions=9,
                  checked_ranges=len(ranges),checked_instructions=instructions,checked_exported_bridges=len(bridges),
                  constants=len(constants['constant_windows']),semantic_anchors=len(anchors),resource_rows=4,
                  semantic_status=dict(Counter(row['status'] for row in ledger)),
                  boundary='字节声明块及有限语义已核；深层容器/分配、CRT扫描器、运行测试未在本批闭合。')
    (BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__ == '__main__':
    main()
