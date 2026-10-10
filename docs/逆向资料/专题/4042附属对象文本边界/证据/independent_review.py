"""独立复核 4042 附属对象的磁盘字节、布局和复制路径。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
raw = json.loads((HERE / '4042_child_raw.json').read_text(encoding='utf-8'))
image = (ROOT / 'RnClient.exe').read_bytes()
assert hashlib.sha256(image).hexdigest() == raw['disk_sha256']
pe = struct.unpack_from('<I', image, 0x3C)[0]
assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
base = struct.unpack_from('<I', image, pe + 52)[0]
section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
sections = [struct.unpack_from('<4I', image, section_table + n * 40 + 8)
            for n in range(struct.unpack_from('<H', image, pe + 6)[0])]


def disk_bytes(va, size):
    matches = [(rva, off) for _, rva, raw_size, off in sections
               if base + rva <= va and va + size <= base + rva + raw_size]
    assert len(matches) == 1, hex(va)
    rva, off = matches[0]
    return image[off + va - base - rva:off + va - base - rva + size]


def instruction_map(rows):
    result = {}
    for row in rows:
        va = int(row['va'], 16)
        assert va not in result
        assert disk_bytes(va, row['size']).hex() == row['hex'], hex(va)
        result[va] = row
    return result


blocks = [c for f in raw['functions'] for c in f['chunks']]
blocks += raw['jumps'] + [w['block'] for w in raw['windows']]
for block in blocks:
    va = int(block['va'], 16)
    assert int(block['end_va'], 16) == va + block['size']
    data = disk_bytes(va, block['size'])
    assert data.hex() == block['disk_hex'] == block['idb_hex']
    assert hashlib.sha256(data).hexdigest() == block['sha256']
    assert block['equal'] is True

assert [f['va'] for f in raw['functions']] == [
    '0x7fd7f0', '0x640c90', '0x640d60', '0x6629d0']
assert len(raw['jumps']) == 3 and len(raw['incoming']) == 7
assert len(raw['windows']) == 3
assert {j['va']: j['target'] for j in raw['jumps']} == {
    '0x60ba62': '0x7fd7f0', '0x60a536': '0x640c90',
    '0x60968b': '0x640d60'}
for jump in raw['jumps']:
    va = int(jump['va'], 16)
    target = va + 5 + struct.unpack('<i', disk_bytes(va + 1, 4))[0]
    assert hex(target) == jump['target']
rows = {}
for f in raw['functions']:
    rows.update(instruction_map(f['instructions']))
for window in raw['windows']:
    rows.update(instruction_map(window['instructions']))


def require(va, opcode, phrase):
    row = rows[va]
    assert row['hex'] == opcode and phrase in row['text'], hex(va)


require(0x7F4266, '6a5c', 'push    5Ch')
require(0x7F4268, 'e807d0e0ff', 'operator new')
require(0x7F42BF, '899140020000', '[ecx+240h]')
require(0x7F42E0, 'e85162e1ff', 'sub_60A536')
require(0x7FD7FE, '6a1e', 'push    1Eh')
require(0x7FD803, '83c154', '54h')
require(0x640CC5, '895118', '[ecx+18h]')
require(0x640D1F, '8d4cca1c', '1Ch')
require(0x640D26, '890491', '[ecx+edx*4]')
require(0x640CCB, 'c6405001', '[eax+50h]')
require(0x640D38, 'c6400800', '[eax+8]')
require(0x640D41, '83c154', '54h')
require(0x640D75, '83c108', 'add     ecx, 8')
require(0x640D79, 'e890f6fcff', 'j__strcpy')
require(0x662A3D, '83c205', 'add     edx, 5')
require(0x662A4B, '8b8c8a000e0000', '0E00h')
require(0x662A52, 'e8b9fbf9ff', 'GetFontType')
require(0x662A59, 'e82d6cfaff', 'sub_60968B')

assert 0x18 - 8 == 16
assert 0x5C - 8 == 84
assert 0x18 - 8 - 1 == 15
result = {'status': 'PASS', 'disk_sha256': raw['disk_sha256'],
          'byte_ranges': len(blocks), 'instruction_sites': len(rows),
          'field_start': '0x18', 'text_start': '0x8',
          'conservative_text_bytes_including_nul': 16,
          'max_non_nul_bytes_before_next_field': 15,
          'limits': '静态布局；未验证所有 Q 的来源、上游长度或运行时可达性'}
(HERE / 'independent_local.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False))
