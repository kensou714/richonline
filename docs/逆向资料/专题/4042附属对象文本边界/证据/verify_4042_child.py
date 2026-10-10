"""离线检查 IDA 原证和当前磁盘 PE 的一致性。"""
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
base = struct.unpack_from('<I', image, pe + 52)[0]
section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
sections = [struct.unpack_from('<4I', image, section_table + n * 40 + 8)
            for n in range(struct.unpack_from('<H', image, pe + 6)[0])]


def check(block):
    ea, size = int(block['va'], 16), block['size']
    assert int(block['end_va'], 16) == ea + size
    candidates = [(rva, off) for _, rva, raw_size, off in sections
                  if base + rva <= ea and ea + size <= base + rva + raw_size]
    assert len(candidates) == 1, block['va']
    rva, off = candidates[0]
    disk = image[off + ea - base - rva:off + ea - base - rva + size]
    assert disk.hex() == block['disk_hex'] == block['idb_hex']
    assert hashlib.sha256(disk).hexdigest() == block['sha256']
    assert block['equal'] is True


blocks = [c for f in raw['functions'] for c in f['chunks']]
blocks += raw['jumps']
blocks += [w['block'] for w in raw['windows']]
for block in blocks:
    check(block)
assert [f['va'] for f in raw['functions']] == [
    '0x7fd7f0', '0x640c90', '0x640d60', '0x6629d0']
assert len(raw['incoming']) == 7 and len(raw['windows']) == 3
print(f'PASS: {len(blocks)} byte ranges, 4 functions, 3 jumps, 3 call windows')
