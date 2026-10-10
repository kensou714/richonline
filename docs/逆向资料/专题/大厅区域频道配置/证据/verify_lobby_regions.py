"""离线复核大厅区域/频道配置原证的 PE 映射、代码字节和跳板目标。"""

import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
raw = json.loads((HERE / 'lobby_regions_ida_raw.json').read_text(encoding='utf-8'))
image = (ROOT / 'RnClient.exe').read_bytes()
assert raw['schema'] == 1
assert hashlib.sha256(image).hexdigest() == raw['disk_sha256']
pe = struct.unpack_from('<I', image, 0x3C)[0]
assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
base = struct.unpack_from('<I', image, pe + 52)[0]
assert hex(base) == raw['image_base']
section_table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
sections = [struct.unpack_from('<4I', image, section_table + n * 40 + 8)
            for n in range(struct.unpack_from('<H', image, pe + 6)[0])]


def disk_bytes(ea, size):
    matches = [(rva, off) for _, rva, raw_size, off in sections
               if base + rva <= ea and ea + size <= base + rva + raw_size]
    assert len(matches) == 1, hex(ea)
    rva, off = matches[0]
    return image[off + ea - base - rva:off + ea - base - rva + size]


def check_block(block):
    ea, size = int(block['va'], 16), block['size']
    assert size > 0 and int(block['end_va'], 16) == ea + size
    disk = disk_bytes(ea, size)
    assert disk.hex() == block['disk_hex'] == block['idb_hex']
    assert hashlib.sha256(disk).hexdigest() == block['disk_sha256'] == block['idb_sha256']
    assert block['equal'] is True
    return ea, ea + size


expected = [0x69EEE0, 0x69F750, 0x6A0130]
assert [int(f['va'], 16) for f in raw['functions']] == expected
assert [int(w['site'], 16) for w in raw['windows']] == [0x60ABDA, 0x5FFE60, 0x60617F]
instruction_count = 0
blocks = []
for function in raw['functions']:
    assert function['pseudocode'] and function['pseudocode_error'] is None
    ranges = [check_block(chunk) for chunk in function['chunks']]
    blocks.extend(ranges)
    assert ranges[0][0] == int(function['va'], 16)
    assert ranges[0][1] == int(function['end_va'], 16)
    for row in function['instructions']:
        ea, size = int(row['va'], 16), row['size']
        assert size > 0 and any(start <= ea and ea + size <= end for start, end in ranges)
        assert disk_bytes(ea, size).hex() == row['hex']
        instruction_count += 1

for window, target in zip(raw['windows'], expected):
    block_range = check_block(window['block'])
    blocks.append(block_range)
    assert len(window['instructions']) == 1
    ea = int(window['site'], 16)
    assert block_range == (ea, ea + 5)
    encoded = disk_bytes(ea, 5)
    assert encoded[0] == 0xE9
    assert ea + 5 + struct.unpack_from('<i', encoded, 1)[0] == target
    assert window['instructions'][0]['hex'] == encoded.hex()
    assert window['instructions'][0]['code_refs'] == [hex(target)]

result = dict(status='PASS', disk_sha256=raw['disk_sha256'],
              idb_input_sha256=raw['idb_input_sha256'],
              input_hash_matches_disk=raw['idb_input_sha256'] == raw['disk_sha256'],
              functions=len(raw['functions']), chunks=len(blocks),
              instructions=instruction_count, jump_windows=len(raw['windows']),
              scope='当前磁盘 PE 离线字节、指令切片和 E9 跳板目标；不验证伪代码语义或运行时行为')
(HERE / 'lobby_regions_validation.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False))
