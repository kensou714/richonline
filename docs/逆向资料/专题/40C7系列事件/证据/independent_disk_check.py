"""独审附加核验：RTC记录容量、构造opcode、当前PE与函数字节及区间覆盖。"""
import hashlib
import json
import re
import struct
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
blob = (ROOT / 'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', blob, 60)[0]
count = struct.unpack_from('<H', blob, pe + 6)[0]
opt = struct.unpack_from('<H', blob, pe + 20)[0]
image_base = struct.unpack_from('<I', blob, pe + 52)[0]
sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt + i * 40 + 8) for i in range(count)]


def disk(va, size):
    for _, rva, raw_size, raw_offset in sections:
        delta = va - image_base - rva
        if 0 <= delta and delta + size <= raw_size:
            return blob[raw_offset + delta:raw_offset + delta + size]
    raise ValueError(hex(va))


def load(name):
    return json.loads((BASE / name).read_text('utf-8'))


review = load('function_review.json')
functions = {}
non_instruction_gaps = []
comparisons = 0
for name in review['sources']:
    evidence = load(name)
    for f in evidence['functions']:
        functions.setdefault(f['va'], f)
        covered = set()
        for row in f['byte_ranges']:
            va = int(row['va'], 16)
            assert disk(va, row['size']).hex() == row['idb_hex'] == row['disk_hex']
            covered.update(range(va, va + row['size']))
            comparisons += 1
        for chunk in f['declared_chunks']:
            missing = set(range(int(chunk['start_va'], 16), int(chunk['end_va'], 16))) - covered
            if missing:
                non_instruction_gaps.append(dict(function=f['va'], chunk=chunk, bytes=len(missing)))
    for row in evidence['thunks']:
        va = int(row['va'], 16)
        raw = disk(va, row['size'])
        assert raw.hex() == row['idb_hex'] == row['disk_hex']
        assert raw[0] == 0xE9 and va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
        comparisons += 1

rtc_expected = {
    '0x672020': [12, 24, 12, 4, 10, 4],
    '0x6722c0': [12, 24, 12, 20, 20, 10, 4],
    '0x672600': [12, 24, 6, 10, 4],
    '0x672850': [12, 24, 20, 4, 10, 4],
    '0x672ae0': [12, 24, 20, 20, 10, 4],
    '0x672d90': [12, 24, 4, 20, 4, 10, 4],
    '0x6730a0': [24, 12, 6, 10, 4],
    '0x6732b0': [24, 12, 6, 10, 4],
    '0x6734c0': [24, 12, 6, 10, 4],
}
rtc = []
for va, expected in rtc_expected.items():
    f = functions[va]
    names = [re.search(r'lea\s+edx, stru_([0-9A-F]+)', ins['text']) for ins in f['assembly']]
    names = [m for m in names if m]
    assert len(names) == 1
    header = int(names[0][1], 16)
    n, ptr = struct.unpack('<II', disk(header, 8))
    entries = []
    for i in range(n):
        offset, size, name = struct.unpack('<iII', disk(ptr + 12 * i, 12))
        assert disk(name, 6) == b'xPack\0'
        entries.append(dict(stack_offset=offset, size=size))
    assert [row['size'] for row in entries] == expected, va
    rtc.append(dict(handler=va, descriptor=hex(header), descriptor_hex=disk(header, 8).hex(),
                    array_va=hex(ptr), array_hex=disk(ptr, n * 12).hex(), entries=entries))

opcodes = []
for va, opcode in [('0x63f080', 0x6000), ('0x6946e0', 0x606B),
                   ('0x694940', 0x6078), ('0x694970', 0x6079)]:
    expected = b'\x66\xc7\x00' + struct.pack('<H', opcode)
    matches = [ins for ins in functions[va]['assembly'] if 'mov     word ptr [eax],' in ins['text']]
    assert len(matches) == 1
    at = int(matches[0]['va'], 16)
    assert disk(at, 5) == expected
    opcodes.append(dict(constructor=va, write_va=hex(at), opcode=hex(opcode), bytes=expected.hex()))

result = dict(passed=True, disk_sha256=hashlib.sha256(blob).hexdigest(),
              unique_functions=len(functions), function_and_thunk_comparisons=comparisons,
              uncovered_declared_chunk_bytes=non_instruction_gaps,
              rtc_descriptors=rtc, opcode_writes=opcodes,
              boundary='RTC容量是局部对象尺寸，不等价于网络包长；独立语义审阅另见独立审阅.txt。')
(BASE / 'independent_disk_result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(passed=True, unique_functions=len(functions), comparisons=comparisons,
                     rtc_descriptors=len(rtc), opcode_writes=len(opcodes), chunk_gaps=len(non_instruction_gaps))))
