"""采证后逐条核验Avatar窗口、字串和有界探针；准备阶段不执行。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def verify(source_name='avatar_context.json', output_name='avatar_context_verified.json'):
    source = (HERE / source_name).read_bytes()
    record = json.loads(source)
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        _, rva, size, offset = struct.unpack_from('<IIII', blob, pe + 24 + optional + 40 * index + 8)
        assert offset + size <= len(blob)
        sections.append((rva, size, offset))
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def check(row, key='va', instruction=False):
        address, size = int(row[key], 16), row['size']
        raw = bytes.fromhex(row['hex'])
        assert size > 0 and len(raw) == size
        offsets = [off + address - base - rva for rva, length, off in sections
                   if 0 <= address - base - rva and address - base - rva + size <= length]
        assert len(offsets) == 1
        disk = blob[offsets[0]:offsets[0] + size]
        assert raw == disk, row[key]
        if instruction:
            decoded = list(decoder.disasm(raw, address))
            assert len(decoded) == 1 and decoded[0].size == size
        row.update(disk_offset=hex(offsets[0]), disk_hex=disk.hex(), matching=True)

    for row in record['literals']:
        check(row, 'target')
        content = bytes.fromhex(row['content_hex'])
        assert row['string_type'] == 0 and bytes.fromhex(row['hex']) == content + b'\0'
        assert content and all(32 <= value <= 126 for value in content)
    for row in record['data']:
        check(row)
        raw = bytes.fromhex(row['hex'])
        if 'first_nul' in row:
            assert row['first_nul'] == raw.find(b'\0')
        if row.get('ascii_candidate_hex') is not None:
            candidate = bytes.fromhex(row['ascii_candidate_hex'])
            assert candidate and raw[:row['first_nul']] == candidate
            assert all(32 <= value <= 126 for value in candidate)
        if 'target' in row:
            assert len(raw) == 5 and raw[0] == 0xE9
            assert int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
    for group in (*record['windows'], *record['incoming']):
        for row in group['context']:
            check(row, instruction=True)
        group['context_disk_status'] = '逐条当前PE一致' if group['context'] else '无指令窗口，仅导航'
    record.update(source_sha256=hashlib.sha256(source).hexdigest(), disk_sha256=hashlib.sha256(blob).hexdigest(),
                  context_disk_status='字串、数据和已有窗口逐条核当前PE，不代表业务审阅')
    (HERE / output_name).write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(literals=len(record['literals']), data=len(record['data']),
                windows=sum(len(g['context']) for g in record['windows']),
                incoming=sum(len(g['context']) for g in record['incoming']))


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
