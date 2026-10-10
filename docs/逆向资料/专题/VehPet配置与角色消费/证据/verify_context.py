"""离线逐条核验VehPet调用窗口、引用导航及ASCII字面量的当前PE副本。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def verify(source_name='vehpet_context.json', output_name='vehpet_context_verified.json'):
    source = HERE / source_name
    source_bytes = source.read_bytes()
    record = json.loads(source_bytes)
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional_size + 40 * index
        _, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, at + 8)
        assert raw_offset + raw_size <= len(blob)
        sections.append((rva, raw_size, raw_offset))

    def check(row, address_key='va'):
        address, size = int(row[address_key], 16), row['size']
        assert size > 0 and row['hex'] is not None
        original = bytes.fromhex(row['hex'])
        assert len(original) == size
        matches = [(raw_offset + address - base - rva)
                   for rva, raw_size, raw_offset in sections
                   if 0 <= address - base - rva and address - base - rva + size <= raw_size]
        assert len(matches) == 1, (row[address_key], '缺少唯一磁盘范围')
        offset = matches[0]
        disk = blob[offset:offset + size]
        row.update(disk_offset=hex(offset), disk_hex=disk.hex(), matching=original == disk)
        assert row['matching'], row[address_key]

    for row in record['literals']:
        check(row, 'target')
        content = bytes.fromhex(row['content_hex'])
        assert row['string_type'] == 0 and bytes.fromhex(row['hex']) == content + b'\0'
        assert content and all(32 <= value <= 126 for value in content)
        if 'bounded_hex' in row:
            bound = dict(va=row['target'], size=128, hex=row['bounded_hex'])
            check(bound)
            row['bounded_disk_hex'] = bound['disk_hex']
    for row in record.get('data', []):
        check(row)
    for group in (*record.get('windows', []), *record['incoming']):
        for row in group['context']:
            check(row)
        group['context_disk_status'] = '逐条磁盘一致' if group['context'] else '无指令窗口，仅引用导航'
    record.update(source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  disk_sha256=hashlib.sha256(blob).hexdigest(),
                  context_disk_status='所有已有指令窗口和字面量均已逐条对当前PE核验')
    output = HERE / output_name
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(literals=len(record['literals']),
                windows=sum(len(group['context']) for group in record.get('windows', [])),
                incoming=sum(len(group['context']) for group in record['incoming']),
                disk_sha256=record['disk_sha256'])


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
