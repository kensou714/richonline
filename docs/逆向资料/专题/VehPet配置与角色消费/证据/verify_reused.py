"""本批只复用七个已导函数；完整块重核当前PE，窗口边界以Capstone独立解码确认。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCES = (
    ('TeachMode对象与消费者/证据/teachmode_raw.json', (0x627CF0, 0x640020), 'teachmode'),
    ('角色与精灵动画/证据/角色精灵_IDA原始导出.json', (0x6425A0, 0x642740, 0x642B30, 0x643A00), 'sprite'),
    ('银行与资金/证据/bank_handlers.json', (0x7F7160,), 'bank'),
)
# 窗口长度仅用于字段契约，不能代表整个角色绘制函数已完成语义审阅。
SITES = {0x627CF0: (0x627D46,), 0x640020: (0x640081,),
         0x6425A0: (0x64261B, 0x642677, 0x6426CC), 0x7F7160: (0x7F719E,),
         0x642740: (0x6428D4, 0x642913),
         0x642B30: (0x642C34, 0x643812),
         0x643A00: (0x643A3B, 0x6440E1, 0x6441D3, 0x644B84, 0x644242, 0x644BF3)}


def verify():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional_size + 40 * i + 8)
                for i in range(count)]

    def disk(address, size):
        matches = [offset + address - base - rva for _, rva, raw_size, offset in sections
                   if 0 <= address - base - rva and address - base - rva + size <= raw_size]
        assert len(matches) == 1
        offset = matches[0]
        assert offset + size <= len(blob)
        return offset, blob[offset:offset + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    records = []
    for relative, addresses, schema in SOURCES:
        path = ROOT / 'docs/逆向资料/专题' / relative
        source_bytes = path.read_bytes()
        source = json.loads(source_bytes)
        for function in source['functions']:
            address = int(function['address' if schema == 'sprite' else 'va'], 16)
            if address not in addresses:
                continue
            chunks, decoded = [], {}
            for chunk in function.get('chunks', function.get('byte_ranges', [])):
                start = int(chunk['start' if schema == 'sprite' else 'va'], 16)
                original = bytes.fromhex(chunk['bytes_hex' if schema == 'sprite' else 'idb_hex'])
                offset, actual = disk(start, len(original))
                assert actual == original, hex(start)
                chunks.append(dict(va=hex(start), size=len(original), disk_offset=hex(offset),
                                   idb_hex=original.hex(), disk_hex=actual.hex(), matching=True))
                decoded_chunk = list(decoder.disasm(actual, start))
                assert sum(ins.size for ins in decoded_chunk) == len(actual), hex(start)
                for ins in decoded_chunk:
                    decoded[ins.address] = dict(va=hex(ins.address), size=ins.size,
                                               hex=ins.bytes.hex(), disk_hex=ins.bytes.hex(),
                                               matching=True, capstone=ins.mnemonic + ' ' + ins.op_str)
            assembly = function['instructions' if schema == 'teachmode' else 'assembly']
            assert set(decoded) == {int(row['ea' if schema == 'sprite' else 'va'], 16)
                                    for row in assembly}, hex(address)
            rows = []
            for row in assembly:
                va = int(row['ea' if schema == 'sprite' else 'va'], 16)
                assert va in decoded, (hex(address), hex(va))
                check = dict(decoded[va], text=row['text'])
                if schema == 'teachmode':
                    assert row['size'] == check['size'] and row['hex'] == check['hex']
                rows.append(check)
            rows.sort(key=lambda row: int(row['va'], 16))
            windows = []
            for site in SITES[address]:
                positions = [i for i, row in enumerate(rows) if int(row['va'], 16) == site]
                assert len(positions) == 1, hex(site)
                index = positions[0]
                windows.append(dict(site=hex(site), context=rows[max(0, index - 18):index + 25]))
            records.append(dict(va=hex(address), source=relative,
                                source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                                source_idb_input_sha256=source.get('idb_input_sha256'),
                                chunks=chunks, windows=windows,
                                status='既有原证完整块重核；语义仅本批字段窗口'))
    assert len(records) == 7
    result = dict(schema=1, disk_sha256=hashlib.sha256(blob).hexdigest(),
                  scope='七个复用函数完整块磁盘核验与有限字段窗口；不增加唯一VA覆盖', functions=records)
    (HERE / 'reused_verified.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(functions=len(records), chunks=sum(len(row['chunks']) for row in records),
                windows=sum(len(row['windows']) for row in records), disk_sha256=result['disk_sha256'])


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
