"""完整核验本批必要旧原证与来源SHA；有限消费不升级为全函数语义审阅。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCES = (
    ('TeachMode对象与消费者/证据/teachmode_raw.json', (0x627E70,), 'teachmode'),
    ('角色与精灵动画/证据/角色精灵_IDA原始导出.json', (0x642740,), 'sprite'),
    ('游戏时间与计时调度/证据/functions.json', (0x641EE0,), 'group'),
    ('图像运行时接口/证据/draw_mapping_dependencies.json', (0x6DAA10,), 'group'),
    ('MapView配置记录与预览消费/证据/functions_raw.json', (0x622D50,), 'group'),
)
SITES = {0x627E70: (0x627EC9, 0x627EEA),
         0x642740: (0x642A15, 0x642A54, 0x642A93, 0x642AD2, 0x642B11),
         0x641EE0: (0x641FFC, 0x642011, 0x6420F2, 0x642167, 0x6421CE, 0x642235),
         0x6DAA10: (), 0x622D50: ()}


def verify():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40 * i + 8) for i in range(count)]

    def disk(va, size):
        offsets = [off + va - base - rva for _, rva, length, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(offsets) == 1
        return offsets[0], blob[offsets[0]:offsets[0] + size]

    decoder, records = Cs(CS_ARCH_X86, CS_MODE_32), []
    for relative, addresses, schema in SOURCES:
        source_bytes = (ROOT / 'docs/逆向资料/专题' / relative).read_bytes()
        source = json.loads(source_bytes)
        for function in source['functions']:
            va = int(function['address' if schema == 'sprite' else 'va'], 16)
            if va not in addresses:
                continue
            chunks, decoded = [], {}
            raw_chunks = function['chunks'] if schema in ('sprite', 'teachmode') else function.get('chunk_byte_ranges', function.get('byte_ranges', []))
            for row in raw_chunks:
                at = int(row['start' if schema == 'sprite' else 'va'], 16)
                raw = bytes.fromhex(row['bytes_hex' if schema == 'sprite' else 'idb_hex'])
                offset, actual = disk(at, len(raw))
                assert raw == actual, hex(at)
                chunks.append(dict(va=hex(at), size=len(raw), idb_hex=raw.hex(), disk_hex=actual.hex(),
                                   disk_offset=hex(offset), matching=True))
                block = list(decoder.disasm(raw, at))
                assert sum(ins.size for ins in block) == len(raw), hex(at)
                decoded.update((ins.address, dict(va=hex(ins.address), size=ins.size,
                                                  hex=ins.bytes.hex(), disk_hex=ins.bytes.hex(),
                                                  capstone=ins.mnemonic + ' ' + ins.op_str)) for ins in block)
            assembly = function['instructions' if schema == 'teachmode' else 'assembly']
            assert set(decoded) == {int(row['ea' if schema == 'sprite' else 'va'], 16) for row in assembly}, hex(va)
            rows = []
            for row in assembly:
                at = int(row['ea' if schema == 'sprite' else 'va'], 16)
                check = dict(decoded[at], text=row['text'])
                if schema == 'teachmode':
                    assert check['size'] == row['size'] and check['hex'] == row['hex']
                rows.append(check)
            rows.sort(key=lambda row: int(row['va'], 16))
            windows = []
            for site in SITES[va]:
                indexes = [i for i, row in enumerate(rows) if int(row['va'], 16) == site]
                assert len(indexes) == 1
                index = indexes[0]
                windows.append(dict(site=hex(site), context=rows[max(0, index - 18):index + 30]))
            records.append(dict(va=hex(va), source=relative, source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                                source_idb_input_sha256=source.get('idb_input_sha256'),
                                source_disk_sha256=source.get('disk_sha256'), chunks=chunks, windows=windows,
                                status='完整块磁盘重核，本批语义范围另见正文/清单'))
    assert len(records) == sum(len(row[1]) for row in SOURCES)
    result = dict(schema=1, disk_sha256=hashlib.sha256(blob).hexdigest(),
                  scope='五个复用函数完整块核验，不重复增加唯一VA；局部窗口不代表全函数已审', functions=records)
    (HERE / 'reused_verified.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(functions=len(records), chunks=sum(len(row['chunks']) for row in records),
                windows=sum(len(row['windows']) for row in records))


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
