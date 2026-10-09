"""在当前IDA租约只读导出RTC布局、40C1注册和动画3虚表；不修改IDB。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/40C1状态事件/证据'


def export_layout(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40*i + 8)
                for i in range(count)]
    def span(ea, size):
        observed = db.bytes.get_bytes_at(ea, size)
        disk = None
        for _, rva, raw_size, raw in sections:
            delta = ea-base-rva
            if 0 <= delta and delta+size <= raw_size:
                disk = blob[raw+delta:raw+delta+size]
                break
        assert disk is not None and observed == disk, hex(ea)
        return dict(va=hex(ea), size=size, idb_hex=observed.hex(),
                    disk_hex=disk.hex(), matching=True)
    rtcs = []
    spans = []
    for ea in [0x66FE6F, 0x67F89C]:
        header = span(ea, 8)
        count, table = struct.unpack('<II', bytes.fromhex(header['idb_hex']))
        ranges = [header, span(table, 12*count)]
        rows = []
        for i in range(count):
            offset, size, name = struct.unpack('<iiI', db.bytes.get_bytes_at(table+12*i, 12))
            text = bytearray()
            while len(text) < 128:
                value = db.bytes.get_bytes_at(name+len(text), 1)[0]
                text.append(value)
                if value == 0:
                    break
            assert text[-1] == 0
            ranges.append(span(name, len(text)))
            rows.append(dict(offset=offset, size=size, name=text[:-1].decode('ascii')))
        spans.extend(ranges)
        rtcs.append(dict(header_va=hex(ea), table_va=hex(table), entries=rows))
    source = ROOT / 'docs/逆向资料/专题/游戏分派桥接/证据/dispatch_bridges_raw.json'
    registration = next(r for r in json.loads(source.read_text(encoding='utf-8'))['entries']
                        if r['code'] == '0x40c1')
    spans.extend([span(0x7EE923, 10), span(0x603A2E, 5), span(0x61071F, 5), span(0xA2BFE0, 16),
                  span(0x605739, 5), span(0x60E825, 5), span(0x600C11, 5)])
    output = dict(disk_sha256=hashlib.sha256(blob).hexdigest(), rtcs=rtcs,
                  registration=registration, byte_ranges=spans,
                  vtable_va='0xa2bfe0', vtable_words=list(struct.unpack('<IIII', db.bytes.get_bytes_at(0xA2BFE0, 16))),
                  boundary='不读取A9E3E4运行时槽作为磁盘初值；只证明注册指令及跳板。')
    (HERE / 'data_layout.json').write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(rtc_entries=[r['entries'] for r in rtcs], byte_ranges=len(spans),
                vtable_words=[hex(v) for v in output['vtable_words']])
