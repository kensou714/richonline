"""在 IDA-MCP 内只读取证；逐函数对照当前磁盘 PE，保留版本边界。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
OUT = ROOT / 'docs/逆向资料/专题/基础对象与分派'

def export(db, addresses, filename):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 24 + 28)[0]
    sections = []
    for i in range(count):
        pos = pe + 24 + optional_size + i * 40
        virtual_size, rva, raw_size, offset = struct.unpack_from('<IIII', blob, pos + 8)
        sections.append((rva, raw_size, offset))
    records = []
    for ea in sorted(set(addresses)):
        f = db.functions.get_at(ea)
        if f is None or f.start_ea != ea:
            raise ValueError('不是函数入口：' + hex(ea))
        size = f.end_ea - ea
        ida_bytes = db.bytes.get_bytes_at(ea, size)
        disk_bytes = None
        for rva, raw_size, offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= raw_size:
                disk_bytes = blob[offset + relative:offset + relative + size]
                break
        record = dict(va=hex(ea), end=hex(f.end_ea),
                      ida_bytes_hex=ida_bytes.hex(),
                      disk_bytes_equal=disk_bytes == ida_bytes,
                      comparison_scope='入口至end_ea连续范围；不代表全部外部依赖相同',
                      pseudocode=[], assembly=[], references=[])
        try:
            record['pseudocode'] = db.pseudocode.get_text(ea)
        except Exception as exc:
            record['decompile_error'] = str(exc)
        record['assembly'] = [dict(va=hex(ins.ea), text=db.instructions.get_disassembly(ins))
                              for ins in db.functions.get_instructions(f)]
        record['references'] = [dict(source=hex(x.from_ea), type=x.type)
                                for x in db.xrefs.to_ea(ea)]
        records.append(record)
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(),
                  historical_inventory_sha256='cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77',
                  scope='IDA当前数据库只读取证，磁盘版本以逐函数字节对照为限', functions=records)
    (OUT / filename).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(count=len(records), mismatches=[r['va'] for r in records if not r['disk_bytes_equal']])
