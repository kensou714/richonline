"""在已打开的 IDA 数据库中只读导出邮件与礼物分组函数群。"""
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'))

ADDRESSES = [0x6A8C20, 0x6A8E00, 0x6A90E0, 0x6A91A0, 0x6A9270,
             0x6AEBE0, 0x6AEF10, 0x6AF1E0, 0x6AF490, 0x6AF4D0,
             0x6A9330, 0x6A9430, 0x69DF50, 0x69E600, 0x6B8170,
             0x91FBB0, 0x828F60, 0x843BC0, 0x798580, 0x798740,
             0x798770, 0x7987A0, 0x7987C0, 0x757640, 0x759DD0]

def export_inventory(db):
    return export_group(db, ADDRESSES,
                        ROOT / 'docs/逆向资料/专题/邮件与礼物分组/证据/functions.json')

def export_data(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [(blob[at+40*i:at+40*i+8].rstrip(b'\0').decode('ascii'),
                 *struct.unpack_from('<IIII', blob, at + 40*i + 8))
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    ranges = []
    for ea,size in ((0xA80D1C,4),(0x6A9311,20)):
        raw = db.bytes.get_bytes_at(ea,size)
        disk = None
        mapping = None
        for name,vs,rva,rs,ro in sections:
            relative = ea-base-rva
            if 0 <= relative and relative+size <= max(vs,rs):
                mapping = dict(section=name,section_rva=hex(rva),virtual_size=vs,
                               raw_size=rs,raw_offset=ro,relative_offset=relative,
                               classification='磁盘原始区' if relative+size<=rs else '仅虚拟区')
                if relative+size <= rs:
                    disk = blob[ro+relative:ro+relative+size]
                break
        ranges.append(dict(va=hex(ea),size=size,idb_hex=raw.hex(),
                           disk_hex=disk.hex() if disk is not None else None,
                           disk_mapped=disk is not None,mapping=mapping,
                           matching=raw==disk if disk is not None else None))
    xrefs = {}
    for ea in (0xA80D1C,0x798580,0x798740,0x798770,0x7987A0,0x7987C0):
        direct = []
        for x in db.xrefs.to_ea(ea):
            f = db.functions.get_at(x.from_ea)
            row = dict(source=hex(x.from_ea),kind=int(x.type),
                       function=hex(f.start_ea) if f else None,bridge_callers=[])
            raw = db.bytes.get_bytes_at(x.from_ea,5)
            if raw and raw[0] == 0xE9:
                for y in db.xrefs.to_ea(x.from_ea):
                    caller = db.functions.get_at(y.from_ea)
                    row['bridge_callers'].append(dict(site=hex(y.from_ea),kind=int(y.type),
                        function=hex(caller.start_ea) if caller else None))
            direct.append(row)
        xrefs[hex(ea)] = direct
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(),byte_ranges=ranges,
                  xrefs=xrefs,scope='当前IDA精确直接引用及一层E9调用者；仅虚拟区的IDA值不当作磁盘初值，不穷尽动态别名写入')
    path = ROOT / 'docs/逆向资料/专题/邮件与礼物分组/证据/data.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return dict(ranges=len(ranges),unmapped=[r['va'] for r in ranges if not r['disk_mapped']],
                mismatches=[r['va'] for r in ranges if r['disk_mapped'] and not r['matching']])
