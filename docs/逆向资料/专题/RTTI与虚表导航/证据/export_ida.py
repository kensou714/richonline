"""在现有IDA-MCP租约中执行；只读数据链、交叉引用、跳板和所属函数。"""
import json
import struct
from pathlib import Path

RT_ROOT = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/RTTI与虚表导航')
RT_PROJECT = RT_ROOT.parents[3]
rt_scan = json.loads((RT_ROOT / '证据/rtti_scan.json').read_text('utf-8'))
rt_blob = (RT_PROJECT / 'RnClient.exe').read_bytes()
rt_sections = rt_scan['sections']

def rt_disk(va, size):
    for s in rt_sections:
        if s['va'] <= va and va + size <= s['va'] + s['raw_size']:
            off = s['raw_offset'] + va - s['va']
            return rt_blob[off:off + size]
    return None

def rt_identity(va, size):
    live = db.bytes.get_bytes_at(va, size)
    disk = rt_disk(va, size)
    return dict(va=hex(va), size=size, idb_hex=live.hex() if live else None,
                disk_hex=disk.hex() if disk else None, matching=live == disk)

rt_data = []
for record in rt_scan['data_records']:
    row = dict(record)
    row.update(rt_identity(int(row['va'], 16), row['size']))
    rt_data.append(row)
rt_failures = []
for record in rt_scan['rejected_col_candidates']:
    row = dict(record)
    row['bytes'] = rt_identity(int(row['candidate_col'], 16), 20)
    rt_failures.append(row)

rt_targets = {}
rt_addresses = set()
def rt_resolve(ea):
    chain = []
    original = ea
    while ea not in [int(r['va'], 16) for r in chain] and len(chain) < 16:
        raw = db.bytes.get_bytes_at(ea, 5)
        if not raw or raw[0] != 0xe9:
            break
        target = ea + 5 + int.from_bytes(raw[1:], 'little', signed=True)
        row = rt_identity(ea, 5)
        row['target'] = hex(target)
        chain.append(row)
        ea = target
    f = db.functions.get_at(ea)
    if f is not None and f.start_ea == ea:
        rt_addresses.add(ea)
    return dict(entry=hex(original), implementation=hex(ea), jumps=chain,
                declared_entry=f is not None and f.start_ea == ea)

rt_xrefs = []
rt_tables = [dict(v, kind='RTTI已验证') for v in rt_scan['vftables']]
rt_tables.append(dict(va='0xa2bfb0', kind='动画0已知虚表；复用角色与精灵动画专题',
                     entries=[dict(slot=hex(0xa2bfb0 + i * 4),
                                   target=hex(struct.unpack('<I', rt_disk(0xa2bfb0 + i * 4, 4))[0])) for i in range(3)]))
for v in rt_tables:
    address = int(v['va'], 16)
    references = []
    for x in db.xrefs.to_ea(address):
        f = db.functions.get_at(x.from_ea)
        ins = db.instructions.get_at(x.from_ea)
        row = dict(source=hex(x.from_ea), type=int(x.type),
                   function=hex(f.start_ea) if f else None,
                   instruction=db.instructions.get_disassembly(ins) if ins else None,
                   bytes=rt_identity(x.from_ea, ins.size) if ins else None)
        if f:
            rt_addresses.add(f.start_ea)
        references.append(row)
    targets = [rt_resolve(int(e['target'], 16)) for e in v['entries']]
    rt_xrefs.append(dict(vtable=v['va'], kind=v['kind'], references=references,
                         preceding_slot=rt_identity(address - 4, 4), targets=targets))

exec((RT_PROJECT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'))
rt_export = export_group(db, rt_addresses, str(RT_ROOT / '证据/functions_raw.json'))
rt_result = dict(disk_sha256=rt_scan['disk_sha256'], data_records=rt_data,
                 rejected_col_samples=rt_failures, vtable_references=rt_xrefs,
                 scope='表与写入引用定位；函数原证导出不等于函数完整语义审阅', function_export=rt_export)
rt_seh = rt_identity(0xa31bc8, 12)
rt_seh.update(kind='type_info析构SEH scope table',
              fields=list(struct.unpack('<iII', rt_disk(0xa31bc8, 12))))
rt_result['supplemental_data'] = [rt_seh]
for rt_va, rt_size, rt_text in [(0xa31b70, 18, 'Unknown exception'),
                               (0xa319bc, 2, '*'),
                               (0xa2265c, 19, 'vector<T> too long')]:
    rt_row = rt_identity(rt_va, rt_size)
    rt_row.update(kind='正文引用ASCII字面量', text=rt_text)
    assert rt_disk(rt_va, rt_size) == rt_text.encode('ascii') + b'\0'
    rt_result['supplemental_data'].append(rt_row)
(RT_ROOT / '证据/ida_navigation.json').write_text(json.dumps(rt_result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
dict(data_records=len(rt_data), data_mismatches=sum(not r['matching'] for r in rt_data),
     tables=len(rt_xrefs), function_export=rt_export)
