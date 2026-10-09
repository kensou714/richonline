"""只读导出CRT随机数及选定调用边界；反向引用只是导航。"""
from pathlib import Path
import json
import hashlib
import struct

RN_ROOT = Path('F:/大富翁online/Richonline')
RN_BASE = RN_ROOT / 'docs/逆向资料/专题/随机数状态与取样边界/证据'
assert hashlib.sha256((RN_ROOT/'RnClient.exe').read_bytes()).hexdigest() == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RN_BASE.mkdir(parents=True, exist_ok=True)
exec((RN_ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'))
rn_addresses = [0x9208a0,0x9208c0,0x930940,0x930960,0x930750,0x930760,0x930d40,0x695040,0x695010,0x7d83d0,0x7e1420,0x7eca40,0x7e20a0,
                0x80e6b0,0x80e710,0x81f950,0x623ad0,0x6aa530,0x911ab0,0x913e90,0x914220,0x9157f0]
rn_summary = export_group(db, rn_addresses, str(RN_BASE/'functions_raw.json'))
rn_refs = []
for target in [0x9208a0,0x9208c0,0x608763,0x60ae14,0x60b486,0x60a685,0x6022be]:
    refs = []
    for x in db.xrefs.to_ea(target):
        f = db.functions.get_at(x.from_ea)
        i = db.instructions.get_at(x.from_ea)
        refs.append(dict(site=hex(x.from_ea),kind=int(x.type),function=hex(f.start_ea) if f else None,
                         disassembly=db.instructions.get_disassembly(i) if i else None,
                         size=i.size if i else None,
                         idb_hex=db.bytes.get_bytes_at(x.from_ea,i.size).hex() if i else None))
    rn_refs.append(dict(target=hex(target),references=refs))
rn_navigation = dict(disk_sha256=hashlib.sha256((RN_ROOT/'RnClient.exe').read_bytes()).hexdigest(),
                     scope='已知rand/srand入口及跳板反向引用；未声明地址单列，不计函数数',
                     targets=rn_refs, export_summary=rn_summary)
rn_blob = (RN_ROOT/'RnClient.exe').read_bytes()
rn_pe = struct.unpack_from('<I',rn_blob,0x3c)[0]
rn_base = struct.unpack_from('<I',rn_blob,rn_pe+52)[0]
rn_optional = struct.unpack_from('<H',rn_blob,rn_pe+20)[0]
rn_sections=[]
for rn_i in range(struct.unpack_from('<H',rn_blob,rn_pe+6)[0]):
    rn_at=rn_pe+24+rn_optional+rn_i*40
    rn_rva,rn_size,rn_offset=struct.unpack_from('<III',rn_blob,rn_at+12)
    rn_sections.append((rn_base+rn_rva,rn_size,rn_offset))
def rn_identity(va,size):
    disk=None
    for start,n,offset in rn_sections:
        if start<=va and va+size<=start+n:
            disk=rn_blob[offset+va-start:offset+va-start+size]
            break
    live=db.bytes.get_bytes_at(va,size)
    return dict(va=hex(va),size=size,idb_hex=live.hex() if live else None,
                disk_hex=disk.hex() if disk is not None else None,
                matching=live==disk if disk is not None else None)
rn_data=[]
for a,s in [(0xa33cc4,'kernel32.dll'),(0xa33cb8,'FlsAlloc'),(0xa33ca8,'FlsGetValue'),
            (0xa33c98,'FlsSetValue'),(0xa33c8c,'FlsFree'),(0xa31720,'Lower'),(0xa316e8,'Upper')]:
    r=rn_identity(a,len(s)+1)
    assert r['disk_hex']==(s.encode('ascii')+b'\0').hex()
    r.update(kind='正文引用ASCII字面量',text=s)
    rn_data.append(r)
rn_data.append(dict(rn_identity(0xa69d94,4),kind='CRT存储槽索引初值'))
rn_float=rn_identity(0xa23388,4)
rn_float.update(kind='浮点取样除数',value=struct.unpack('<f',bytes.fromhex(rn_float['disk_hex']))[0])
assert rn_float['value']==100.0
rn_data.append(rn_float)
for t in rn_refs:
    for x in t['references']:
        if x['size']:
            x['bytes']=rn_identity(int(x['site'],16),x['size'])
rn_navigation['data_records']=rn_data
rn_tls_thunk=rn_identity(0x60e519,5)
rn_tls_raw=bytes.fromhex(rn_tls_thunk['disk_hex'])
assert rn_tls_raw[0]==0xe9
rn_tls_thunk['target']=hex(0x60e519+5+int.from_bytes(rn_tls_raw[1:],'little',signed=True))
assert rn_tls_thunk['target']=='0x930750'
rn_navigation['address_taken_thunks']=[rn_tls_thunk]
(RN_BASE/'reverse_navigation.json').write_text(json.dumps(rn_navigation,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(rn_summary)
