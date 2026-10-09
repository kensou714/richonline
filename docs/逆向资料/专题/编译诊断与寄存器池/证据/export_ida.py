"""只读导出编译诊断小群、寄存器池和出处引用；不修改 IDB。"""
from pathlib import Path
import json
import struct
import hashlib

CD_ROOT = Path('F:/大富翁online/Richonline')
CD_BASE = CD_ROOT/'docs/逆向资料/专题/编译诊断与寄存器池/证据'
exec((CD_ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'))
cd_core = [0x995011,0x993EC8,0x9CAD79,0x9CB6FC,0x9CB700,0x9CA930,
           0x9CAA68,0x9CAF88,0x9D0A78,0x994DE3,0x98E8C1,0x98E170]
print(export_group(db,cd_core,CD_BASE/'functions_raw.json'))
print(export_group(db,[0xA0B1AA,0x9916F1],CD_BASE/'identity_callers.json'))
cd_blob = (CD_ROOT/'RnClient.exe').read_bytes()
cd_nt = struct.unpack_from('<I',cd_blob,0x3C)[0]
cd_sections = []
for j in range(struct.unpack_from('<H',cd_blob,cd_nt+6)[0]):
    at = cd_nt+24+struct.unpack_from('<H',cd_blob,cd_nt+20)[0]+j*40
    rva,size,offset = struct.unpack_from('<III',cd_blob,at+12)
    cd_sections.append((rva+0x400000,size,offset))
def cd_bytes(a,n):
    b = db.bytes.get_bytes_at(a,n)
    raw = next((cd_blob[off+a-start:off+a-start+n] for start,size,off in cd_sections
                if start<=a and a+n<=start+size),None)
    return dict(va=hex(a),size=n,idb_hex=b.hex(),disk_hex=raw.hex() if raw is not None else None,
                matching=raw==b if raw is not None else None)
cd_nav = []
for target in [0x6104E0,0x60573E,0x609591,0x6077A0,0x606B75,0x6092FD,0x6126D2,0x60CDD1,0x60A333]:
    refs = []
    for x in db.xrefs.to_ea(target):
        a=x.from_ea;ins=db.instructions.get_at(a);f=db.functions.get_at(a)
        refs.append(dict(site=hex(a),kind=int(x.type),function=hex(f.start_ea) if f else None,
            text=db.instructions.get_disassembly(ins) if ins else None,
            bytes=cd_bytes(a,ins.size if ins else 4)))
    cd_nav.append(dict(target=hex(target),thunk=cd_bytes(target,5),references=refs))
cd_data = []
for a,n in [(0xA51D70,22),(0xA45020,23),(0xA75FE4,4),(0xA6DF58,4),
            (0xA3FF08,8),(0xA2B480,8),(0xA226E0,8)]:
    r=cd_bytes(a,n);r['references']=[dict(site=hex(x.from_ea),kind=int(x.type)) for x in db.xrefs.to_ea(a)]
    cd_data.append(r)
for a in [0x995011,0x9D0A78,0x994DE3,0x98E8C1,0xA0B1AA,0x9916F1]:
    f=db.functions.get_at(a)
    for c in db.functions.get_chunks(f):
        for ins in db.instructions.get_between(c.start_ea,c.end_ea):
            for x in db.xrefs.from_ea(ins.ea):
                if x.type in (1,2,3) and x.to_ea>=0xA00000:
                    b=db.bytes.get_bytes_at(x.to_ea,260).split(b'\0')[0]
                    if b and all(32<=v<127 for v in b):
                        r=cd_bytes(x.to_ea,len(b)+1);r['ascii']=b.decode('ascii')
                        cd_data.append(r)
cd_data=list({r['va']:r for r in cd_data}.values())
out=dict(disk_sha256=hashlib.sha256(cd_blob).hexdigest(),targets=cd_nav,data_records=cd_data)
(CD_BASE/'navigation_data.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(dict(calls=sum(len(t['references']) for t in cd_nav),data=len(cd_data)))
