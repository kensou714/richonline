"""在当前 IDA 租约中只读导出文本过滤、字码转换和调用点。"""
from pathlib import Path
import json
import struct
import hashlib

TF_ROOT = Path('F:/大富翁online/Richonline')
TF_BASE = TF_ROOT/'docs/逆向资料/专题/文本过滤与字码转换/证据'
exec((TF_ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'))
tf_core = [0x628EF0,0x64C460,0x64C490,0x64C510,0x64C770,0x64F220,
           0x64C9E0,0x64CAE0,0x647610,0x64CDC0,0x627160,0x818D70,
           0x818EA0,0x818F10,0x818FA0,0x8190B0,0x64ED90,0x64F000,
           0x64F030,0x81C450,0x623AD0,0x623EE0,0x6AAB50,0x6C14E0,
           0x8198E0,0x81B4C0,0x81B7F0,0x81AD80,0x9228E0]
print(export_group(db,tf_core,TF_BASE/'functions_raw.json'))
print(export_group(db,[0x648C20,0x64A9F0],TF_BASE/'caller_functions.json'))
tf_blob=(TF_ROOT/'RnClient.exe').read_bytes()
tf_pe=struct.unpack_from('<I',tf_blob,0x3c)[0]
tf_sections=[]
for j in range(struct.unpack_from('<H',tf_blob,tf_pe+6)[0]):
    at=tf_pe+24+struct.unpack_from('<H',tf_blob,tf_pe+20)[0]+j*40
    rva,n,off=struct.unpack_from('<III',tf_blob,at+12)
    tf_sections.append((rva+0x400000,n,off))
def tf_identity(a,n):
    b=db.bytes.get_bytes_at(a,n)
    raw=next((tf_blob[off+a-start:off+a-start+n] for start,size,off in tf_sections
              if start<=a and a+n<=start+size),None)
    return dict(va=hex(a),size=n,idb_hex=b.hex(),disk_hex=raw.hex() if raw is not None else None,
                matching=raw==b if raw is not None else None,
                storage='磁盘映射' if raw is not None else '无磁盘原始区；仅IDB当前值')
tf_nav=[]
for target in [0x600F90,0x608597,0x604163,0x601850,0x60C6E2,0x603AF6,0x608A79]:
    refs=[]
    for x in db.xrefs.to_ea(target):
        a=x.from_ea
        ins=db.instructions.get_at(a)
        f=db.functions.get_at(a)
        context=[]
        if f:
            arr=[i for c in db.functions.get_chunks(f) for i in db.instructions.get_between(c.start_ea,c.end_ea)]
            idx=next((i for i,v in enumerate(arr) if v.ea==a),None)
            if idx is not None:
                context=[dict(va=hex(i.ea),text=db.instructions.get_disassembly(i),bytes=tf_identity(i.ea,i.size))
                         for i in arr[max(0,idx-10):idx+5]]
        refs.append(dict(site=hex(a),kind=int(x.type),function=hex(f.start_ea) if f else None,
                         disassembly=db.instructions.get_disassembly(ins) if ins else None,
                         bytes=tf_identity(a,ins.size if ins else 4),context=context))
    tf_nav.append(dict(target=hex(target),thunk=tf_identity(target,5),references=refs))
tf_data=[]
for a,n in [(0xA22A10,4),(0xA22A24,4),(0xA67342,2),(0xA76738,4),(0xABABB8,4),(0xABAA40,32)]:
    tf_data.append(tf_identity(a,n))
# 只从已导出的加载函数指令引用中提取 ASCII 字面量；不把未知数据解释为字符串。
for ea in [0x623AD0,0x623EE0,0x64C510,0x64C770]:
    f=db.functions.get_at(ea)
    for c in db.functions.get_chunks(f):
        for ins in db.instructions.get_between(c.start_ea,c.end_ea):
            for x in db.xrefs.from_ea(ins.ea):
                a=x.to_ea
                if x.type in (1,2,3) and 0xA00000<=a<0xA70000:
                    b=db.bytes.get_bytes_at(a,260).split(b'\0')[0]
                    if b and all(32<=v<127 for v in b) and (b.startswith(b'Data') or b in [b'ITEM',b'str']):
                        r=tf_identity(a,len(b)+1);r['ascii']=b.decode('ascii');tf_data.append(r)
tf_data=list({r['va']:r for r in tf_data}.values())
out=dict(disk_sha256=hashlib.sha256(tf_blob).hexdigest(),targets=tf_nav,data_records=tf_data)
(TF_BASE/'navigation_data.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(dict(navigation=sum(len(t['references']) for t in tf_nav),data=len(tf_data)))
