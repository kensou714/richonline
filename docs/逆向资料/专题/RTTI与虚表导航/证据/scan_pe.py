"""只读扫描32位MSVC RTTI导航；结构验证不等于类型业务或虚函数语义恢复。"""
from pathlib import Path
from collections import Counter,defaultdict
import hashlib
import json
import struct
import re

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[4]
EXPECTED='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
blob=(ROOT/'RnClient.exe').read_bytes()
assert hashlib.sha256(blob).hexdigest()==EXPECTED
pe=struct.unpack_from('<I',blob,0x3c)[0]
assert blob[pe:pe+4]==b'PE\0\0'
image_base=struct.unpack_from('<I',blob,pe+52)[0]
count=struct.unpack_from('<H',blob,pe+6)[0]
optional=struct.unpack_from('<H',blob,pe+20)[0]
assert struct.unpack_from('<H',blob,pe+24)[0]==0x10b
sections=[]
for i in range(count):
    off=pe+24+optional+40*i
    name=blob[off:off+8].rstrip(b'\0').decode('ascii')
    vs,rva,rs,ro=struct.unpack_from('<IIII',blob,off+8)
    flags=struct.unpack_from('<I',blob,off+36)[0]
    sections.append(dict(name=name,va=image_base+rva,virtual_size=vs,raw_size=rs,raw_offset=ro,flags=flags))
def mapped(va,size=1):
    return next((s for s in sections if s['va']<=va and va+size<=s['va']+s['raw_size']),None)
def disk(va,size):
    s=mapped(va,size)
    if s is None: raise ValueError('地址无磁盘映射 '+hex(va))
    start=s['raw_offset']+va-s['va']
    return blob[start:start+size]
def ints(va,n):return struct.unpack('<'+'I'*n,disk(va,n*4))
def signed(v):return v-0x100000000 if v>=0x80000000 else v
def executable(va):
    s=mapped(va)
    return s is not None and bool(s['flags']&0x20000000)
def zstr(va,limit=512):
    out=bytearray()
    for i in range(limit):
        x=disk(va+i,1)
        if x==b'\0':return bytes(out)
        out.extend(x)
    raise ValueError('字符串未终止')
records={}
def audit(va,size,kind):
    records[(va,size)]=dict(va=hex(va),size=size,kind=kind,disk_hex=disk(va,size).hex())

names=json.loads((ROOT/'docs/逆向资料/全量分析/names.json').read_text('utf-8'))
name_map={int(n['va'],16):n['name'] for n in names}
type_descriptors={}
type_failures=[]
for s in sections:
    if s['flags']&0x20000000:continue
    raw=blob[s['raw_offset']:s['raw_offset']+s['raw_size']]
    for match in re.finditer(rb'\.\?A[VU]',raw):
        va=s['va']+match.start()-8
        try:
            assert va%4==0,'类型描述器不对齐'
            vftable,spare=ints(va,2)
            name=zstr(va+8).decode('ascii')
            assert name.endswith('@@'),'类型名后缀不符'
            assert mapped(vftable,4) and executable(ints(vftable,1)[0]),'type_info虚表入口非代码'
            assert spare==0,'spare非0，需运行态另核'
            type_descriptors[va]=dict(va=hex(va),type_info_vtable=hex(vftable),spare=spare,
                decorated_name=name,ida_name=name_map.get(va),status='类型描述器结构已验证；尚无类业务结论')
            audit(va,8+len(name)+1,'TypeDescriptor')
        except (AssertionError,ValueError,UnicodeDecodeError) as e:
            type_failures.append(dict(va=hex(va),reason=str(e)))

references=defaultdict(list)
data_words=[]
for s in sections:
    if s['flags']&0x20000000:continue
    for offset in range(0,s['raw_size']-3,4):
        va=s['va']+offset
        value=ints(va,1)[0]
        references[value].append(va)
        data_words.append((va,value))

hierarchies={}
def hierarchy(va):
    if va in hierarchies:return hierarchies[va]
    signature,attrs,n,array=ints(va,4)
    assert signature==0,'CHD signature非0'
    assert attrs<=7,'CHD attributes超出已知mask7'
    assert 0<n<=512,'CHD base数量越界'
    descriptors=ints(array,n)
    bases=[]
    for pointer in descriptors:
        td,contained,mdisp,pdisp,vdisp,attributes=ints(pointer,6)
        assert td in type_descriptors,'BCD TypeDescriptor未通过验证'
        assert contained<n,'BCD contained超过层级数量'
        assert attributes<=0x7f,'BCD属性超出已知mask'
        assert signed(pdisp)==-1 or 0<=signed(pdisp)<0x100000,'BCD pdisp异常'
        bases.append(dict(va=hex(pointer),type_descriptor=hex(td),contained_bases=contained,
                          pmd=dict(mdisp=signed(mdisp),pdisp=signed(pdisp),vdisp=signed(vdisp)),attributes=attributes))
        audit(pointer,24,'BaseClassDescriptor前24字节')
    assert bases[0]['contained_bases']==n-1,'根BCD不覆盖全部base'
    audit(va,16,'ClassHierarchyDescriptor')
    audit(array,n*4,'BaseClassArray')
    row=dict(va=hex(va),signature=signature,attributes=attrs,base_count=n,base_array=hex(array),bases=bases)
    hierarchies[va]=row
    return row

locators={}
col_failures=[]
for td in type_descriptors:
    for site in references.get(td,[]):
        col=site-12
        try:
            signature,offset,cd_offset,type_va,chd=ints(col,5)
            assert signature==0,'COL signature非0'
            assert offset<0x100000 and cd_offset<0x100000,'COL对象偏移异常'
            h=hierarchy(chd)
            assert int(h['bases'][0]['type_descriptor'],16)==td,'COL类型与首BCD不一致'
            assert h['bases'][0]['pmd']==dict(mdisp=0,pdisp=-1,vdisp=0),'根PMD非(0,-1,0)'
            locators[col]=dict(va=hex(col),signature=signature,offset=offset,cd_offset=cd_offset,
                              type_descriptor=hex(type_va),hierarchy=hex(chd),status='COL完整结构链已验证')
            audit(col,20,'CompleteObjectLocator')
        except (AssertionError,ValueError,struct.error) as e:
            col_failures.append(dict(type_descriptor=hex(td),reference_site=hex(site),candidate_col=hex(col),reason=str(e)))

vftables=[]
for col,row in locators.items():
    for site in references.get(col,[]):
        va=site+4
        if not mapped(va,4) or not executable(ints(va,1)[0]):continue
        entries=[]
        for index in range(1024):
            slot=va+4*index
            if not mapped(slot,4):break
            target=ints(slot,1)[0]
            if not executable(target):break
            entries.append(dict(slot=hex(slot),target=hex(target)))
        assert entries
        audit(site,4+len(entries)*4,'COL指针与连续虚函数入口前缀')
        vftables.append(dict(va=hex(va),locator=hex(col),type_descriptor=row['type_descriptor'],
                            object_offset=row['offset'],entries=entries,
                            boundary='到首个非代码指针；长度只作导航前缀，未证明全部虚函数槽',
                            status='RTTI结构链及至少一个代码入口已验证；虚函数语义未审阅'))

heuristic=[]
known={int(v['va'],16) for v in vftables}
run=[]
def commit():
    if len(run)>=3 and run[0][0] not in known:
        heuristic.append(dict(va=hex(run[0][0]),entries=[dict(slot=hex(a),target=hex(v)) for a,v in run],
                              status='启发式代码地址数组；无RTTI确认，不计语义审阅',
                              preceding_dword=hex(ints(run[0][0]-4,1)[0]) if mapped(run[0][0]-4,4) else None))
for va,value in data_words:
    if run and va!=run[-1][0]+4:commit();run=[]
    if executable(value):run.append((va,value))
    else:commit();run=[]
commit()

result=dict(disk_sha256=EXPECTED,image_base=hex(image_base),sections=sections,
            scope='PE32静态导航；未重命名IDB，未把扫描项算作函数业务审阅',
            type_descriptors=list(type_descriptors.values()),locators=list(locators.values()),
            hierarchies=list(hierarchies.values()),vftables=vftables,
            heuristic_arrays=heuristic,rejected_type_candidates=type_failures,rejected_col_candidates=col_failures,
            rejection_counts=dict(Counter(r['reason'] for r in col_failures)),data_records=list(records.values()))
(BASE/'rtti_scan.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(type_descriptors=len(type_descriptors),locators=len(locators),hierarchies=len(hierarchies),
                     rtti_vftables=len(vftables),heuristic_arrays=len(heuristic),rejected_col_candidates=len(col_failures),
                     rejected_type_candidates=len(type_failures),data_records=len(records)),ensure_ascii=True))
