"""只读PE核验；窗口字节/ABI分支/完整函数块/候选原证一致。"""
from pathlib import Path
import json
import struct
import hashlib

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[3]
blob=(ROOT/'RnClient.exe').read_bytes()
sha=hashlib.sha256(blob).hexdigest()
pe=struct.unpack_from('<I',blob,0x3c)[0]
count=struct.unpack_from('<H',blob,pe+6)[0]
opts=struct.unpack_from('<H',blob,pe+20)[0]
imagebase=struct.unpack_from('<I',blob,pe+52)[0]
sections=[struct.unpack_from('<IIII',blob,pe+24+opts+40*i+8) for i in range(count)]
def disk(va,size):
    ea=int(va,16) if isinstance(va,str) else va
    for vs,rva,rawsize,off in sections:
        rel=ea-imagebase-rva
        if 0<=rel and rel+size<=rawsize:
            return blob[off+rel:off+rel+size]
    raise ValueError(hex(ea))
def check(row):
    assert row['matching'] and disk(row['va'],row['size']).hex()==row['idb_hex']==row['disk_hex'],row['va']
data=json.loads((BASE/'证据/未声明窗口与全段候选.json').read_text(encoding='utf-8'))
assert data['disk_sha256']==sha
assert [(w['va'],w['end_va']) for w in data['windows']]==[('0x8e14f0','0x8e1542'),('0x8e15f0','0x8e160f')]
for w in data['windows']:
    check(w['byte_range']);check(w['thunk'])
    for row in w['boundary_checks']:check(row)
    assert w['kind']=='未声明代码窗口' and not w['thunk_xrefs']
    assert w['entry_xrefs']==[dict(source=w['thunk']['va'],type=19)]
    code=bytes.fromhex(w['thunk']['idb_hex'])
    assert code[0]==0xe9 and int(w['thunk']['va'],16)+5+struct.unpack('<i',code[1:])[0]==int(w['va'],16)
    a=w['assembly']
    assert int(a[0]['va'],16)==int(w['va'],16)
    assert all(int(x['va'],16)+x['size']==int(y['va'],16) for x,y in zip(a,a[1:]))
    assert int(a[-1]['va'],16)+a[-1]['size']==int(w['end_va'],16)
assert disk(0x8e14f8,8).hex()=='39beac0100007437'
assert disk(0x8e151d,4).hex()=='85ff7e16'
assert disk(0x8e1521,7).hex()=='8d04bd00000000'
assert disk(0x8e153f,3).hex()=='c20400'
assert disk(0x8e15f0,31).hex()=='8b4424088b91ac0100003bc27f0e8b89a80100008b542404895481fcc20800'
for row in data['field_candidates']:check(row['bytes'])
assert len(data['field_candidates'])==43
assert sum(0x8e0000<=int(r['va'],16)<0x910000 for r in data['field_candidates'])==15
for row in data['pointer_occurrences']:
    needle=struct.pack('<I',int(row['target'],16))
    matches=[]
    for vs,rva,rawsize,off in sections:
        at=blob.find(needle,off,off+rawsize)
        while at!=-1:
            matches.append(dict(va=hex(imagebase+rva+at-off),file_offset=hex(at)))
            at=blob.find(needle,at+1,off+rawsize)
    assert row['occurrences']==matches==[]
raw=json.loads((BASE/'证据/构造释放复制与移动复用.json').read_text(encoding='utf-8'))
assert raw['disk_sha256']==sha
for f in raw['functions']:
    assert f['bytes_match_disk']
    for r in f['byte_ranges']+f['chunk_byte_ranges']:check(r)
    assert {(c['start_va'],int(c['end_va'],16)-int(c['start_va'],16)) for c in f['declared_chunks']}=={(r['va'],r['size']) for r in f['chunk_byte_ranges']}
for r in raw['thunks']:check(r)
review=json.loads((BASE/'function_review.json').read_text(encoding='utf-8'))
assert {r['va'] for r in review['functions']}=={f['va'] for f in raw['functions']}
assert {r['va'] for r in review['code_windows']}=={w['va'] for w in data['windows']}
for r in review['code_windows']+review['functions']:
    assert r['status'] and r['conclusion'] and r['unknown'] and r['evidence']
    for p in r['evidence']:assert (BASE/p).is_file()
for p in BASE.glob('*.txt'):
    assert all(not s.strip() or s.startswith('//') for s in p.read_text(encoding='utf-8').splitlines()),p.name
result=dict(scope='静态字节核验，不等于业务可达或漏洞复现',disk_sha256=sha,undeclared_windows=2,
    window_bytes=sum(w['byte_range']['size'] for w in data['windows']),window_instructions=sum(len(w['assembly']) for w in data['windows']),
    entry_thunks=2,declared_dependency_functions=len(raw['functions']),dependency_chunks=sum(len(f['declared_chunks']) for f in raw['functions']),
    dependency_bytes=sum(r['size'] for f in raw['functions'] for r in f['chunk_byte_ranges']),dependency_thunks=len(raw['thunks']),
    candidate_instructions=43,control_candidates=15,confirmed_direct_callers=0)
(BASE/'专题验证.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
