"""磁盘原证、控制转移、窗口指令边界、尺寸状态模型及中文格式核验。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
from model import verify

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[4]
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
load=lambda n:json.loads((BASE/n).read_text('utf-8'))
blob=(ROOT/'RnClient.exe').read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
nt=struct.unpack_from('<I',blob,0x3C)[0];opt=nt+24
base=struct.unpack_from('<I',blob,opt+28)[0]
sections=[]
for i in range(struct.unpack_from('<H',blob,nt+6)[0]):
    at=opt+struct.unpack_from('<H',blob,nt+20)[0]+40*i
    rva,size,offset=struct.unpack_from('<III',blob,at+12)
    sections.append((base+rva,size,offset))
def disk(a,n):
    for start,size,offset in sections:
        if start<=a and a+n<=start+size:return blob[offset+a-start:offset+a-start+n]
    raise AssertionError((hex(a),n))
counts=Counter();bridges={}
def record(r):
    raw=disk(int(r['va'],16),r['size'])
    assert raw.hex()==r['idb_hex']
    if 'disk_hex' in r:assert raw.hex()==r['disk_hex'] and r['matching'] is True
    counts['byte_records']+=1
    return raw
def bridge(r):
    raw=record(r);a=int(r['va'],16)
    assert raw[0]==0xE9 and a+5+struct.unpack_from('<i',raw,1)[0]==int(r['target'],16)
    bridges[a]=r
sources=[load('functions_raw.json'),load('callbacks_raw.json')]
functions=[f for s in sources for f in s['functions']]
assert len(functions)==len({f['va'] for f in functions})==20
for s in sources:
    assert s['disk_sha256']==SHA
    for r in s['thunks']:bridge(r)
for f in functions:
    assert f['bytes_match_disk'] is True
    assert len(f['declared_chunks'])==len(f['chunk_byte_ranges'])
    for name in ['byte_ranges','chunk_byte_ranges']:
        for r in f[name]:record(r)
    for c,r in zip(f['declared_chunks'],f['chunk_byte_ranges']):
        assert c['start_va']==r['va'] and int(c['end_va'],16)-int(c['start_va'],16)==r['size']
    for i in f['assembly']:
        a=int(i['va'],16)
        assert any(int(c['start_va'],16)<=a<int(c['end_va'],16) for c in f['declared_chunks'])
    for call in f['calls']:
        a=int(call['site'],16);raw=disk(a,6)
        if raw[0] in (0xE8,0xE9):assert a+5+struct.unpack_from('<i',raw,1)[0]==int(call['target'],16)
        elif raw[:2]==b'\xff\x15':
            assert struct.unpack_from('<I',raw,2)[0]==int(call['target'],16)
        else:
            # 两次lstrlenA通过EDI调用；此前8B3D从同一IAT槽装载，不伪称E8直接调用。
            assert a in {0x8E1E27,0x8E1E36} and raw[:2]==b'\xff\xd7'
            source=disk(0x8E1E20,6)
            assert source[:2]==b'\x8b\x3d' and struct.unpack_from('<I',source,2)[0]==int(call['target'],16)
            counts['register_import_calls']+=1
    counts['instructions']+=len(f['assembly'])
    counts['declared_chunks']+=len(f['declared_chunks'])
    counts['chunk_bytes']+=sum(r['size'] for r in f['chunk_byte_ranges'])
nav=load('navigation.json')
for r in nav['bridges']+load('callback_bridges.json'):bridge(r)
for r in nav['inbound']:
    a=int(r['site'],16);raw=bytes.fromhex(r['idb_hex'])
    assert disk(a,len(raw))==raw
    if r['kind'] in (16,17,18,19):
        assert raw[0] in (0xE8,0xE9) and a+5+struct.unpack_from('<i',raw,1)[0]==int(r['target'],16)
    counts['navigation_records']+=1
# 用已有完整调用者的声明指令列表核窗口边界，防止get_between从指令中部启动。
prior=json.loads((BASE.parents[1]/'列表控件行记录与布局/证据/list_dependencies.json').read_text('utf-8'))
assert prior['disk_sha256']==SHA
all_instructions={i['va']:i['text'] for f in prior['functions'] for i in f['assembly']}
for w in nav['windows']:
    a=int(w['start_va'],16);end=int(w['end_va'],16)
    assert end-a==w['size'] and disk(a,w['size']).hex()==w['idb_hex']
    assert w['assembly'][0]['va']==w['start_va']
    assert w['end_va'] in all_instructions
    for ins in w['assembly']:assert all_instructions[ins['va']]==ins['text']
    expected=[x for x in all_instructions if a<=int(x,16)<end]
    assert {i['va'] for i in w['assembly']}==set(expected)
    last=w['assembly'][-1]
    assert int(last['va'],16)+5==end and disk(int(last['va'],16),1)==b'\xe8'
    counts['window_bytes']+=w['size'];counts['window_instructions']+=len(w['assembly'])
data={r['va']:record(r) for r in nav['data']}
assert data['0xa67aa0'].decode('gbk')=='获得图片大小失败\n\0'
assert data['0xa67ab8'].decode('gbk')=='没有指定获得图片大小的函数\n\0'
asm={int(f['va'],16):'\n'.join(i['text'] for i in f['assembly']) for f in functions}
for va,tokens in {0x8E2200:['mov     [eax+0Ch], edx','call    sub_600ACC','retn    8'],
0x8E1FB0:['[esi], 5','[esi+0Ch]','[ebx+10h]','[ebx+14h]','add     esp, 24h','add     esp, 20h','[edi+160h]','[edi+164h]'],
0x8E1C70:['[edx+2Ch]','0FFFFFFFFh','[edi+181h]','[edi+180h]'],
0x8E1D10:['[ecx], 5','[ecx+eax*8+1Ch]'],
0x8E1DB0:['j___stricmp','operator delete','operator new','rep movsb'],
0x6E4D00:['mov     al, 1','sub_60C372','sub_608623'],
0x6E4D40:['mov     al, 1','sub_60C372','sub_608623'],
0x6E51D0:['[eax+84h]','0FFFFFFFFh','sub_60C3C7'],
0x8E1930:['mov     esi, ecx','push    2','push    3','[edi+0ACh]'],
0x8E8620:['[ecx+2Ch], eax'],0x8E86A0:['[ecx+10h], eax'],0x8E86C0:['[ecx+14h], eax']}.items():
    assert all(t in asm[va] for t in tokens),(hex(va),tokens)
model=verify()
assert json.loads(json.dumps(model))==load('model_results.json')
review=load('function_review.json')
assert review['counts']=={'局部语义已审阅':15,'部分分析':5} and review['reused_count']==5
assert {f['va'] for f in functions}=={f['va'] for f in review['functions']}
for f in review['functions']:
    assert f['status']==f['review_status'] and f['full_dependency_closure'] is False
    assert bool(f['reviewed_chunks'])==(f['status']=='局部语义已审阅')
    assert f['conclusion'] and f['unknown'] and all((BASE/p).exists() for p in f['evidence'])
docs=list(BASE.parent.glob('*.txt'))
for p in docs:assert all(not line or line.startswith('//') for line in p.read_text('utf-8').splitlines())
result=dict(status='通过',disk_sha256=SHA,functions=20,review_counts=review['counts'],reused_functions=5,
            documents=len(docs),unique_bridges=len(bridges),data_records=len(data),checks=dict(counts),
            state_model_cases=model['state_cases'],refresh_model_cases=len(model['refresh_cases']),
            caveat='静态局部契约；回调重入、全局生命周期和实机渲染未验证')
(BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
print(json.dumps(result,ensure_ascii=True))
