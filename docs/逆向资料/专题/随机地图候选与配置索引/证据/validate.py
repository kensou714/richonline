"""核对磁盘PE、全部导出块、桥、导航、常量、资源与离线契约。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
from model import verify, ALLOWED

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[4]
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
load=lambda name:json.loads((BASE/name).read_text('utf-8'))
blob=(ROOT/'RnClient.exe').read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
nt=struct.unpack_from('<I',blob,0x3C)[0]
opt=nt+24
image_base=struct.unpack_from('<I',blob,opt+28)[0]
sections=[]
for i in range(struct.unpack_from('<H',blob,nt+6)[0]):
    at=opt+struct.unpack_from('<H',blob,nt+20)[0]+40*i
    rva,size,offset=struct.unpack_from('<III',blob,at+12)
    sections.append((image_base+rva,size,offset))
def disk(a,n):
    for start,size,offset in sections:
        if start<=a and a+n<=start+size:
            return blob[offset+a-start:offset+a-start+n]
    raise AssertionError((hex(a),n))
counts=Counter()
def record(r):
    raw=disk(int(r['va'],16),r['size'])
    assert raw.hex()==r['idb_hex']
    if 'disk_hex' in r:
        assert raw.hex()==r['disk_hex'] and r['matching'] is True
    counts['byte_records']+=1
    return raw
sources=[load(n) for n in ['functions_raw.json','dependencies_raw.json','supplement_raw.json']]
functions=[f for source in sources for f in source['functions']]
assert len(functions)==len({f['va'] for f in functions})==32
bridges={}
for source in sources:
    assert source['disk_sha256']==SHA
    for thunk in source['thunks']:
        raw=record(thunk)
        a=int(thunk['va'],16)
        assert raw[0]==0xE9 and a+5+struct.unpack_from('<i',raw,1)[0]==int(thunk['target'],16)
        bridges[a]=thunk
for f in functions:
    assert f['bytes_match_disk'] is True
    assert len(f['declared_chunks'])==len(f['chunk_byte_ranges'])
    for field in ['byte_ranges','chunk_byte_ranges']:
        for r in f[field]:record(r)
    for chunk,r in zip(f['declared_chunks'],f['chunk_byte_ranges']):
        assert r['va']==chunk['start_va'] and r['size']==int(chunk['end_va'],16)-int(chunk['start_va'],16)
    for ins in f['assembly']:
        a=int(ins['va'],16)
        assert any(int(c['start_va'],16)<=a<int(c['end_va'],16) for c in f['declared_chunks'])
    for call in f['calls']:
        a=int(call['site'],16);raw=disk(a,5)
        if raw[0] in (0xE8,0xE9):
            assert a+5+struct.unpack_from('<i',raw,1)[0]==int(call['target'],16)
            counts['relative_calls']+=1
        else:
            raw=disk(a,6)
            assert raw[:2]==b'\xff\x15' and struct.unpack_from('<I',raw,2)[0]==int(call['target'],16)
            counts['indirect_import_calls']+=1
    counts['instructions']+=len(f['assembly'])
    counts['declared_chunks']+=len(f['declared_chunks'])
    counts['chunk_bytes']+=sum(r['size'] for r in f['chunk_byte_ranges'])
for target in load('inbound.json'):
    for edge in target['edges']:
        raw=bytes.fromhex(edge['idb_hex']);a=int(edge['site'],16)
        assert disk(a,len(raw))==raw
        if edge['kind'] in (16,17,18,19) and raw[0] in (0xE8,0xE9):
            assert a+5+struct.unpack_from('<i',raw,1)[0]==int(edge['target'],16)
        counts['navigation_records']+=1
data=load('data_raw.json')
for r in data:record(r)
assert disk(0xA239D0,19)==b'Data\\RandomMap.kpd\0'
assert struct.unpack('<4I',disk(0x6AAB34,16))==(0x6AAADC,0x6AAAEE,0x6AAB06,0x6AAAD0)
asm={int(f['va'],16):'\n'.join(i['text'] for i in f['assembly']) for f in functions}
for va,tokens in {0x6A9D50:['548h','558h','568h','578h','588h','598h','5A8h','5B8h','5C8h','80h'],
                  0x6AA530:['idiv    ecx','j__srand','j__rand','timeGetTime'],
                  0x6AA450:['jnb','movzx   edx, al','retn    8'],
                  0x6AAA80:['[ecx]','switch 4 cases','xor     al, al','retn    4'],
                  0x7E9610:['114h','108h','jge','j__strcmp'],
                  0x6BA970:['rep movsd','20h','80h'],
                  0x6B91E0:['mov     [ebp+var_4], ecx','retn    8']}.items():
    assert all(t in asm[va] for t in tokens),(hex(va),tokens)
assert ALLOWED=={0:{0,3},1:{0,1,3},2:{0,1,2,3},3:{3}}
model=verify()
assert model==load('model_results.json') or json.loads(json.dumps(model))==load('model_results.json')
resources=load('resources.json')
for r in resources['resources']:
    raw=(ROOT/r['path']).read_bytes()
    assert len(raw)==r['source_size'] and hashlib.sha256(raw).hexdigest()==r['source_sha256']
    decoded=(BASE/(Path(r['path']).name+'.decoded.bin')).read_bytes()
    assert len(decoded)==r['decoded_size'] and hashlib.sha256(decoded).hexdigest()==r['decoded_sha256']
for group in resources['groups']:
    assert [e['key'] for e in group['entries']]==['map%02d' % i for i in range(1,group['count']+1)]
    assert not group['unconsumed_keys'] and max(e['value_size'] for e in group['entries'])<128
    for e in group['entries']:
        p=ROOT/e['disk_path']
        assert p.is_file()==e['disk_exists']
        if e['disk_exists']:
            raw=p.read_bytes()
            assert hashlib.sha256(raw).hexdigest()==e['disk_sha256']
            summary=e['emp_summary']
            assert len(raw)==summary['file_size'] and summary['mode_offset']==23288
            assert struct.unpack_from('<I',raw,16)[0]==summary['version_at_16']
            assert struct.unpack_from('<I',raw,23288)[0]==summary['mode']
assert [g['count'] for g in resources['groups']]==[16,9,25,22,4,26,3,3,3]
assert resources['total_records']==111 and resources['unique_candidates']==54 and not resources['not_in_maplist']
review=load('function_review.json')
assert review['counts']=={'局部语义已审阅':29,'部分分析':3}
assert {f['va'] for f in review['functions']}=={f['va'] for f in functions}
for f in review['functions']:
    assert f['status']==f['review_status'] and f['full_dependency_closure'] is False
    assert bool(f['reviewed_chunks'])==(f['status']=='局部语义已审阅')
    assert f['conclusion'] and f['unknown'] and all((BASE/p).exists() for p in f['evidence'])
docs=list(BASE.parent.glob('*.txt'))
assert len(docs)>=7
for p in docs:assert all(not line or line.startswith('//') for line in p.read_text('utf-8').splitlines())
result=dict(status='通过',disk_sha256=SHA,functions=32,review_counts=review['counts'],documents=len(docs),
            unique_bridges=len(bridges),data_records=len(data),checks=dict(counts),selection_model_cases=model['selection_cases'],
            resource_records=111,unique_candidates=54,caveat='静态局部原证和模型；无真实客户端验收、外部依赖闭包或补丁')
(BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
print(json.dumps(result,ensure_ascii=True))
