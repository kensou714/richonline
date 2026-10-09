"""独立复验PE、函数块、跳板、RTC、事件字典及资源；只写本专题报告。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[4]
blob=(ROOT/'RnClient.exe').read_bytes()
sha=hashlib.sha256(blob).hexdigest()
assert sha=='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
pe=struct.unpack_from('<I',blob,0x3c)[0]
assert blob[:2]==b'MZ' and blob[pe:pe+4]==b'PE\0\0'
image_base=struct.unpack_from('<I',blob,pe+52)[0]
count=struct.unpack_from('<H',blob,pe+6)[0]
optional=struct.unpack_from('<H',blob,pe+20)[0]
sections=[struct.unpack_from('<IIII',blob,pe+24+optional+40*i+8) for i in range(count)]
counts=Counter()
def load(name): return json.loads((BASE/name).read_text('utf-8'))
def disk(va,size):
    for _,rva,raw_size,offset in sections:
        rel=va-image_base-rva
        if 0<=rel and rel+size<=raw_size: return blob[offset+rel:offset+rel+size]
    return None
def audit(r,unmapped=False):
    va,size=int(r['va'],16),r['size']
    raw=bytes.fromhex(r['idb_hex'])
    assert len(raw)==size and size>0
    actual=disk(va,size)
    if actual is None:
        assert unmapped and r['disk_hex'] is None and r['matching'] is None
        assert any(0<=va-image_base-rva and va-image_base-rva+size<=vs for vs,rva,_,_ in sections)
    else:
        assert raw==actual==bytes.fromhex(r['disk_hex']) and r['matching'] is True,r['va']
    counts['byte_comparisons']+=1
    return va,va+size
review=load('function_review.json')
functions={}
for source in review['sources']:
    data=load(source)
    assert data['disk_sha256']==sha
    for f in data['functions']:
        assert f['va'] not in functions
        functions[f['va']]=f
        assert f['pseudocode'] and f['assembly'] and f['bytes_match_disk'] is True
        chunks=[(int(c['start_va'],16),int(c['end_va'],16)) for c in f['declared_chunks']]
        spans=[audit(r) for r in f['byte_ranges']]
        assert any(a==int(f['va'],16) for a,b in chunks)
        assert all(any(a<=s<e<=b for a,b in chunks) for s,e in spans)
        # 当前原证每个声明块都连续导出；漏字节或漏异常尾块必须使校验失败。
        assert sorted(chunks)==sorted(spans),f['va']
        addresses=[int(i['va'],16) for i in f['assembly']]
        assert len(addresses)==len(set(addresses))
        assert all(any(s<=a<e for s,e in spans) for a in addresses)
        counts['declared_chunks']+=len(chunks)
        counts['instruction_entries']+=len(addresses)
    for thunk in data['thunks']:
        va,_=audit(thunk)
        raw=disk(va,5)
        assert raw[0]==0xe9
        assert va+5+int.from_bytes(raw[1:],'little',signed=True)==int(thunk['target'],16)
        counts['thunks']+=1
assert set(functions)=={f['va'] for f in review['functions']}
assert review['counts']==dict(Counter(f['review_status'] for f in review['functions']))

data=load('data_audit.json')
for r in data['records']: audit(r,unmapped=True)
for r in data['rtc']:
    raw=disk(int(r['site'],16),6)
    assert raw[:2]==b'\x8d\x15' and struct.unpack_from('<I',raw,2)[0]==int(r['fd'],16)
    n,table=struct.unpack('<II',disk(int(r['fd'],16),8))
    assert n==len(r['variables'])
    for index,var in enumerate(r['variables']):
        offset,size,name=struct.unpack('<iII',disk(table+12*index,12))
        assert (offset,size)==(var['offset'],var['size'])
        assert disk(name,len(var['name'])+1)==var['name'].encode('ascii')+b'\0'
for va,s in data['strings'].items():
    raw=bytes.fromhex(s['hex'])
    assert disk(int(va,16),len(raw))==raw
    assert raw[-1]==0

resource=load('resource.json')
raw=(ROOT/resource['source']).read_bytes()
plain=(BASE/'LogFixStr.decoded.bin').read_bytes()
assert hashlib.sha256(raw).hexdigest()==resource['source_sha256']
assert hashlib.sha256(plain).hexdigest()==resource['decoded_sha256']
assert plain.decode('cp950',errors='strict').encode('cp950',errors='strict')==plain
lines=plain.decode('cp950').splitlines()
assert resource['header']==dict(size=64,count=256)
ids=set()
for e in resource['entries']:
    assert e['indx'] not in ids and 0<=e['indx']<256
    ids.add(e['indx'])
    assert bytes.fromhex(e['win32_bytes'])==e['win32'].encode('cp950')
    assert e['required_bytes_with_nul']==len(bytes.fromhex(e['win32_bytes']))+1<=64
    for key in ['indx','win32','linux']:
        assert lines[e[key+'_line']-1].split('=',1)[1].lstrip()==str(e[key])
assert len(ids)==resource['present_entries']==72
assert resource['max_required_bytes']==max(e['required_bytes_with_nul'] for e in resource['entries'])

events=load('event_dictionary.json')['events']
assert [e['event'] for e in events]==list(range(64))+[128]
targets=struct.unpack('<64I',disk(0x7DDD39,256))
assert list(targets)==[int(t,16) for t in data['switch_targets']]
for event in events:
    if event['event']<64: assert int(event['branch_va'],16)==targets[event['event']]
    fmt=data['strings'][event['format_va']]['ascii']
    assert fmt==event['format'] and fmt.endswith('\n')
    assert event['channel']==('Game' if event['event']==128 else 'Sys')
    assert all(a['index'] in ids for a in event['arguments'] if a['kind']=='resource')
    assert event['minimum_record_bytes']<=12
assert len(review['producer_map'])==27
documents=sorted(BASE.parent.glob('*.txt'))
for document in documents:
    for number,line in enumerate(document.read_text('utf-8').splitlines(),1):
        assert not line.strip() or line.startswith('//'),(document.name,number)
result=dict(passed=True,disk_sha256=sha,unique_declared_functions=len(functions),counts=dict(counts),
            review_status_counts=review['counts'],rtc_records=len(data['rtc']),data_records=len(data['records']),
            events=len(events),resource_entries=len(ids),documents=len(documents),
            runtime_validation=False,full_dependency_closure=False,
            review_not_evaluated_by_this_validator=True,
            limitation='静态字节、结构与资源一致，不替代动态日志写入、错误路径或完整UI/网络依赖验证。')
(BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
