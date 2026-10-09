"""只读当前PE与归档IDA字节；核完整chunks、27项注册映射与26项复制事实。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import re

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
        if 0<=rel and rel+size<=rawsize: return blob[off+rel:off+rel+size]
    raise ValueError(hex(ea))
def check(row):
    assert row['matching'] and disk(row['va'],row['size']).hex()==row['idb_hex']==row['disk_hex'],row['va']
raw_names=['注册与生命周期.json','基础消费者.json','输入复用.json','清理与复制依赖.json','游戏界面桥接.json']
functions,thunks={},{}
for name in raw_names:
    raw=json.loads((BASE/'证据'/name).read_text(encoding='utf-8'))
    assert raw['disk_sha256']==sha
    for f in raw['functions']:
        assert f['bytes_match_disk'] and f['chunks']
        for r in f['byte_ranges']: check(r)
        spans=[(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['byte_ranges']]
        for c in f['chunks']:
            assert any(lo<=int(c['start_va'],16) and int(c['end_va'],16)<=hi for lo,hi in spans),(f['va'],c)
        if f['va'] in functions: assert f['byte_ranges']==functions[f['va']]['byte_ranges']
        functions[f['va']]=f
    for t in raw['thunks']: check(t); thunks[t['va']]=t
data=json.loads((BASE/'证据/事件映射与数据.json').read_text(encoding='utf-8'))
assert data['disk_sha256']==sha
for row in data['data_checks']: check(row)
assert {r['event'] for r in data['events']}==set(range(27))
for row in data['events']:
    n=row['event']
    if row['setter']=='0x8e9c30':
        target=struct.unpack('<I',disk(0x8e9d48+4*(n-4),4))[0]
    else:
        index=disk(0x8e9eec+n,1)[0]
        target=struct.unpack('<I',disk(0x8e9ec0+4*index,4))[0]
    # 两种分支均先取callback到EAX/EDX，再写[ECX+字段]，最后retn8。
    code=disk(target,13)
    assert code[:4] in (b'\x8b\x44\x24\x08',b'\x8b\x54\x24\x08'),hex(target)
    assert code[4:6] in (b'\x89\x81',b'\x89\x91')
    assert struct.unpack('<I',code[6:10])[0]==row['field']
    assert code[10:13]==b'\xc2\x08\x00'
    if row['virtual_offset'] is not None:
        thunk=struct.unpack('<I',disk(0xa305ac+row['virtual_offset'],4))[0]
        code=disk(thunk,5)
        assert code[0]==0xe9
        assert thunk+5+struct.unpack('<i',code[1:])[0]==int(row['consumer'],16)
copy_text='\n'.join(a['text'] for a in functions['0x8e2d80']['assembly'])
ctor_text='\n'.join(a['text'] for a in functions['0x8e0af0']['assembly'])
for off in range(460,568,4):
    token=f'+{off:X}h]'
    assert token in ctor_text
    assert (token in copy_text)==(off!=516)
review=json.loads((BASE/'function_review.json').read_text(encoding='utf-8'))
assert {r['va'] for r in review['functions']}==set(functions)
for r in review['functions']:
    assert r['conclusion'] and r['unknown'] and r['evidence']
    for path in r['evidence']: assert (BASE/path).is_file()
for path in BASE.glob('*.txt'):
    assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines()),path.name
result=dict(scope='静态字节/映射一致性，不代表动态安全或业务验证',disk_sha256=sha,
            functions=len(functions),code_ranges=sum(len(f['byte_ranges']) for f in functions.values()),
            function_bytes=sum(r['size'] for f in functions.values() for r in f['byte_ranges']),
            thunks=len(thunks),data_regions=len(data['data_checks']),events=27,
            copy_omitted_field=516,statuses=dict(Counter(r['review_status'] for r in review['functions'])))
(BASE/'专题验证.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
