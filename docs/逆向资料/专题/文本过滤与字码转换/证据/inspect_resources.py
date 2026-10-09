"""只读解包四份资源，保留逐记录字节并枚举全部 16 位输入的查表边界。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import struct
import lzokay

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[4]
def dump(name,value):
    (BASE/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def unpack(name):
    raw=(ROOT/'Data'/name).read_bytes()
    packed=bytes((x-raw[0])&255 for x in raw[1:])
    n,m=struct.unpack_from('<II',packed)
    assert m==len(packed)-8
    plain=lzokay.decompress(packed[8:],n)
    assert len(plain)==n
    (BASE/(name+'.decoded.bin')).write_bytes(plain)
    return plain,dict(path='Data/'+name,source_size=len(raw),source_sha256=hashlib.sha256(raw).hexdigest(),
                      key=raw[0],compressed_size=m,decoded_size=n,decoded_sha256=hashlib.sha256(plain).hexdigest())
resources=[]
for name in ['Filter.kpd','FilterN.kpd','FliterN.kpd']:
    plain,record=unpack(name)
    entries=[]
    for match in re.finditer(rb'(?m)^str[ \t]*=[ \t]*(.*)\r?$',plain):
        b=match.group(1).rstrip(b'\r')
        e=dict(offset=match.start(1),bytes=b.hex(),length=len(b))
        for codec in ['cp950','gbk']:
            try:
                text=b.decode(codec);e[codec]=text;e[codec+'_roundtrip']=text.encode(codec)==b
            except UnicodeError:e[codec+'_roundtrip']=False
        entries.append(e)
    record.update(section_count=len(re.findall(rb'\[ITEM\]',plain)),entries=entries,
                  empty_entries=sum(e['length']==0 for e in entries),
                  max_entry_bytes=max((e['length'] for e in entries),default=0),
                  over_slot_entries=sum(e['length']>63 for e in entries),
                  cp950_roundtrip=sum(e['cp950_roundtrip'] for e in entries),
                  gbk_roundtrip=sum(e['gbk_roundtrip'] for e in entries))
    resources.append(record)
table,record=unpack('ChsTb.kpd')
assert len(table)==0x18964
tables=[]
for title,start,rows,cols,low in [('前向',0,87,94,0xA1),('反向',0x7fc8,89,191,0x40)]:
    entries=[]
    for row in range(rows):
        for col in range(cols):
            at=start+(row*cols+col)*4
            b=table[at:at+4]
            entries.append(dict(offset=at,grid_input=f'{row+0xa1:02x}{col+low:02x}',source=b[:2].hex(),target=b[2:].hex()))
    counts=Counter(e['target'] for e in entries)
    tables.append(dict(name=title,offset=start,rows=rows,cols=cols,record_size=4,
                       source_matches_grid=sum(e['source']==e['grid_input'] for e in entries),
                       zero_targets=counts['0000'],question_targets=counts['3f3f'],entries=entries))
record['tables']=tables
resources.append(record)
dump('resources.json',resources)
audits=[]
for direction,predicate,start,cols,low,limit in [
    ('前向',lambda x:0xA1A1<=x<=0xA9FE or 0xB0A1<=x<=0xF7FE,0,94,0xa1,0x7fc8),
    ('反向',lambda x:0xA140<=x<=0xA3FE or 0xA440<=x<=0xC67E or 0xC940<=x<=0xF9FE,0x7fc8,191,0x40,0x18964)]:
    accepted=[];invalid=[];outside=[];zero=[];aliases=[]
    for value in range(65536):
        if not predicate(value):continue
        hi,lo=divmod(value,256)
        at=start+((hi-0xa1)*cols+lo-low)*4
        accepted.append(value)
        if not low<=lo<=0xfe:invalid.append(value)
        if not (start<=at and at+4<=limit):
            outside.append(dict(input=hex(value),offset=at))
            continue
        if table[at:at+2]!=bytes([hi,lo]):aliases.append(value)
        if table[at+2:at+4]==b'\0\0':zero.append(value)
    audits.append(dict(direction=direction,accepted=len(accepted),invalid_tail_accepted=len(invalid),
                       invalid_tail_examples=[hex(x) for x in invalid[:8]],outside_region=outside,
                       source_grid_alias_count=len(aliases),zero_target_inputs=len(zero),
                       zero_examples=[hex(x) for x in zero[:8]]))
dump('mapping_boundary.json',audits)
print(json.dumps([({k:v for k,v in r.items() if k not in ['entries','tables']}) for r in resources],ensure_ascii=True))
print(json.dumps(audits,ensure_ascii=True))
