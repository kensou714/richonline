"""独立PE/IDA审阅；仅写独审结果，不建立IDA函数或改变作者原证。"""
import hashlib,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent;TOP=HERE.parent;ROOT=Path(r'F:\大富翁online\Richonline')
def audit(db=None):
    blob=(ROOT/'RnClient.exe').read_bytes();sha=hashlib.sha256(blob).hexdigest()
    assert sha=='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe=struct.unpack_from('<I',blob,60)[0];n=struct.unpack_from('<H',blob,pe+6)[0]
    opt=struct.unpack_from('<H',blob,pe+20)[0];base=struct.unpack_from('<I',blob,pe+52)[0]
    sections=[struct.unpack_from('<IIII',blob,pe+24+opt+40*i+8) for i in range(n)]
    text_sections=[]
    for i,(vs,rva,raw,off) in enumerate(sections):
        if blob[pe+24+opt+40*i:pe+24+opt+40*i+8].rstrip(b'\0')==b'.text':text_sections.append((base+rva,base+rva+vs))
    def disk(va,size):
        for _,rva,raw,off in sections:
            d=va-base-rva
            if 0<=d and d+size<=raw:return blob[off+d:off+d+size]
        raise AssertionError(('未映射',hex(va),size))
    comparisons=0;ranges=set()
    def check(row):
        nonlocal comparisons
        va=int(row['va'],16);size=row['size'];expected=bytes.fromhex(row['idb_hex'])
        assert len(expected)==size and disk(va,size)==expected==bytes.fromhex(row['disk_hex']) and row['matching']
        if db is not None:assert db.bytes.get_bytes_at(va,size)==expected
        comparisons+=1;ranges.add((va,size))
    data=json.loads((HERE/'未声明窗口与全段候选.json').read_text(encoding='utf-8'));assert data['disk_sha256']==sha
    assert [(w['va'],w['end_va']) for w in data['windows']]==[('0x8e14f0','0x8e1542'),('0x8e15f0','0x8e160f')]
    assert text_sections==[(0x5FF000,0xA21A73)]
    window_instructions=0
    for w in data['windows']:
        start,end=int(w['va'],16),int(w['end_va'],16);a=w['assembly']
        assert w['byte_range']['size']==end-start
        for row in [w['byte_range'],w['thunk']]+w['boundary_checks']:check(row)
        assert int(a[0]['va'],16)==start and int(a[-1]['va'],16)+a[-1]['size']==end
        assert all(int(x['va'],16)+x['size']==int(y['va'],16) for x,y in zip(a,a[1:]))
        assert w['entry_xrefs']==[dict(source=w['thunk']['va'],type=19)] and w['thunk_xrefs']==[]
        code=disk(int(w['thunk']['va'],16),5);assert code[0]==0xE9
        assert int(w['thunk']['va'],16)+5+int.from_bytes(code[1:],'little',signed=True)==start
        if db is not None:
            for ins in a:assert db.functions.get_at(int(ins['va'],16)) is None
            actual=[dict(va=hex(i.ea),size=i.size,text=db.instructions.get_disassembly(i)) for i in db.instructions.get_between(start,end)]
            assert actual==a
            for target,key in [(start,'entry_xrefs'),(int(w['thunk']['va'],16),'thunk_xrefs')]:
                assert [dict(source=hex(x.from_ea),type=int(x.type)) for x in db.xrefs.to_ea(target)]==w[key]
            calls=[]
            for ins in db.instructions.get_between(start,end):
                for x in db.xrefs.from_ea(ins.ea):
                    if x.type in (16,17):calls.append(dict(site=hex(ins.ea),target=hex(x.to_ea)))
            assert calls==[{k:c[k] for k in ('site','target')} for c in w['calls']]
        window_instructions+=len(a)
    assert disk(0x8E14F8,8).hex()=='39beac0100007437'
    assert disk(0x8E151D,4).hex()=='85ff7e16'
    assert disk(0x8E1521,7).hex()=='8d04bd00000000'
    assert disk(0x8E153F,3).hex()=='c20400'
    assert disk(0x8E15F0,31).hex()=='8b4424088b91ac0100003bc27f0e8b89a80100008b542404895481fcc20800'
    candidates=data['field_candidates'];assert len(candidates)==43
    assert data['candidate_scan_range']==['0x5ff000','0xa21a73']
    for row in candidates:check(row['bytes'])
    control=[r for r in candidates if 0x8E0000<=int(r['va'],16)<0x910000]
    assert len(control)==15 and sum(r['function'] is None for r in control)==7
    if db is not None:
        actual=[]
        for ins in db.instructions.get_between(0x5FF000,0xA21A73):
            line=db.instructions.get_disassembly(ins)
            if re.search(r'\+(1A8h|1ACh)\]',line,re.I):
                f=db.functions.get_at(ins.ea)
                actual.append(dict(va=hex(ins.ea),function=hex(f.start_ea) if f else None,text=line))
        assert actual==[{k:r[k] for k in ('va','function','text')} for r in candidates]
    for r in data['pointer_occurrences']:
        needle=struct.pack('<I',int(r['target'],16));hits=[]
        for _,rva,raw,off in sections:
            at=blob.find(needle,off,off+raw)
            while at!=-1:
                hits.append(dict(va=hex(base+rva+at-off),file_offset=hex(at)));at=blob.find(needle,at+1,off+raw)
        assert hits==r['occurrences']==[]
    raw=json.loads((HERE/'构造释放复制与移动复用.json').read_text(encoding='utf-8'));assert raw['disk_sha256']==sha
    functions={};chunks=set();instructions={}
    for f in raw['functions']:
        declared={(int(c['start_va'],16),int(c['end_va'],16),c['is_main']) for c in f['declared_chunks']}
        assert {(s,e) for s,e,_ in declared}=={(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges']+f['chunk_byte_ranges']:check(row)
        for i in f['assembly']:
            va=int(i['va'],16);assert any(s<=va<e for s,e,_ in declared)
            assert any(int(r['va'],16)<=va<int(r['va'],16)+r['size'] for r in f['byte_ranges'])
            instructions[va]=i['text']
        if db is not None:
            live=db.functions.get_at(int(f['va'],16));assert live.start_ea==int(f['va'],16)
            cs=list(db.functions.get_chunks(live));assert {(c.start_ea,c.end_ea,c.is_main) for c in cs}==declared
            actual={i.ea:db.instructions.get_disassembly(i) for c in cs for i in db.instructions.get_between(c.start_ea,c.end_ea)}
            assert actual=={int(i['va'],16):i['text'] for i in f['assembly']}
        chunks.update((f['va'],s,e) for s,e,_ in declared);functions[f['va']]=f
    for row in raw['thunks']:
        check(row);code=bytes.fromhex(row['idb_hex']);assert code[0]==0xE9
        assert int(row['va'],16)+5+int.from_bytes(code[1:],'little',signed=True)==int(row['target'],16)
    review=json.loads((TOP/'function_review.json').read_text(encoding='utf-8'))
    assert {r['va'] for r in review['functions']}==set(functions)
    assert {r['va'] for r in review['code_windows']}=={w['va'] for w in data['windows']}
    for r in review['functions']+review['code_windows']:
        assert r['status']==r['review_status'] and r['conclusion'] and r['unknown'] and r['full_dependency_closure'] is False
        for p in r['evidence']:assert (TOP/p).is_file()
    for p in TOP.glob('*.txt'):assert all(not s.strip() or s.startswith('//') for s in p.read_text(encoding='utf-8').splitlines())
    return dict(scope='窗口不并入声明函数；候选扫描限已解码.text，非动态可达性证明。',ida_live=db is not None,
                exe_sha256=sha,undeclared_windows=2,window_bytes=113,window_instructions=window_instructions,
                dependency_functions=len(functions),dependency_chunks=len(chunks),dependency_instruction_addresses=len(instructions),
                dependency_thunks=len(raw['thunks']),entry_thunks=2,candidate_instructions=len(candidates),control_candidates=len(control),
                byte_comparisons=comparisons,distinct_address_size_ranges=len(ranges),range_size_sum=sum(s for _,s in ranges),mismatches=0)
if __name__=='__main__':
    result=audit();(HERE/'independent_local_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
