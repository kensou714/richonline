"""独立审阅：只读作者原证与当前PE；可由有效IDA-MCP lease执行audit(db)。"""
import hashlib,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent;TOP=HERE.parent
ROOT=Path(r'F:\大富翁online\Richonline')
RAW=['创建与链表.json','几何传播.json','状态与销毁.json','名称调用复用.json']
def audit(db=None):
    blob=(ROOT/'RnClient.exe').read_bytes();sha=hashlib.sha256(blob).hexdigest()
    assert sha=='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe=struct.unpack_from('<I',blob,60)[0];n=struct.unpack_from('<H',blob,pe+6)[0]
    opt=struct.unpack_from('<H',blob,pe+20)[0];base=struct.unpack_from('<I',blob,pe+52)[0]
    sections=[struct.unpack_from('<IIII',blob,pe+24+opt+40*i+8) for i in range(n)]
    def disk(va,size):
        for _,rva,raw,off in sections:
            d=va-base-rva
            if 0<=d and d+size<=raw:return blob[off+d:off+d+size]
        raise AssertionError(('未映射',hex(va),size))
    comparisons=0;ranges=set()
    def check(row):
        nonlocal comparisons
        va=int(row['va'],16);size=row['size'];expected=bytes.fromhex(row['idb_hex'])
        assert len(expected)==size and expected==bytes.fromhex(row['disk_hex'])==disk(va,size)
        assert row['matching'] is True
        if db is not None:assert db.bytes.get_bytes_at(va,size)==expected
        comparisons+=1;ranges.add((va,size))
    functions={};thunks={};chunks=set();instructions={}
    for name in RAW:
        raw=json.loads((HERE/name).read_text(encoding='utf-8'));assert raw['disk_sha256']==sha
        for f in raw['functions']:
            declared={(int(c['start_va'],16),int(c['end_va'],16),c['is_main']) for c in f['declared_chunks']}
            complete={(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges']}
            assert {(s,e) for s,e,_ in declared}==complete
            for r in f['byte_ranges']+f['chunk_byte_ranges']:check(r)
            for ins in f['assembly']:
                va=int(ins['va'],16);assert any(s<=va<e for s,e,_ in declared)
                assert any(int(r['va'],16)<=va<int(r['va'],16)+r['size'] for r in f['byte_ranges'])
                if va in instructions:assert instructions[va]==ins['text']
                instructions[va]=ins['text']
            if f['va'] in functions:
                for key in ['declared_chunks','chunk_byte_ranges','byte_ranges','assembly','calls']:
                    assert functions[f['va']][key]==f[key],(f['va'],key)
            functions[f['va']]=f;chunks.update((f['va'],s,e) for s,e,_ in declared)
            if db is not None:
                live=db.functions.get_at(int(f['va'],16));assert live.start_ea==int(f['va'],16)
                lc=list(db.functions.get_chunks(live));assert {(c.start_ea,c.end_ea,c.is_main) for c in lc}==declared
                actual={}
                for c in lc:
                    for ins in db.instructions.get_between(c.start_ea,c.end_ea):actual[ins.ea]=db.instructions.get_disassembly(ins)
                assert actual=={int(i['va'],16):i['text'] for i in f['assembly']},f['va']
        for t in raw['thunks']:
            check(t);code=bytes.fromhex(t['idb_hex']);assert code[0]==0xE9
            assert int(t['va'],16)+5+int.from_bytes(code[1:],'little',signed=True)==int(t['target'],16)
            if t['va'] in thunks:assert thunks[t['va']]==t
            thunks[t['va']]=t
    data=json.loads((HERE/'链字段与虚表数据.json').read_text(encoding='utf-8'));assert data['disk_sha256']==sha
    for key in ('data_checks','writer_checks','vtable_thunk_checks'):
        for r in data[key]:check(r)
    for r in data['virtual_mapping']:
        pointer=int.from_bytes(disk(0xA305AC+r['offset'],4),'little');assert pointer==int(r['entry'],16)
        code=disk(pointer,5);assert code[0]==0xE9
        assert pointer+5+int.from_bytes(code[1:],'little',signed=True)==int(r['implementation'],16)
    writers=json.loads((HERE/'链字段写者候选.json').read_text(encoding='utf-8'))['writers']
    assert {r['va'] for r in writers}=={r['va'] for r in data['writer_checks']}
    for r in writers:assert instructions[int(r['va'],16)]==r['text']
    if db is not None:
        live_writers=[]
        for ins in db.instructions.get_between(0x8E0000,0x910000):
            text=db.instructions.get_disassembly(ins)
            if re.match(r'(mov|and|or|xchg)\s+[^,]*\+(190h|194h|198h)\],',text,re.I):
                f=db.functions.get_at(ins.ea)
                live_writers.append(dict(va=hex(ins.ea),function=hex(f.start_ea) if f else None,text=text))
        assert live_writers==writers
    callsites=[]
    for f in functions.values():
        for c in f['calls']:
            if c['target']=='0x610d96':callsites.append(dict(site=c['site'],function=f['va']))
    assert sorted(callsites,key=lambda r:r['site'])==sorted(data['name_lookup_direct_callers'],key=lambda r:r['site'])
    assert len(callsites)==15
    if db is not None:
        actual=[dict(site=hex(x.from_ea),function=hex(db.functions.get_at(x.from_ea).start_ea)) for x in db.xrefs.to_ea(0x610D96) if db.functions.get_at(x.from_ea)]
        assert sorted(actual,key=lambda r:r['site'])==sorted(callsites,key=lambda r:r['site'])
    # 关键机器码位置保留为明确分支契约，不以关键词存在代替完整人工回读。
    anchors={0x8E2337:'jz      short loc_8E233F',0x8E2339:'mov     [esi+198h], eax',
             0x8E2467:'mov     [esi+190h], edi',0x8E2475:'jz      short loc_8E247D',
             0x8E2B81:'mov     eax, edi',0x8E2BC4:'retn    8',
             0x8E2CD3:'mov     eax, edx',0x8EA692:'mov     ecx, [esi+198h]',
             0x8EA6A5:'call    dword ptr [eax+78h]',0x8E38BE:'mov     ecx, edi',
             0x8E38D3:'retn    4',0x8E39E5:'call    dword ptr [eax]',
             0x8E3A29:'call    dword ptr [edx]',0x8E378C:'jle     short loc_8E37C9',
             0x8E379E:'jle     short loc_8E37AC'}
    for va,text in anchors.items():assert instructions[va]==text
    # 从磁盘跳表逐项读取case目的地，读取该case的push分配量。
    assert disk(0x8E24F4,3)==bytes.fromhex('ff248d')
    table=int.from_bytes(disk(0x8E24F7,4),'little');sizes=[]
    for i in range(13):
        dest=int.from_bytes(disk(table+4*i,4),'little')
        assert disk(dest,1)==b'\x68';sizes.append(int.from_bytes(disk(dest+1,4),'little'))
    assert sizes==[0x240,0x250,0x250,0x268,0x384,0x268,0x264,0x250,0x490,0x268,0x340,0x32C,0x364]
    review=json.loads((TOP/'function_review.json').read_text(encoding='utf-8'))['functions']
    assert {r['va'] for r in review}==set(functions)
    for r in review:
        assert r['status']==r['review_status'] and r['conclusion'] and r['unknown'] and r['full_dependency_closure'] is False
        for evidence in r['evidence']:assert (TOP/evidence).is_file()
    for p in TOP.glob('*.txt'):
        assert all(not s.strip() or s.startswith('//') for s in p.read_text(encoding='utf-8').splitlines())
    return dict(scope='独立PE核对；传入db时额外重取IDA块、指令、写者及调用点。非动态安全证明。',
                ida_live=db is not None,exe_sha256=sha,functions=len(functions),declared_chunks=len(chunks),
                instruction_addresses=len(instructions),unique_thunks=len(thunks),byte_comparisons=comparisons,
                distinct_address_size_ranges=len(ranges),range_size_sum=sum(size for _,size in ranges),
                data_regions=len(data['data_checks']),chain_writers=len(writers),name_callers=len(callsites),
                factory_sizes=sizes,mismatches=0)
if __name__=='__main__':
    result=audit();(HERE/'independent_local_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
