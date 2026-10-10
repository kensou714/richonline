"""独立只读核验；local()写独审结果，audit(db)供主持IDA lease代跑。"""
from pathlib import Path
from collections import Counter
from contextlib import redirect_stdout
import hashlib
import io
import json
import runpy
import struct
import sys

HERE=Path(__file__).resolve().parent.parent
ROOT=HERE.parents[3]
NAMES=['candidate_core','layout_seeds','accessors_and_consumers','consumer_methods','record_users','text_contract','record_finalize']

def load():
    blob=(ROOT/'RnClient.exe').read_bytes()
    pe=struct.unpack_from('<I',blob,0x3c)[0]
    assert blob[:2]==b'MZ' and blob[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',blob,pe+24)[0]==0x10b
    count=struct.unpack_from('<H',blob,pe+6)[0]
    opts=struct.unpack_from('<H',blob,pe+20)[0]
    base=struct.unpack_from('<I',blob,pe+52)[0]
    sections=[struct.unpack_from('<IIII',blob,pe+24+opts+40*i+8) for i in range(count)]
    def read(va,size):
        ea=int(va,16) if isinstance(va,str) else va
        for vs,rva,rawsize,off in sections:
            rel=ea-base-rva
            if 0<=rel and rel+size<=rawsize:
                return blob[off+rel:off+rel+size]
        raise ValueError(hex(ea))
    raw={n:json.loads((HERE/'证据'/(n+'.json')).read_text(encoding='utf-8')) for n in NAMES}
    functions={}
    for item in raw.values():
        for f in item['functions']:
            if f['va'] in functions:
                assert functions[f['va']]==f
            functions[f['va']]=f
    return blob,read,raw,functions

def byte_rows(node):
    if isinstance(node,dict):
        if {'va','size','idb_hex'}<=node.keys():
            yield node
        for v in node.values():yield from byte_rows(v)
    elif isinstance(node,list):
        for v in node:yield from byte_rows(v)

def models():
    def i32(n):
        n&=0xffffffff
        return n if n<0x80000000 else n-0x100000000
    def rem_math(n):
        n=i32(n)
        return n%512 if n>=0 else -((-n)%512)
    def rem_machine(n):
        n=i32(n)&0x800001ff
        if n&0x80000000:
            n=((n-1)|0xfffffe00)+1
        return i32(n)
    samples=list(range(-4096,4097))+[-0x80000000,-0x7fffffff,0x7fffffff,0x7ffffffe]
    assert all(rem_math(n)==rem_machine(n) for n in samples)
    def submit(W,N,C):
        W=rem_machine(i32(W+1))
        if i32(N)<512:
            N=i32(N+1)
            if N>5:C=rem_machine(i32(C+1))
        else:C=rem_machine(i32(C+1))
        return W,N,C
    def previous(W,N,C):
        if i32(N)<512:return W,N,i32(C-1) if i32(C)>0 else C
        t=rem_machine(i32(C-1))
        return W,N,t if t!=W else C
    def following(W,N,C):
        if i32(N)<512:
            return W,N,i32(C+1) if i32(C+5)<i32(N) else C
        return W,N,rem_machine(i32(C+1)) if rem_machine(i32(C+5))!=W else C
    state=(0,0,0); milestones={}
    for n in range(1,518):
        state=submit(*state)
        if n in [1,5,6,512,513,517]:milestones[str(n)]=list(state)
    assert milestones=={'1':[1,1,0],'5':[5,5,0],'6':[6,6,1],'512':[0,512,507],'513':[1,512,508],'517':[5,512,0]}
    assert previous(0,512,0)==(0,512,-1)
    assert previous(7,4,0)==(7,4,0)
    assert following(6,6,1)==(6,6,1) and following(6,6,0)==(6,6,1)
    # 下一次入口先清零；同一次多行提交则不清零。只模拟元数据，不执行游戏外部副作用。
    reset_then_one=submit(0,0,0)
    assert reset_then_one==(1,1,0)
    # 元素初始化模型使用非零哨兵，确认每条只有两个BYTE被覆盖，不虚构memset。
    obj=bytearray([0xa5])*0x2bd54
    starts=[340*i for i in range(512)]+[0x2a80c+340*i for i in range(16)]
    for start in starts:obj[start]=obj[start+272]=0
    changed=[i for i,x in enumerate(obj) if x!=0xa5]
    assert len(changed)==1056 and all(obj[x:x+4]==b'\xa5'*4 for x in [0x2a800,0x2a804,0x2a808,0x2bd4c,0x2bd50])
    # 双字节/控制码分类模型：只对有效两字节样例，不外推编码名称/输入安全。
    def token(head,next_byte,width):
        signed=next_byte if next_byte<128 else next_byte-256
        return (2,24,'控制码') if head==6 and 20<=signed<=70 else ((2,width,'高位首字节') if head>=128 else (1,width,'普通单字节'))
    cases=[(6,19,7,(1,7,'普通单字节')),(6,20,7,(2,24,'控制码')),(6,70,7,(2,24,'控制码')),(6,71,7,(1,7,'普通单字节')),(6,0xff,7,(1,7,'普通单字节')),(0x81,0x40,12,(2,12,'高位首字节'))]
    assert all(token(a,b,c)==expected for a,b,c,expected in cases)
    def retreat(data,delimiter_set,keep):
        for pos in range(len(data)-1,-1,-1):
            if data[pos] in delimiter_set:
                return data[:pos+int(keep)],len(data)-pos-1
        return data,0
    assert retreat(b'abc def',{32,44,46},True)==(b'abc ',3)
    assert retreat(b'abc def',{32,44,46,33},False)==(b'abc',3)
    assert retreat(b'abc!def',{32,44,46},True)==(b'abc!def',0)
    return dict(scope='独立模型，未执行游戏代码或证明状态可达',signed_remainder_samples=len(samples),submit_milestones=milestones,
        negative_cursor_example=dict(input=[0,512,0],output=list(previous(0,512,0)),first_read_offset=-340),
        next_append_reset_then_one=list(reset_then_one),element_initialization_changed_bytes=len(changed),classification_cases=len(cases),delimiter_cases=3)

def local():
    blob,read,raw,functions=load();sha=hashlib.sha256(blob).hexdigest()
    unique_bytes={};chunk_set=set();tail_set=set();thunks={};comparisons=0
    for name,item in raw.items():
        assert item['disk_sha256']==sha
        for r in byte_rows(item):
            saved=bytes.fromhex(r['idb_hex']);actual=read(r['va'],r['size'])
            assert saved==actual and len(saved)==r['size'] and r['disk_hex']==actual.hex() and r['matching'] is True
            comparisons+=1
            for off,value in enumerate(saved):
                ea=int(r['va'],16)+off
                assert ea not in unique_bytes or unique_bytes[ea]==value
                unique_bytes[ea]=value
            if 'target' in r:
                assert saved[0]==0xe9 and len(saved)==5
                assert int(r['va'],16)+5+struct.unpack('<i',saved[1:])[0]==int(r['target'],16)
                thunks[r['va']]=r
        for f in item['functions']:
            assert f['bytes_match_disk']
            for c in f['declared_chunks']:
                start,end=int(c['start_va'],16),int(c['end_va'],16)
                chunk_set.add((f['va'],start,end))
                if not c['is_main']:tail_set.add((f['va'],start,end))
                rows=[r for r in f['chunk_byte_ranges'] if int(r['va'],16)==start and r['size']==end-start]
                assert len(rows)==1
                cursor=start
                for r in sorted(f['byte_ranges'],key=lambda x:int(x['va'],16)):
                    lo=int(r['va'],16);hi=lo+r['size']
                    if lo<=cursor<hi:cursor=min(end,hi)
                assert cursor==end
    review=json.loads((HERE/'函数审阅清单.json').read_text(encoding='utf-8'))
    assert {r['va'] for r in review['functions']}==set(functions)
    statuses=dict(Counter(r['status'] for r in review['functions']))
    assert statuses==review['status_counts']=={'局部语义审阅':18,'仅导出':11,'仅桥接核对':4}
    for r in review['functions']:
        assert r['conclusion'] and r['unresolved'] and all((HERE/p).is_file() for p in r['review_sources'])
    assert len(functions)==33 and len(chunk_set)==34 and len(tail_set)==1 and len(thunks)==85 and len(unique_bytes)==6077
    assert 340*512==0x2a800 and 0x2a80c+16*340==0x2bd4c and 0x2bd50+4==179540
    instructions={int(a['va'],16):a['text'] for f in functions.values() for a in f['assembly']}
    expected={0x62a209:'push    2BD54h; Size',0x62a2b3:'push    200h; int',0x62a2b8:'push    154h; unsigned int',
        0x62a2cb:'push    10h; int',0x62a2d5:'add     ecx, 2A80Ch',0x62a321:'mov     byte ptr [eax+110h], 0',
        0x62a32b:'mov     byte ptr [ecx], 0',0x64b8c7:'jl      short loc_64B8D1',0x64b93f:'call    j__strcpy',
        0x64ba64:'movsx   eax, byte ptr [edx+1]',0x64ba68:'cmp     eax, 14h',0x64ba78:"cmp     edx, 46h ; 'F'",
        0x64bb23:'mov     byte ptr [edx+eax], 0',0x64bc84:'mov     byte ptr [edx+eax+1], 0',
        0x64be0a:'and     ecx, 800001FFh',0x64be30:'jge     short loc_64BE78',0x64be51:'jle     short loc_64BE76',
        0x64bf12:'jz      short loc_64BF20',0x64c02e:'movsx   edx, byte ptr [ecx+eax]',0x64c0ee:'movsx   edx, byte ptr [ecx+eax]'}
    assert all(instructions[va]==text for va,text in expected.items())
    # 截获作者生成器写入，在内存中重算；不改清单、正文和核验结果。
    originals={p:p.read_bytes() for p in [HERE/'函数审阅清单.json',HERE/'逐函数审阅.txt',HERE/'核验结果.json']}
    captured={};old=Path.write_text;out=io.StringIO();oldpath=list(sys.path)
    def capture(path,text,*args,**kwargs):
        target=Path(path).resolve()
        assert target in originals,'作者脚本新增未知写入：'+str(target)
        encoding=kwargs.get('encoding',args[0] if args else 'utf-8') or 'utf-8'
        captured[target]=text.encode(encoding)
        return len(text)
    try:
        Path.write_text=capture;sys.path.insert(0,str(HERE))
        with redirect_stdout(out):
            runpy.run_path(str(HERE/'build_review.py'),run_name='__main__')
            try:runpy.run_path(str(HERE/'validate_evidence.py'),run_name='__main__')
            except SystemExit as exc:assert exc.code in [0,None,False]
    finally:
        Path.write_text=old;sys.path[:]=oldpath
    assert set(captured)==set(originals)
    normalize=lambda b:b.decode('utf-8').replace('\r\n','\n')
    assert all(normalize(captured[p])==normalize(b) and p.read_bytes()==b for p,b in originals.items())
    nav=json.loads((HERE/'证据/entry_callers.json').read_text(encoding='utf-8'))
    for r in nav['observed_e9_navigation']:
        b=bytes.fromhex(r['idb_hex']);assert read(r['va'],5)==b and b[0]==0xe9
        assert int(r['va'],16)+5+struct.unpack('<i',b[1:])[0]==int(r['target'],16)
    supplemental=[]
    for va,target in [(0x605d06,0x62a310),(0x60e073,0x62a1d0),(0x6068aa,0x64bdf0),(0x607138,0x64b880)]:
        b=read(va,5)
        assert b[0]==0xe9 and va+5+struct.unpack('<i',b[1:])[0]==target
        supplemental.append(dict(va=hex(va),target=hex(target),disk_hex=b.hex()))
    result=dict(scope='独立PE+人工重点汇编+模型；不宣称33函数全语义闭合',disk_sha256=sha,evidence_files=len(raw),
        functions=len(functions),chunks=len(chunk_set),tail_chunks=len(tail_set),instructions=len(instructions),e9_thunks=len(thunks),
        unique_verified_bytes=len(unique_bytes),byte_record_comparisons=comparisons,statuses=statuses,manual_instruction_anchors=len(expected),
        author_artifacts_recomputed_without_writing=3,generated_text_comparison='仅统一CRLF/LF后文本一致；作者原文件字节未改',
        supplemental_entry_checks=supplemental,models=models())
    (HERE/'证据/independent_local_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result

def audit(db):
    # 数据库只读；写入仅为本专题新增独审JSON，由主持lease代跑并说明来源。
    blob,read,raw,functions=load();byte_checks=0;insn_checks=0;chunks=0;tails=0;thunks={}
    for name,item in raw.items():
        for r in byte_rows(item):
            assert db.bytes.get_bytes_at(int(r['va'],16),r['size']).hex()==r['idb_hex']==read(r['va'],r['size']).hex()
            byte_checks+=1
            if 'target' in r:thunks[r['va']]=r
    for va,f in functions.items():
        ea=int(va,16);live=db.functions.get_at(ea)
        assert live is not None and live.start_ea==ea
        current=list(db.functions.get_chunks(live))
        assert [(hex(c.start_ea),hex(c.end_ea),bool(c.is_main)) for c in current]==[(c['start_va'],c['end_va'],c['is_main']) for c in f['declared_chunks']]
        decoded={}
        for c in current:
            chunks+=1;tails+=int(not c.is_main)
            for ins in db.instructions.get_between(c.start_ea,c.end_ea):decoded[hex(ins.ea)]=db.instructions.get_disassembly(ins)
        assert decoded=={a['va']:a['text'] for a in f['assembly']}
        insn_checks+=len(decoded)
    assert chunks==34 and tails==1 and len(functions)==33 and len(thunks)==85
    supplemental=[]
    for va,target in [(0x605d06,0x62a310),(0x60e073,0x62a1d0),(0x6068aa,0x64bdf0),(0x607138,0x64b880)]:
        b=db.bytes.get_bytes_at(va,5)
        assert b==read(va,5) and b[0]==0xe9 and va+5+struct.unpack('<i',b[1:])[0]==target
        supplemental.append(dict(va=hex(va),target=hex(target),matching=True))
    result=dict(scope='主持IDA lease代跑只读audit(db)；非独审代理自己的lease，未改IDB',disk_sha256=hashlib.sha256(blob).hexdigest(),
        functions=33,chunks=chunks,tail_chunks=tails,instructions=insn_checks,e9_thunks=len(thunks),byte_record_comparisons=byte_checks,
        key_instruction_anchors='local()独立PE锚点与当前IDA反汇编全部一致',supplemental_entry_checks=supplemental,database_mutations=0)
    (HERE/'证据/independent_live_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result

if __name__=='__main__':
    print(json.dumps(local(),ensure_ascii=False,indent=2))
