"""独立复核格式化主体与保存点；只读PE、原证及可选IDA，不执行客户端。"""
from collections import Counter
from contextlib import redirect_stdout
from itertools import product
from pathlib import Path
import hashlib
import io
import json
import re
import runpy
import struct
import sys

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
MAIN = {0x8E0380,0x92BBD0,0x92BAD0}
OWNERS = {0x8E67C0:12,0x8F1000:12,0x8F9490:4,0x901F30:1,
          0x905420:4,0x909330:3,0x90AAA0:1,0x90E060:8}


def reproduce():
    old_write,old_path = Path.write_text,list(sys.path)
    old_model = sys.modules.pop('hex_model',None)
    captured = {}
    def capture(path,text,*args,**kwargs):
        captured[path.resolve()] = text
        return len(text)
    try:
        Path.write_text = capture
        sys.path.insert(0,str(HERE))
        with redirect_stdout(io.StringIO()):
            runpy.run_path(str(HERE/'build_hex_review.py'))['build']()
            assert runpy.run_path(str(HERE/'validate_hex.py'))['validate']() == 0
    finally:
        Path.write_text,sys.path[:] = old_write,old_path
        sys.modules.pop('hex_model',None)
        if old_model is not None:
            sys.modules['hex_model'] = old_model
    owned = TOPIC/'独立审阅.txt'
    owned_lines = len(owned.read_text('utf-8').splitlines()) if owned.exists() else 0
    for path,text in captured.items():
        if path.suffix=='.json':
            a,b = json.loads(text),json.loads(path.read_text('utf-8'))
            if path.name=='validation.json':
                # 作者逐行验证所有txt；新增独审正文只增加格式断言数，不影响语义结果。
                assert a['checks']['assertions']-b['checks']['assertions'] in (0,owned_lines)
                a['checks'].pop('assertions');b['checks'].pop('assertions')
            assert a==b,path
        else:
            assert text==path.read_text('utf-8'),path
    assert len(captured)==5
    return len(captured)


def audit(db=None):
    data = json.loads((HERE/'hex_raw.json').read_text('utf-8'))
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==data['disk_sha256']==SHA
    assert data['idb_input_sha256']!=SHA
    if db is not None:
        import ida_bytes
        import ida_funcs
        import ida_nalt
        import idautils
        import idc
        assert ida_nalt.retrieve_input_file_sha256().hex()==data['idb_input_sha256']
    pe = struct.unpack_from('<I',image,60)[0]
    assert image[:2]==b'MZ' and image[pe:pe+4]==b'PE\0\0'
    opt = struct.unpack_from('<H',image,pe+20)[0]
    base = struct.unpack_from('<I',image,pe+52)[0]
    sections = [struct.unpack_from('<4I',image,pe+24+opt+40*i+8)
                for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    def disk(va,size):
        for _,rva,length,at in sections:
            delta = va-base-rva
            if 0<=delta and delta+size<=length:
                return image[at+delta:at+delta+size]
        return None
    bytes_map,code_bytes,spans = {},{},set()
    comparisons,unmapped = 0,0
    def check(row,code=False,allow_unmapped=False):
        nonlocal comparisons,unmapped
        va,size = int(row['va'],16),row['size']
        raw = bytes.fromhex(row['ida_hex'])
        assert len(raw)==size and hashlib.sha256(raw).hexdigest()==row['sha256']
        current = disk(va,size)
        if current is None:
            assert allow_unmapped and row['disk_hex'] is None and row['equal'] is None
            unmapped+=1
        else:
            assert current==raw and row['disk_hex']==raw.hex() and row['equal'] is True
            spans.add((va,size));comparisons+=1
            for i,value in enumerate(raw):
                assert bytes_map.get(va+i,value)==value
                bytes_map[va+i]=value
                if code:
                    code_bytes[va+i]=value
        if db is not None:
            assert db.bytes.get_bytes_at(va,size)==raw
    def target(site,raw):
        if raw[0] in (0xE8,0xE9):
            assert len(raw)==5
            return site+5+struct.unpack_from('<i',raw,1)[0]
        assert raw[0]==0xEB and len(raw)==2
        return site+2+struct.unpack_from('<b',raw,1)[0]
    bridges = {}
    for row in data['thunks']:
        check(row)
        va = int(row['va'],16)
        raw = bytes.fromhex(row['ida_hex'])
        assert raw[0]==0xE9 and va not in bridges
        bridges[va]=target(va,raw)
        assert bridges[va]==int(row['target'],16)
    def resolve(va):
        seen=set()
        while va in bridges:
            assert va not in seen
            seen.add(va);va=bridges[va]
        return va
    def live_instruction(a):
        return dict(va=hex(a),size=idc.get_item_size(a),
                    hex=ida_bytes.get_bytes(a,idc.get_item_size(a)).hex(),
                    text=idc.generate_disasm_line(a,0) or '')
    functions,ins,raw_ins,chunk_count,noncode_count,call_count = {},{},{},0,0,0
    for f in data['functions']:
        va=int(f['va'],16)
        assert va not in functions
        functions[va]=f
        chunks=[]
        for c in f['chunks']:
            check(c,code=True)
            s,e=int(c['va'],16),int(c['end'],16)
            assert e-s==c['size']
            chunks.append((s,e));chunk_count+=1
        for key in ['instructions','non_code_items']:
            for row in f[key]:
                a,raw=int(row['va'],16),bytes.fromhex(row['hex'])
                assert len(raw)==row['size'] and disk(a,len(raw))==raw
                assert sum(s<=a and a+len(raw)<=e for s,e in chunks)==1
                if key=='instructions':
                    assert a not in ins
                    ins[a]=row['text'];raw_ins[a]=raw
                else:
                    noncode_count+=1
        for call in f['calls']:
            a=int(call['site'],16)
            assert a in raw_ins
            if call['direct']:
                dest=target(a,raw_ins[a])
                assert dest==int(call['target'],16) and resolve(dest)==int(call['resolved'],16)
            else:
                assert call['resolved'] is None
            call_count+=1
        if db is not None:
            live=ida_funcs.get_func(va)
            assert live and live.start_ea==va and list(idautils.Chunks(va))==chunks
            assert [live_instruction(a) for s,e in chunks for a in idautils.Heads(s,e)
                    if ida_bytes.is_code(ida_bytes.get_full_flags(a))]==f['instructions']
            assert [live_instruction(a) for s,e in chunks for a in idautils.Heads(s,e)
                    if not ida_bytes.is_code(ida_bytes.get_full_flags(a))]==f['non_code_items']
            live_calls=[];live_refs=[]
            for s,e in chunks:
                for a in idautils.Heads(s,e):
                    if not ida_bytes.is_code(ida_bytes.get_full_flags(a)):
                        continue
                    mnemonic=idc.print_insn_mnem(a)
                    if mnemonic in ('call','jmp'):
                        dest=idc.get_operand_value(a,0)
                        operand=idc.get_operand_type(a,0)
                        direct=operand in (idc.o_near,idc.o_far)
                        live_calls.append(dict(site=hex(a),kind=mnemonic,direct=direct,target=hex(dest),
                                               resolved=hex(resolve(dest)) if direct else None,
                                               target_name=idc.get_name(dest),operand_type=operand))
                    live_refs.extend(dict(site=hex(a),target=hex(t),name=idc.get_name(t))
                                     for t in idautils.DataRefsFrom(a))
            assert live_calls==f['calls'] and live_refs==f['data_refs']
    assert set(functions)==MAIN|set(OWNERS)
    strings={}
    for row in data['strings']:
        check(row)
        va=int(row['va'],16)
        assert va not in strings
        strings[va]=bytes.fromhex(row['ida_hex'])
    assert strings[0xA679B0]==b'0x00000000\0'
    check(data['global']['snapshot'],allow_unmapped=True)
    assert unmapped==1 and data['global']['snapshot']['va']=='0xacc3d8'
    assert data['global']['ida_item_size']==10
    if db is not None:
        assert idc.get_item_size(0xACC3D8)==10
        assert hex(idc.next_head(0xACC3D8))==data['global']['next_head']
        refs=[]
        for a in range(0xACC3D8,0xACC3D8+32):
            for x in idautils.XrefsTo(a):
                owner=ida_funcs.get_func(x.frm)
                refs.append(dict(target=hex(a),site=hex(x.frm),type=int(x.type),
                                 owner=hex(owner.start_ea) if owner else None,instruction=live_instruction(x.frm)))
        assert refs==data['global']['references']
    for row in data['incoming']:
        i=row['instruction'];a=int(i['va'],16);raw=bytes.fromhex(i['hex'])
        assert disk(a,len(raw))==raw and target(a,raw)==int(row['entry'],16)
        if db is not None:
            assert live_instruction(a)==i
            owner=ida_funcs.get_func(a)
            assert (hex(owner.start_ea) if owner else None)==row['owner']
    if db is not None:
        incoming=[]
        for entry in [0x8E0380,0x600248]:
            for a in idautils.CodeRefsTo(entry,False):
                owner=ida_funcs.get_func(a)
                incoming.append(dict(site=hex(a),entry=hex(entry),owner=hex(owner.start_ea) if owner else None,
                                     instruction=live_instruction(a)))
        assert incoming==data['incoming']
    # 模板、临时区写入及lstrlen IAT来源，独立于反编译的Buffer命名。
    anchors={0x8E0382:'bfb079a600',0x8E0396:'6a10',0x8E039C:'bfd8c3ac00',
             0x8E03A1:'68ccc3ac00',0x8E03A9:'f3a5',0x8E03B1:'f3a4',
             0x8E03B5:'890dccc3ac00',0x8E03BB:'890dd0c3ac00',0x8E03C1:'66890dd4c3ac00',
             0x8E03CD:'8b3d683bad00',0x8E03DB:'ffd7',0x8E03EF:'ffd7',0x8E03F9:'ffd7',
             0x8E03F6:'8bd8',0x8E03FB:'bfe2c3ac00',0x8E0402:'2bf8',
             0x92BBD4:'837d100a',0x92BBDE:'7d09',0x92BAE5:'c6012d',0x92BAF4:'f7d8',
             0x92BB04:'f77510',0x92BB0F:'f77510',0x92BB49:'77b4',0x92BB8C:'72cc'}
    assert all(raw_ins[a].hex()==b for a,b in anchors.items())
    assert not any('cld' in t or 'std' in t for a,t in ins.items() if 0x8E0380<=a<=0x8E041A)
    def cstr(a):
        out=bytearray()
        for i in range(1024):
            b=disk(a+i,1)
            assert b is not None
            if b==b'\0':
                return bytes(out)
            out.extend(b)
        raise AssertionError('字符串超过独审上限')
    iat={};import_rva=struct.unpack_from('<I',image,pe+24+104)[0]
    for i in range(256):
        desc=disk(base+import_rva+20*i,20)
        if desc==bytes(20):
            break
        original,_,_,dll,first=struct.unpack('<5I',desc)
        for j in range(4096):
            value=struct.unpack('<I',disk(base+(original or first)+4*j,4))[0]
            if value==0:
                break
            iat[base+first+4*j]=(cstr(base+dll),None if value&0x80000000 else cstr(base+value+2))
    assert iat[0xAD3B68]==(b'KERNEL32.dll',b'lstrlenA')
    calls=json.loads((HERE/'save_color_calls.json').read_text('utf-8'))
    business=[r for r in data['incoming'] if r['owner']!='0x600248']
    assert len(data['incoming'])==46 and len(business)==45
    assert Counter(int(r['owner'],16) for r in calls)==OWNERS
    assert {r['call'] for r in calls}=={r['site'] for r in business}
    for row in calls:
        sequence=functions[int(row['owner'],16)]['instructions']
        ix=next(i for i,x in enumerate(sequence) if x['va']==row['call'])
        ci=next(i for i,x in enumerate(sequence) if x['va']==row['consumer_call'])
        assert sequence[ci]['hex'] in ('ff16','ff17') and ci>ix
        before=sequence[max(0,ix-6):ix]
        candidate=[]
        for x in before:
            b=bytes.fromhex(x['hex'])
            if b[0]==0x8B and len(b) in (3,6) and b[1]&7 in (3,6) and b[1]>>6 in (1,2):
                candidate.append((x,int.from_bytes(b[2:],'little',signed=True)))
        assert len(candidate)==1 and candidate[0][1]==row['offset']
        between=sequence[ix+1:ci]
        assert not any(x['text'].startswith('call') for x in between)
        registers={'eax':'formatted'}
        pushed=[]
        for x in between:
            b=bytes.fromhex(x['hex'])
            text=x['text'].split(';',1)[0].strip()
            if b[0]==0x68:
                pushed.append(struct.unpack_from('<I',b,1)[0])
            elif len(b)==1 and 0x50<=b[0]<=0x57:
                register=['eax','ecx','edx','ebx','esp','ebp','esi','edi'][b[0]-0x50]
                pushed.append(registers[register])
            elif text.startswith('mov '):
                destination,source=text.split(None,1)[1].split(', ')
                registers[destination]=source
            else:
                assert text.startswith('add     esp, ')
        assert raw_ins[int(row['key_push'],16)]==b'\x68'+struct.pack('<I',int(row['key_va'],16))
        assert strings[int(row['key_va'],16)]==row['key'].encode('ascii')+b'\0'
        callback_reg='esi' if sequence[ci]['hex']=='ff16' else 'edi'
        slot=next(x for x in before if re.fullmatch(r'lea     '+callback_reg+r', \[(eax|ecx|edx)\+60h\]',x['text']))
        manager_reg=re.search(r'\[(eax|ecx|edx)\+',slot['text'])[1]
        previous=sequence[max(0,ix-10):ix]
        assert any(x['text']=='mov     '+manager_reg+', dword_ACC3C8' for x in previous)
        assert row['callback_slot']==96
        object_reg='ebx' if bytes.fromhex(candidate[0][0]['hex'])[1]&7==3 else 'esi'
        assert any(x['text'].endswith('['+object_reg+'+8]') for x in between)
        assert pushed==['formatted',int(row['key_va'],16),'['+object_reg+'+8]']
    # 以逐位提取的独立公式核作者DIV/反转模型；只覆盖规定的有限位型集合。
    model=runpy.run_path(str(HERE/'hex_model.py'))
    values=set(range(65536))|{n<<16 for n in range(65536)}
    values|={(n<<24)|(255-n) for n in range(256)}
    values|={0x7FFFFFFF,0x80000000,0xFFFFFFFF,0x12345678,0xABCDEF01}
    alphabet=b'0123456789abcdef'
    for value in values:
        expected=b'0x'+bytes(alphabet[(value>>shift)&15] for shift in range(28,-1,-4))+b'\0'
        assert model['format_value'](value)==expected
        assert model['parse_fixed'](expected)==int(expected[2:10],16)==value
    crt_cases=0
    for value,radix in product([-0x80000000,-1,0,1,9,10,35,255,0x7FFFFFFF,0xFFFFFFFF],range(2,37)):
        unsigned=value&0xFFFFFFFF
        signed=unsigned if unsigned<0x80000000 else unsigned-0x100000000
        text=model['ltoa'](value,radix)
        assert text[-1:]==b'\0'
        visible=text[:-1].decode('ascii')
        assert int(visible,radix)==(signed if radix==10 else unsigned)
        assert visible.startswith('-')==(radix==10 and signed<0)
        crt_cases+=1
    for n,m in product(range(1,9),repeat=2):
        start,end=0xACC3E2-m,0xACC3E2-m+n
        assert (end>0xACC3E2)==(n>m)
        assert start>=0xACC3DA
    review=json.loads((TOPIC/'函数审阅清单.json').read_text('utf-8'))
    assert {int(r['va'],16) for r in review['functions'] if r['status']=='主体已审阅'}==MAIN
    assert {int(r['va'],16) for r in review['functions'] if r['status']=='局部已审阅'}==set(OWNERS)
    assert review['counts']=={'主体已审阅':3,'局部已审阅':8}
    assert review['reuse'][0]['va']=='0x8e0450'
    for p in TOPIC.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in p.read_text('utf-8').splitlines())
    outputs=reproduce()
    return dict(ida_live=db is not None,disk_sha256=SHA,idb_input_sha256=data['idb_input_sha256'],
                whole_idb_identity_claimed=False,functions=len(functions),chunks=chunk_count,
                instructions=len(ins),non_code_items=noncode_count,range_comparisons=comparisons,
                unique_spans=len(spans),unique_code_bytes=len(code_bytes),unique_mapped_bytes=len(bytes_map),
                unmapped_ida_snapshots=unmapped,thunks=len(bridges),calls=call_count,strings=len(strings),
                incoming=len(data['incoming']),save_call_sites=len(calls),save_owners=len(OWNERS),
                finite_format_values=len(values),finite_crt_cases=crt_cases,interleaving_arithmetic=64,
                author_outputs_reproduced=outputs,mismatches=0,
                scope='3主体及45保存点局部静态契约、有限位型/交错算术模型；共享存储容量、并发可达、回调深拷贝与落盘未闭环，8E0450仅复用规范八位有限域。')


if __name__=='__main__':
    result=audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result,ensure_ascii=True))
