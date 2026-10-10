"""独审原证、导航边界、复用状态与有限模型；audit(db)只读。"""
import hashlib
import importlib.util
import json
import re
import struct
import sys
from collections import Counter
from itertools import product
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = ('functions_raw.json','callbacks_raw.json')


def read(name):
    return json.loads((HERE/name).read_text(encoding='utf-8-sig'))


def model_check():
    spec = importlib.util.spec_from_file_location('image_states_independent',HERE/'model.py')
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    cases = gates = 0
    for kind,mode,image,path,dims,builtin,callback in product(
        (-1,0,1,4,5,6),(-1,0,1,2,5),(-2147483648,-2,-1,0,1,2147483647),
        ('','file'),((0,0),(0,1),(1,0),(-1,-1),(-1,0),(320,240)),
        (False,True),('missing','false','true','true-invalid')):
        expected = dict(state=mode,dimensions=dims,cache=(900,901),events=[])
        branch = kind==5 and mode==1 and (image>=0 or bool(path))
        invoke = branch and dims==(0,0)
        if invoke:
            if callback=='missing':
                expected['events']=['missing']
            else:
                expected['events']=['id' if image>=0 else 'path']
                if callback=='false':
                    expected['events'].append('failed')
                else:
                    expected['dimensions']=(-1,-1) if callback=='true-invalid' else (320,240)
        if branch and builtin and (not invoke or callback in ('true','true-invalid')):
            expected['cache']=expected['dimensions']
        assert model.update(kind,mode,image,path,dims,builtin,callback)==expected
        cases += 1
    for enabled,visible,index in product(range(256),range(256),(-1,0,1,2,3,4)):
        assert model.refresh_gate(enabled,visible,index)==(visible!=0 and index==(0 if enabled else 3))
        gates += 1
    return dict(state_cases=cases,byte_gate_cases=gates,
                limitation='索引固定且合法，回调不重入；不执行机器码、字符串分配或资源管理器。')


def audit(db=None):
    blob = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest()==SHA
    pe = struct.unpack_from('<I',blob,60)[0]
    base = struct.unpack_from('<I',blob,pe+52)[0]
    optional = struct.unpack_from('<H',blob,pe+20)[0]
    count = struct.unpack_from('<H',blob,pe+6)[0]
    sections=[struct.unpack_from('<IIII',blob,pe+24+optional+40*i+8) for i in range(count)]
    ranges,comparisons={},0
    def disk(va,size):
        for _,rva,length,offset in sections:
            d=va-base-rva
            if 0<=d and d+size<=length:return blob[offset+d:offset+d+size]
        raise AssertionError(('无磁盘映射',hex(va),size))
    def check(row):
        nonlocal comparisons
        va,size=int(row['va'],16),row['size']
        raw=bytes.fromhex(row['idb_hex'])
        assert len(raw)==size and raw==disk(va,size)
        if 'disk_hex' in row:assert raw==bytes.fromhex(row['disk_hex']) and row['matching']
        assert (va,size) not in ranges or ranges[(va,size)]==raw
        ranges[(va,size)]=raw
        comparisons+=1
        return raw
    functions,thunks={},{}
    def bridge(row):
        raw=check(row)
        assert raw[0]==0xe9 and int(row['va'],16)+5+struct.unpack_from('<i',raw,1)[0]==int(row['target'],16)
        assert row['va'] not in thunks or thunks[row['va']]==row['target']
        thunks[row['va']]=row['target']
    for name in SOURCES:
        source=read(name)
        assert source['disk_sha256']==SHA
        for f in source['functions']:
            assert f['va'] not in functions
            functions[f['va']]=f
        for row in source['thunks']:bridge(row)
    nav=read('navigation.json')
    for row in nav['bridges']+read('callback_bridges.json'):bridge(row)
    instructions=calls=refs=chunks=indirect=register_calls=0
    for f in functions.values():
        declared={(int(c['start_va'],16),int(c['end_va'],16),c['is_main']) for c in f['declared_chunks']}
        assert {(s,e) for s,e,_ in declared}=={(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges']+f['chunk_byte_ranges']:check(row)
        assembly={int(i['va'],16):i['text'] for i in f['assembly']}
        assert len(assembly)==len(f['assembly']) and all(any(s<=a<e for s,e,_ in declared) for a in assembly)
        assert not any(t.startswith(('db ','dd ','dw ','align ')) for t in assembly.values())
        if db is not None:
            live=db.functions.get_at(int(f['va'],16))
            assert live.start_ea==int(f['va'],16) and live.end_ea==int(f['end_va'],16)
            live_chunks=list(db.functions.get_chunks(live))
            assert {(c.start_ea,c.end_ea,c.is_main) for c in live_chunks}==declared
            actual={i.ea:db.instructions.get_disassembly(i) for c in live_chunks for i in db.instructions.get_between(c.start_ea,c.end_ea)}
            assert actual==assembly,('完整汇编',f['va'])
            assert {(hex(x.from_ea),int(x.type)) for x in db.xrefs.to_ea(live.start_ea)}=={(r['source'],r['kind']) for r in f['references']}
        for row in f['calls']:
            va=int(row['site'],16);raw=disk(va,6)
            if raw[0]==0xe8:target=va+5+struct.unpack_from('<i',raw,1)[0]
            elif raw[:2]==b'\xff\x15':target=struct.unpack_from('<I',raw,2)[0]
            else:
                assert raw[:2]==b'\xff\xd7' and va in (0x8e1e27,0x8e1e36)
                assert disk(0x8e1e20,2)==b'\x8b\x3d'
                target=struct.unpack('<I',disk(0x8e1e22,4))[0]
                register_calls+=1
            assert hex(target)==row['target'] and va in assembly
            for b in row['thunks']:
                assert b==hex(target)
                target=int(thunks[b],16)
            assert hex(target)==row['implementation']
            calls+=1
        recorded={r['site'] for r in f['calls']}
        indirect+=sum(i['text'].startswith('call ') and i['va'] not in recorded for i in f['assembly'])
        instructions+=len(assembly);refs+=len(f['references']);chunks+=len(declared)
    for row in nav['inbound']:
        raw=check(dict(va=row['site'],size=5,idb_hex=row['idb_hex']))
        if row['kind'] in (16,17,18,19):
            assert raw[0] in (0xe8,0xe9) and int(row['site'],16)+5+struct.unpack_from('<i',raw,1)[0]==int(row['target'],16)
    if db is not None:
        expected={(r['site'],r['target'],r['kind'],r['owner']) for r in nav['inbound']}
        actual=set()
        for row in nav['bridges']:
            for x in db.xrefs.to_ea(int(row['va'],16)):
                owner=db.functions.get_at(x.from_ea)
                actual.add((hex(x.from_ea),row['va'],int(x.type),hex(owner.start_ea) if owner else None))
        assert actual==expected,('导航集合',len(actual),len(expected))
    prior=json.loads((HERE.parents[1]/'列表控件行记录与布局/证据/list_dependencies.json').read_text(encoding='utf-8-sig'))
    assert prior['disk_sha256']==SHA
    full={int(i['va'],16):i['text'] for f in prior['functions'] for i in f['assembly']}
    for window in nav['windows']:
        start,end=int(window['start_va'],16),int(window['end_va'],16)
        assert start==0x8f8b5a and end==0x8f8b7f and end-start==window['size']==37
        check(dict(va=window['start_va'],size=window['size'],idb_hex=window['idb_hex']))
        expected={int(i['va'],16):i['text'] for i in window['assembly']}
        assert expected=={a:t for a,t in full.items() if start<=a<end}
        assert start in full and end in full and min(expected)==start
        assert max(expected)+5==end and disk(max(expected),1)==b'\xe8'
        if db is not None:
            actual=list(db.instructions.get_between(start,end))
            assert actual[0].ea==start and actual[-1].ea+actual[-1].size==end
            assert {i.ea:db.instructions.get_disassembly(i) for i in actual}==expected
            owner=db.functions.get_at(start)
            heads={i.ea for c in db.functions.get_chunks(owner) for i in db.instructions.get_between(c.start_ea,c.end_ea)}
            assert start in heads and end in heads
    strings={r['va']:check(r) for r in nav['data']}
    assert strings=={'0xa67aa0':'获得图片大小失败\n\0'.encode('gbk'),
                     '0xa67ab8':'没有指定获得图片大小的函数\n\0'.encode('gbk')}
    # 从真实mov源偏移和push顺序重建复制参数，不用作者模型推断复制顺序。
    copy=functions['0x8e1930']
    expected_copy=[('0x8e2230',0,None)]
    for target,offset in [('0x8e1c40',32),('0x8e1c70',24),('0x8e1d10',28),('0x8e1db0',36),
                          ('0x8e1ef0',40),('0x8e1f20',44),('0x8e1f50',48),('0x8e1f80',52)]:
        expected_copy.extend((target,offset+40*i,i) for i in (0,2,1,3))
    expected_copy.extend([('0x8e21d0',8,None),('0x8e2200',12,None),('0x8e1fb0',4,None)])
    assert len(copy['calls'])==len(expected_copy)==36
    begin=0x8e193d
    for call,(target,offset,index) in zip(copy['calls'],expected_copy):
        site=int(call['site'],16)
        segment=[i for i in copy['assembly'] if begin<=int(i['va'],16)<site]
        loads=[i for i in segment if re.match(r'mov\s+(eax|ecx|edx), \[edi(?:\+[^]]+)?\]$',i['text'])]
        assert len(loads)==1 and call['implementation']==target
        raw=disk(int(loads[0]['va'],16),6)
        assert raw[0]==0x8b and raw[1]&7==7
        mod=raw[1]>>6
        actual_offset=0 if mod==0 else struct.unpack_from('<b' if mod==1 else '<i',raw,2)[0]
        assert actual_offset==offset
        pushes=[i['text'].split(';')[0].split()[-1] for i in segment if i['text'].startswith('push ')]
        register=loads[0]['text'].split()[1].rstrip(',')
        assert pushes==[register,'ebx'] if index is None else pushes==[register,str(index),'ebx']
        begin=site+5
    # 基础构造默认值只作既有证据复核，单列字节，不加入本批20函数。
    prior_ctor=json.loads((HERE.parents[1]/'控件回调与事件表/证据/注册与生命周期.json').read_text(encoding='utf-8-sig'))
    assert prior_ctor['disk_sha256']==SHA
    ctor=next(f for f in prior_ctor['functions'] if f['va']=='0x8e0af0')
    reused_bytes=0
    for row in ctor['byte_ranges']:
        va,size=int(row['va'],16),row['size']
        raw=bytes.fromhex(row['idb_hex'])
        assert raw==disk(va,size)==bytes.fromhex(row['disk_hex']) and row['matching']
        if db is not None:assert db.bytes.get_bytes_at(va,size)==raw
        reused_bytes+=size
    if db is not None:
        live=db.functions.get_at(0x8e0af0)
        actual={i.ea:db.instructions.get_disassembly(i) for c in db.functions.get_chunks(live) for i in db.instructions.get_between(c.start_ea,c.end_ea)}
        assert actual=={int(i['va'],16):i['text'] for i in ctor['assembly']}
    if db is not None:
        for (va,size),raw in ranges.items():assert db.bytes.get_bytes_at(va,size)==raw
    review=read('function_review.json')
    assert review['counts']=={'局部语义已审阅':15,'部分分析':5} and review['reused_count']==5
    assert {r['va'] for r in review['functions']}==set(functions)
    for row in review['functions']:
        assert row['status']==row['review_status'] and row['full_dependency_closure'] is False
        assert row['conclusion'] and row['unknown']
        assert row['reviewed_chunks']==(functions[row['va']]['declared_chunks'] if row['status']=='局部语义已审阅' else [])
        for name in row['evidence']:assert any(f['va']==row['va'] for f in read(name)['functions'])
    assert {r['va'] for r in review['functions'] if r['reused_from']}=={'0x8e1c40','0x6e2e60','0x8e86a0','0x8e86c0','0x8e8620'}
    for path in HERE.parent.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    covered=set()
    for va,size in ranges:covered.update(range(va,va+size))
    return dict(pe_sha256=SHA,mode='live' if db is not None else 'local',functions=len(functions),
                instructions=instructions,declared_chunks=chunks,resolved_calls=calls,register_import_calls=register_calls,
                unresolved_calls=indirect,function_references=refs,bridges=len(thunks),comparisons=comparisons,
                unique_ranges=len(ranges),union_bytes=len(covered),navigation_records=len(nav['inbound']),
                windows=1,window_bytes=37,window_instructions=12,strings=2,reused_functions=5,
                copy_call_argument_checks=36,reused_constructor_bytes=reused_bytes,
                model=model_check(),differences=0,
                limitation='静态限定契约；默认回调外部资源管理器、重入、异常与字符串别名未闭合。')


def export_assembly():
    lines=['// 独审阅读副本：20入口完整声明块及一个调用者窗口。']
    for name in SOURCES:
        for f in read(name)['functions']:
            lines.extend(['//','// '+f['va']+' '+f['name']])
            lines.extend('// '+i['va']+' '+i['text'] for i in f['assembly'])
    for w in read('navigation.json')['windows']:
        lines.extend(['//','// 窗口 '+w['start_va']+'..'+w['end_va']])
        lines.extend('// '+i['va']+' '+i['text'] for i in w['assembly'])
    (HERE/'independent_assembly.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':
    result=audit()
    (HERE/'independent_local.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    export_assembly()
    print(json.dumps(result,ensure_ascii=False))
