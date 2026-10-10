"""独审只读PE与IDA复读；不改作者证据、不写IDB，只新增独审结果。"""
import hashlib
import json
import struct
from pathlib import Path

HERE=Path('F:/大富翁online/Richonline/docs/逆向资料/专题/727F控件状态接口')
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def entries():
    namespace={'__file__':str(HERE/'evidence_sources.py')}
    exec((HERE/'evidence_sources.py').read_text(encoding='utf-8'),namespace)
    return namespace['records']()


def audit(db):
    import ida_bytes
    failures=[]
    details=[]
    sources={}
    for row in entries():
        f=row['function']; va=int(f['va'],16)
        chunks=list(db.functions.get_chunks(db.functions.get_at(va)))
        expected=f.get('declared_chunks')
        if not row['reused'] or va==0x7113A0:
            actual=[(c.start_ea,c.end_ea) for c in chunks]
            if actual!=[(int(c['start_va'],16),int(c['end_va'],16)) for c in expected]:
                failures.append(f['va']+':声明块不同')
            heads={i.ea for c in chunks for i in db.instructions.get_between(c.start_ea,c.end_ea)
                   if ida_bytes.is_code(ida_bytes.get_full_flags(i.ea))}
            if heads!={int(i['va'],16) for i in f['assembly']}:
                failures.append(f['va']+':代码头不同')
        for r in f['byte_ranges']+f.get('chunk_byte_ranges',[]):
            if db.bytes.get_bytes_at(int(r['va'],16),r['size']).hex()!=r['idb_hex']:
                failures.append(r['va']+':字节不同')
        source=sources.setdefault(row['source'],json.loads((HERE/row['source']).read_text(encoding='utf-8')))
        needed={t for c in f.get('calls',[]) for t in c.get('thunks',[])}
        for r in source.get('thunks',[]):
            if r['va'] in needed and db.bytes.get_bytes_at(int(r['va'],16),r['size']).hex()!=r['idb_hex']:
                failures.append(r['va']+':E9不同')
        details.append(dict(va=f['va'],reused=row['reused'],live_chunks=len(chunks),saved_instructions=len(f['assembly'])))
    for name in ('navigation.json','local_navigation.json'):
        for r in json.loads((HERE/'证据'/name).read_text(encoding='utf-8'))['references']:
            if db.bytes.get_bytes_at(int(r['site'],16),5).hex()!=r['raw5']:
                failures.append(r['site']+':导航字节不同')
    # 封装的RTC调用正常路径须保留EAX，不能仅凭函数名假设。
    rtc=db.functions.get_at(0x91F6D0)
    rtc_chunks=list(db.functions.get_chunks(rtc))
    rtc_record=dict(va=hex(rtc.start_ea),chunks=[dict(va=hex(c.start_ea),size=c.end_ea-c.start_ea,
        idb_hex=db.bytes.get_bytes_at(c.start_ea,c.end_ea-c.start_ea).hex()) for c in rtc_chunks],
        assembly=[dict(va=hex(i.ea),text=db.instructions.get_disassembly(i)) for c in rtc_chunks
                  for i in db.instructions.get_between(c.start_ea,c.end_ea)])
    result=dict(status='PASS' if not failures else 'FAIL',failures=failures,functions=details,rtc=rtc_record,
                execution_provenance='独审者编写只读脚本，主级审读并持IDA lease代跑；不是独审者独立连接',
                scope='15个重采入口完整块与代码头复读，其中7113A0计旧专题复核；另9个复用入口仅保存范围字节，导航不升格函数语义')
    (HERE/'独审_IDA结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(status=result['status'],records=len(details),failures=failures)


def offline():
    image=(HERE.parents[3]/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==SHA
    pe=struct.unpack_from('<I',image,0x3C)[0]
    assert image[pe:pe+4]==b'PE\0\0'
    base=struct.unpack_from('<I',image,pe+52)[0]
    optional=struct.unpack_from('<H',image,pe+20)[0]
    sections=[struct.unpack_from('<IIII',image,pe+24+optional+40*i+8)
              for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    spans=[]; bridges=set(); newbytes=0
    def disk(va,size):
        for _,rva,rawsize,offset in sections:
            delta=va-base-rva
            if 0<=delta and delta+size<=rawsize:
                return image[offset+delta:offset+delta+size]
        raise ValueError(hex(va))
    def check(r):
        va=int(r['va'],16);raw=disk(va,r['size'])
        assert raw.hex()==r['idb_hex']
        if r.get('disk_hex') is not None:
            assert raw.hex()==r['disk_hex']
        spans.append((va,r['size']))
        return raw
    rows=entries(); assert len(rows)==24 and sum(not r['reused'] for r in rows)==14
    sources={}
    for row in rows:
        f=row['function']
        for r in f['byte_ranges']+f.get('chunk_byte_ranges',[]):
            check(r)
        if not row['reused']:
            newbytes+=sum(r['size'] for r in f['chunk_byte_ranges'])
        source=sources.setdefault(row['source'],json.loads((HERE/row['source']).read_text(encoding='utf-8')))
        needed={t for c in f.get('calls',[]) for t in c.get('thunks',[])}
        for r in source.get('thunks',[]):
            if r['va'] not in needed:
                continue
            raw=check(r);va=int(r['va'],16)
            assert raw[0]==0xE9 and va+5+int.from_bytes(raw[1:],'little',signed=True)==int(r['target'],16)
            bridges.add(va)
    nav=0
    for name in ('navigation.json','local_navigation.json'):
        for r in json.loads((HERE/'证据'/name).read_text(encoding='utf-8'))['references']:
            va=int(r['site'],16);raw=disk(va,5)
            assert raw.hex()==r['raw5']
            spans.append((va,5));nav+=1
            if r['kind'] in (16,17,19) and raw[0] in (0xE8,0xE9):
                assert va+5+int.from_bytes(raw[1:],'little',signed=True)==int(r['target'],16)
    covered={a for va,size in spans for a in range(va,va+size)}
    assert (newbytes,len(spans),len(covered),len(bridges),nav)==(1949,398,8020,84,234)
    # EAX指向栈的结论直接基于机器编码，不依赖符号变量名称。
    for va,expected in [(0x8E0590,'81ec040100005657'),(0x8E05DA,'8d4424085f5e81c404010000c3'),
                        (0x8E060B,'5f8d4424045e81c404010000c3')]:
        assert disk(va,len(bytes.fromhex(expected))).hex()==expected
    namespace={'__name__':'independent_model'}
    exec((HERE/'model_interfaces.py').read_text(encoding='utf-8'),namespace)
    author=namespace['check_model']()
    own=independent_models()
    live=None
    if (HERE/'独审_IDA结果.json').exists():
        live=json.loads((HERE/'独审_IDA结果.json').read_text(encoding='utf-8'))
        assert not live['failures']
        for r in live['rtc']['chunks']:
            assert disk(int(r['va'],16),r['size']).hex()==r['idb_hex']
    result=dict(status='PASS',sha256=SHA,new_functions=14,reused_functions=10,new_declared_bytes=newbytes,
                comparison_records=len(spans),union_bytes=len(covered),attached_e9=len(bridges),navigation=nav,
                author_model=author,independent_model=own,live_recheck=live is not None,
                scope='24条记录不等于24新增函数；14新增为12局部契约和2部分分析，7113A0为重采旧专题复核')
    (HERE/'独审_离线结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=True))


def independent_models():
    for value in range(65536):
        word=bytearray(struct.pack('<H',value))
        cx=(int.from_bytes(word,'little')+1)&65535
        word[:]=cx.to_bytes(2,'little')
        assert int.from_bytes(word,'little')==(value+1)%65536
    paths=[]
    for entry in (0x10000,0x12345000,0x7FFEF000):
        esp=entry-0x104-4-4
        buf=esp+8
        callback_eax=esp+8
        after_callback=esp+4+4+0x104+4
        esp+=4
        default_eax=esp+4
        after_default=esp+4+0x104+4
        assert buf==callback_eax==default_eax==entry-260
        assert after_callback==after_default==entry+4
        assert buf+260==entry
        paths.append(dict(entry=hex(entry),returned=hex(buf),restored=hex(after_default)))
    # 独立展示边界而不访问进程：三段WORD复制消耗的单元不带自动终止字。
    capacity=[]
    for prefix,insert,suffix in [(0,1,0),(100,10000,139),(100,10000,140),(100,10000,141)]:
        writes=prefix+insert+suffix
        capacity.append(dict(prefix=prefix,insert=insert,suffix=suffix,writes=writes,
                             trailing_zero_available=writes<10240,outside_writes=max(0,writes-10240)))
    assert capacity[-2]['writes']==10240 and not capacity[-2]['trailing_zero_available']
    assert capacity[-1]['outside_writes']==1
    for base in (0,0x10000000,0xFFFFFF00):
        assert (base+0xEA0+5000*2)&0xFFFFFFFF == (base+0xEA0+10000)&0xFFFFFFFF
    return dict(word_cases=65536,stack_paths=paths,concat_boundaries=capacity,
                alias_examples=3,not_runtime_execution=True)


if __name__=='__main__':
    offline()
