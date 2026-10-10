"""作者适配与验证；旧原证以JSON文本隔离，防止历史状态被中央递归重复认领。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT/'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '6dafad4aa131c1c24e4b78beb454ade0860e5e97692b553d028c0d26a2c26681'
SOURCE_HASHES = {
 '专题/角色与精灵动画/证据/角色精灵_IDA原始导出.json':'d749d7aa97c6ed034c6910691c6aab81aa8bbec365632fffcda0ca32e9246d47',
 '专题/提示文本生命周期/证据/lifecycle.json':'172aa6b273f084b8ff97e5dd49228e72e7a5f16a303a30bfc1e5010fc9101b2f',
 '专题/界面系统/第二批/ida_ui_batch2_raw.json':'adcc62abdf0eb16cc1baa3944ec9f2315ec29104096782877641fed87cd87c3f',
 '专题/角色1416字段来源/证据/functions.json':'30e9cb669ab4fae9930d98cbf47349364c130ad1597b2fea216bf079d30d4224',
 '专题/TeachMode对象与消费者/证据/teachmode_raw.json':'731f48028d5d68698809e4adefc6e41cec7262dda2434f9e5188606852d84240',
}
SPECS = [
 ('专题/角色与精灵动画/证据/角色精灵_IDA原始导出.json','/functions/0'),
 ('专题/提示文本生命周期/证据/lifecycle.json','/functions/5'),
 ('专题/界面系统/第二批/ida_ui_batch2_raw.json','/functions/0x6e93d0'),
 ('专题/角色1416字段来源/证据/functions.json','/functions/27'),
 ('专题/角色1416字段来源/证据/functions.json','/functions/28'),
 ('专题/角色1416字段来源/证据/functions.json','/functions/7'),
 ('专题/TeachMode对象与消费者/证据/teachmode_raw.json','/functions/50'),
 ('专题/TeachMode对象与消费者/证据/teachmode_raw.json','/functions/66'),
 *[('专题/TeachMode对象与消费者/证据/teachmode_raw.json','/functions/'+str(i)) for i in (91,92,93,94,95,109,110,112,113,119)],
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path,value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n','utf-8')


def pointer(value,path):
    for key in path.strip('/').split('/'):
        value = value[int(key)] if isinstance(value,list) else value[key]
    return value


def main():
    image = (ROOT/'RnClient.exe').read_bytes()
    assert sha(image) == SHA
    nt = struct.unpack_from('<I',image,60)[0]
    base = struct.unpack_from('<I',image,nt+52)[0]
    st = nt+24+struct.unpack_from('<H',image,nt+20)[0]
    sections = [struct.unpack_from('<4I',image,st+40*i+8) for i in range(struct.unpack_from('<H',image,nt+6)[0])]
    decoder = Cs(CS_ARCH_X86,CS_MODE_32)
    checks, decoded, transcript = [], {}, []
    def disk(va,size):
        hits = [(r,o) for _,r,n,o in sections if base+r<=va and va+size<=base+r+n]
        assert len(hits)==1,(hex(va),size)
        r,o = hits[0]
        return image[o+va-base-r:o+va-base-r+size]
    def audit(row,va=None):
        va = va if va is not None else int(row.get('start_va',row.get('va',row.get('start'))),16)
        rawhex = row.get('idb_hex',row.get('bytes_hex',row.get('idb_bytes_hex')))
        size = row.get('size',len(bytes.fromhex(rawhex)))
        code = disk(va,size)
        assert code.hex()==rawhex.lower()
        if row.get('disk_hex') is not None: assert code.hex()==row['disk_hex'].lower()
        if row.get('sha256') is not None: assert sha(code)==row['sha256'].lower()
        assert row.get('matching',row.get('equal',True)) is True
        checks.append((hex(va),size,sha(code)))
        return code
    def decode_ranges(ranges):
        result=[]
        for row in ranges:
            va=int(row.get('start_va',row.get('va',row.get('start'))),16)
            code=audit(row)
            ins=list(decoder.disasm(code,va))
            assert sum(i.size for i in ins)==len(code)
            for i in ins:
                text=i.mnemonic+' '+i.op_str
                decoded[i.address]=text
                result.append(dict(site_va=hex(i.address),size=i.size,hex=i.bytes.hex(),text=text))
        return result
    raw_bytes=(HERE/'bounded_raw.json').read_bytes()
    assert sha(raw_bytes)==RAW_SHA
    raw=json.loads(raw_bytes)
    assert raw['disk_sha256']==SHA
    assert [f['seed_va'] for f in raw['functions']]==['0x6423c0','0x6fc210']
    formal=[]
    for index,f in enumerate(raw['functions']):
        ins=decode_ranges(f['chunk_byte_ranges'])
        assert [i['site_va'] for i in ins]==[r['site_va'] for r in f['assembly']]
        formal.append(dict(f,va=f['seed_va'],source_path='专题/角色外观描述与界面实例/证据/bounded_raw.json',
                           source_pointer='/functions/'+str(index),source_sha256=RAW_SHA,
                           byte_ranges=f['chunk_byte_ranges'],scope='新主体无损适配；语义状态只在清单',
                           decoded_instructions=ins))
        transcript += ['// 新主体 '+f['seed_va']] + ['// '+i['site_va']+' '+i['text'] for i in ins]
    assert sum(len(f['assembly']) for f in formal)==80
    assert sum(r['size'] for f in formal for r in f['chunk_byte_ranges'])==334
    audits={r['seed_va']:r for r in raw['current_chunk_audits']}
    current_old=[]
    for r in raw['current_chunk_audits']:
        ins=decode_ranges(r['chunk_byte_ranges'])
        if r['seed_va'] not in ['0x6423c0','0x6fc210']:
            current_old.append(dict(reference_va=r['seed_va'],chunks=r['chunk_byte_ranges'],pe_instructions=ins,
               scope='当前IDA逐块字节审计；这里的正文由离线PE解码，不冒充旧IDA完整汇编'))
    references=[]
    for path,ptr in SPECS:
        data=(DOCS/path).read_bytes()
        assert sha(data)==SOURCE_HASHES[path]
        f=pointer(json.loads(data),ptr)
        va=f.get('va',f.get('address'))
        ranges=f.get('chunk_byte_ranges',f.get('byte_ranges',f.get('chunks')))
        if ranges is None:
            ranges=[dict(va=va,idb_hex=f['idb_bytes_hex'],size=len(bytes.fromhex(f['idb_bytes_hex'])))]
        ins=decode_ranges(ranges)
        assembly=f.get('assembly',f.get('instructions'))
        sites=[r.get('site_va',r.get('va',r.get('ea',r.get('address')))) for r in assembly]
        # 旧工厂只保存主块；当前异常尾由current_old独立承接。
        assert sites==[r['site_va'] for r in ins]
        references.append(dict(reference_va=va,source_path=path,source_pointer=ptr,source_sha256=sha(data),
             source_record_json=json.dumps(f,ensure_ascii=False,separators=(',',':')),
             checked_ranges=[dict(start_va=hex(int(r.get('start_va',r.get('va',r.get('start'))),16)),
                   size=len(bytes.fromhex(r.get('idb_hex',r.get('bytes_hex')))),
                   sha256=sha(bytes.fromhex(r.get('idb_hex',r.get('bytes_hex'))))) for r in ranges],
             pe_instructions=ins,scope='旧契约有限复用；原记录含历史状态的字段只封装为文本，不重复认领'))
    def callcheck(site,target,endpoint,chain):
        va=int(site,16); at=int(target,16); code=disk(va,5)
        assert code[0] in (0xe8,0xe9) and va+5+struct.unpack_from('<i',code,1)[0]==at
        for bridge in chain:
            assert at==int(bridge,16)
            code=disk(at,5)
            assert code[0]==0xe9
            at+=5+struct.unpack_from('<i',code,1)[0]
        assert at==int(endpoint,16)
    for c in raw['calls']:callcheck(c['site_va'],c['target_va'],c['implementation_va'],c['bridges'])
    for bridge in raw['verified_direct_bridges']:
        audit(bridge)
        callcheck(bridge['start_va'],bridge['target_va'],bridge['target_va'],[])
    windows=raw['explicit_owner_windows']+[e['owner_window'] for rs in raw['incoming'].values() for e in rs if 'owner_window' in e]
    for window in windows:
        for item in window['assembly']:
            code=audit(item['bytes'],int(item['site_va'],16))
            if item['is_code']:
                ins=list(decoder.disasm(code,int(item['site_va'],16)))
                assert len(ins)==1 and ins[0].size==len(code)
    for r in raw['data_windows']:audit(r)
    assert disk(0xa27600,4)==struct.pack('<I',0x605a72)
    for src in raw['reuse_sources']:assert sha((DOCS/src['path']).read_bytes())==src['source_sha256']
    assert sha((DOCS/'专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes())==raw['exporter_sha256']
    unwind_bytes=(HERE/'unwind_data/bounded_raw.json').read_bytes()
    assert sha(unwind_bytes)=='42455681bc0cc25078a04e6af762c5d5afb8a5851ae2c0b0c1f6059d038f1d9e'
    unwind=json.loads(unwind_bytes)
    assert unwind['disk_sha256']==SHA and len(unwind['data_windows'])==7
    for r in unwind['data_windows']:audit(r)
    assert struct.unpack('<8I',disk(0xa58b60,32))==(0x19930520,2,0xa58b50,0,0,0,0,0)
    assert struct.unpack('<4I',disk(0xa58b50,16))==(0xffffffff,0xa13eb0,0,0xa13eb8)
    assert struct.unpack('<8I',disk(0xa57fcc,32))==(0x19930520,1,0xa57fc4,0,0,0,0,0xffffffff)
    assert struct.unpack('<2I',disk(0xa57fc4,8))==(0xffffffff,0xa135b9)
    for src,dst in [(0x605590,0x6e1dd0),(0x60002c,0x642580),(0x60657b,0x91fe50)]:
        callcheck(hex(src),hex(dst),hex(dst),[])
    # 精确检查短描述的全部16次写入及返回，不从“清零”概述推出填充字节。
    writes=[0x6423d1,0x6423da,0x6423e4,0x6423ee,0x6423f8,0x642402,0x64240c,0x642416,
            0x642420,0x64242a,0x642434,0x64243e,0x642448,0x642452,0x64245c]
    for n,site in enumerate(writes):
        text=decoded[site]
        assert text.startswith('mov dword ptr') and text.endswith(', 0')
        if n:assert (' + '+(str(n*4) if n*4<10 else hex(n*4))+']') in text
    assert decoded[0x642466]=='mov byte ptr [eax + 0x3c], 0'
    anchors={0x64246a:'mov eax, dword ptr [ebp - 4]',0x642470:'ret ',0x6fc24e:'add ecx, 0x94',
             0x6fc260:'add ecx, 0x2b0',0x6fc245:'mov dword ptr [eax], 0xa27600',
             0x6fc23b:'mov dword ptr [ebp - 4], 0',0x6fc259:'mov byte ptr [ebp - 4], 1',
             0x6fc26b:'mov dword ptr [ebp - 4], 0xffffffff',0xa13eb3:'jmp 0x605590',
             0xa13ebb:'add ecx, 0x94',0xa13ec1:'jmp 0x60002c',0x6e9400:'push 0x2fc',
             0x6e941b:'je 0x6e942a',0xa135bd:'call 0x604cfd'}
    for va,text in anchors.items():assert decoded[va]==text,(hex(va),decoded[va],text)
    old_anchors={0x63f181:'mov eax, dword ptr [eax + 0x5b4]',0x691b81:'mov eax, dword ptr [eax + 0x28]',
       0x7fd7b1:'mov al, byte ptr [eax + 0x588]',0x642762:'cmp edx, dword ptr [ecx]',
       0x642764:'jne 0x642778',0x64276c:'mov edx, dword ptr [eax + 0x2c]',
       0x64276f:'cmp edx, dword ptr [ecx + 0x24]',0x642772:'je 0x642862',
       0x64279a:'movzx eax, byte ptr [edx + 0x3c]',0x6427a0:'jne 0x642801'}
    for entry,offset in [(0x728390,0xac),(0x7283c0,0xb0),(0x7283f0,0xb4),(0x728420,0xb8),
                         (0x728450,0xbc),(0x7d7a00,0x90),(0x7d7a30,0x94),(0x7d7ac0,0xa4),(0x7d7b20,0xc0)]:
        old_anchors[entry+0x11]='mov eax, dword ptr [eax + '+hex(offset)+']'
        old_anchors[entry+0x17]='and eax, 0xfff'
    for va,text in old_anchors.items():assert decoded[va]==text,(hex(va),decoded[va],text)
    caller_rows=[]
    for idx,lo,hi in [(27,0x7f438b,0x7f4429),(28,0x7f45d1,0x7f466f)]:
        blob=(DOCS/'专题/角色1416字段来源/证据/functions.json').read_bytes()
        f=json.loads(blob)['functions'][idx]
        records=[r for r in f['assembly'] if lo<=int(r['va'],16)<hi]
        calls=[c for c in f['calls'] if lo<=int(c['site'],16)<hi]
        for c in calls:callcheck(c['site'],c['target'],c['implementation'],c['thunks'])
        assert len(records)==43 and len(calls)==14
        stack_base=0x6c if idx==27 else 0x48
        offsets=[0,0xc,0x10,0x14,0x1c,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c]
        write_sites=([0x7f439b,0x7f43a6,0x7f43b1,0x7f43bc,0x7f43c7,0x7f43d2,
                      0x7f43dd,0x7f43e8,0x7f43f3,0x7f43fe,0x7f4409,0x7f4414] if idx==27 else
                     [0x7f45e1,0x7f45ec,0x7f45f7,0x7f4602,0x7f460d,0x7f4618,
                      0x7f4623,0x7f462e,0x7f4639,0x7f4644,0x7f464f,0x7f465a])
        for site,offset in zip(write_sites,offsets):
            width,register=('byte','al') if offset==0x3c else ('dword','eax')
            expected='mov '+width+' ptr [ebp - '+hex(stack_base-offset)+'], '+register
            assert decoded[site]==expected,(hex(site),decoded[site],expected)
        assert decoded[0x7f441e if idx==27 else 0x7f4664]=='add ecx, 0x360'
        caller_rows.append(dict(owner_va=f['va'],source_path='专题/角色1416字段来源/证据/functions.json',
             source_pointer='/functions/'+str(idx),source_sha256=sha(blob),start_va=hex(lo),end_va=hex(hi),
             instructions=records,calls=calls,scope='旧完整原证中的描述填充局部片段，不重复认领caller完整语义'))
    new_manifest=[]
    for i,f in enumerate(formal):
        address=f['va']
        conclusion=('15个DWORD和+3C BYTE清0，返回原this；只证明61字节可见写入，不证明sizeof或尾padding。' if i==0 else
                    '先基类构造再写A27600表址，以this+94与this+2B0构造运行时子对象和短描述；EH状态映射单列，未证明完整异常安全。')
        selected=[r for r in f['decoded_instructions'] if int(r['site_va'],16) in set(writes+[0x642466])|set(anchors)]
        new_manifest.append(dict(va=address,status='静态契约已审阅',conclusion=conclusion,
            evidence='证据/formal_functions.json',source_ref=dict(path='证据/bounded_raw.json',pointer='/functions/'+str(i),sha256=RAW_SHA),
            unknown='调用触发、完整虚表和所有权、实时视觉效果、异常后端均未验证；不恢复源码类名或sizeof',
            declared_chunks=f['chunk_byte_ranges'],semantic_anchors=selected))
    save(HERE/'formal_functions.json',dict(disk_sha256=SHA,functions=formal))
    save(HERE/'reused_sources.json',dict(disk_sha256=SHA,records=references,current_old_audits=current_old))
    save(HERE/'caller_fill_windows.json',dict(disk_sha256=SHA,records=caller_rows))
    save(HERE.parent/'函数审阅清单.json',dict(disk_sha256=SHA,functions=new_manifest,
         summary=dict(new_functions=2,new_bytes=334,new_instructions=80,reused_seed_bytes=463,reused_seed_instructions=115,
                      warning='旧原记录封装为source_record_json，不从旧结论再生成显式审阅记录')))
    (HERE/'author_assembly.txt').write_text('\n'.join(transcript)+'\n','utf-8')
    for doc in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in doc.read_text('utf-8').splitlines()),doc
    result=dict(status='PASS',raw_sha256=RAW_SHA,unwind_raw_sha256=sha(unwind_bytes),new_functions=2,
       new_bytes=334,new_instructions=80,old_seed_bytes=463,old_seed_instructions=115,reuse_records=len(references),
       ranges_checked=len(checks),unique_ranges=len(set(checks)),direct_calls=len(raw['calls']),bridges=len(raw['verified_direct_bridges']),
       windows=len(windows),explicit_owner_windows=5,semantic_checks=len(writes)+1+len(anchors)+len(old_anchors)+26,
       scope='当前PE/原证与局部契约核验；不启动游戏、不修改原证或中央、不模拟全部CRT')
    save(HERE/'author_validation.json',result)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    main()
