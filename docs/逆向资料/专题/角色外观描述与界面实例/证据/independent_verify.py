"""第二十八批角色描述独立审阅；只读PE和原证，不调用IDA或作者代码。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
ROOT = HERE.parents[4]
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '6dafad4aa131c1c24e4b78beb454ade0860e5e97692b553d028c0d26a2c26681'
UNWIND_SHA = '42455681bc0cc25078a04e6af762c5d5afb8a5851ae2c0b0c1f6059d038f1d9e'
FINAL_SHA = {
 '00_有限采证实施计划.txt':'5839dc53d87ae6e0426ecfdf45a2bdd94593ef9627090610632571fc117daa79',
 '01_阅读入口与结构分界.txt':'faaf3b3a029a02e1a06740f4dd5301755e0481996d53bf769f8546d5ee9f6d13',
 '02_短描述默认值与角色填充.txt':'745b56f27c62eb380a7750fa71370baf30f849e35f0e587b7d4c6be75009fbb5',
 '03_界面构造与工厂边界.txt':'307b2857e43b8ae0389a1387a53824b35b721f5faf9a5d3af36f922674dea501',
 '04_异常表与回收动作边界.txt':'238539960ee1ec0e154a94f3230ae0ba1f37d9f39ff32c2bb9c42d81ca69688a',
 '05_证据范围与复跑.txt':'3a56159a2bd8c0b811079ab08650659657fa817128256991d94c973bc428821b',
 '07_独立审阅报告.txt':'89b16530662a06276add01696a74616796183e87cd578332d91b6bf3909fac66',
 '函数审阅清单.json':'db0b58b59c34bd12ced52620bd0e2e72524b31958514df932cf56c78c4e6109d',
 '证据/author_assembly.txt':'2e9e56f6dd4b7123f421cf3629973f3b8ffd2524f8647e8284a59ba5942e1061',
 '证据/author_validation.json':'70b5857c8aad6c45b71722df4dfaa167abe161759d95296d54d8e387e557a0d7',
 '证据/bounded_raw.json':'6dafad4aa131c1c24e4b78beb454ade0860e5e97692b553d028c0d26a2c26681',
 '证据/build_author.py':'e896393dfd891652374f3d9206b2e53f477cc8c7418302e393867c68c42d96f5',
 '证据/caller_fill_windows.json':'039a784838fec34740331a821f831c24b29cd6430faed3bab952b33db69b1f54',
 '证据/export_bounded.py':'ceaf00fb896cd8cb470689eefad3856413e289b67534566fae3e134560f4d05e',
 '证据/export_unwind_data.py':'7a0595591c2ce4fd6c20ecd9debfbb479275c6353a95801fe087638d58d9684e',
 '证据/formal_functions.json':'8d492b239c51449c159a4a36115f8097da58ee3716da81e9f7dba134d5913416',
 '证据/reused_sources.json':'c3f0851268e8f8aa1b87380cb635c79083e50a10475c30296fea277adae790c4',
 '证据/unwind_data/bounded_raw.json':'42455681bc0cc25078a04e6af762c5d5afb8a5851ae2c0b0c1f6059d038f1d9e',
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    image = (ROOT/'RnClient.exe').read_bytes()
    assert sha(image)==PE_SHA
    nt = struct.unpack_from('<I',image,60)[0]
    assert image[:2]==b'MZ' and image[nt:nt+4]==b'PE\0\0'
    base = struct.unpack_from('<I',image,nt+52)[0]
    section_at = nt+24+struct.unpack_from('<H',image,nt+20)[0]
    sections = [struct.unpack_from('<4I',image,section_at+40*i+8)
                for i in range(struct.unpack_from('<H',image,nt+6)[0])]
    decoder = Cs(CS_ARCH_X86,CS_MODE_32)
    decoder.detail = True
    ranges, instructions, transcript = set(), {}, []

    def read(va,size):
        matches = [off+va-base-rva for _,rva,length,off in sections
                   if rva<=va-base and va-base+size<=rva+length]
        assert len(matches)==1
        return image[matches[0]:matches[0]+size]

    def audit(row):
        va = int(row.get('start_va',row.get('va')),16)
        payload = read(va,row['size'])
        assert payload.hex()==row['disk_hex']==row['idb_hex']
        assert row.get('matching',row.get('equal')) is True
        if 'sha256' in row: assert sha(payload)==row['sha256']
        ranges.add((va,len(payload)))
        return va,payload

    def decode(row):
        va,payload = audit(row)
        body = list(decoder.disasm(payload,va))
        assert sum(i.size for i in body)==len(payload)
        for i in body: assert instructions.setdefault(i.address,i).bytes==i.bytes
        return body

    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    assert sha(raw_bytes)==RAW_SHA
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256']==PE_SHA
    assert {f['seed_va'] for f in raw['functions']}=={'0x6423c0','0x6fc210'}
    assert {f['seed_va'] for f in raw['reused_seeds']}=={'0x642480','0x6e1d90','0x6e93d0'}
    sources = {}
    for ref in raw['reuse_sources']:
        p = DOCS/ref['path']
        assert sha(p.read_bytes())==ref['source_sha256']
        sources[ref['path']] = ref['source_sha256']
    bodies = {}
    for f in raw['current_chunk_audits']:
        body = [i for c in f['chunk_byte_ranges'] for i in decode(c)]
        bodies[f['seed_va']] = body
        transcript += ['// 声明块 '+f['seed_va']] + ['// '+hex(i.address)+' '+i.bytes.hex()+' '+i.mnemonic+' '+i.op_str for i in body]
    for f in raw['functions']:
        assert {i.address for i in bodies[f['seed_va']]}=={int(x['site_va'],16) for x in f['assembly']}
        assert f['chunk_byte_ranges']==next(x['chunk_byte_ranges'] for x in raw['current_chunk_audits'] if x['seed_va']==f['seed_va'])
    historical=[]
    for path,key,address in [
        ('专题/角色与精灵动画/证据/角色精灵_IDA原始导出.json',0,'0x642480'),
        ('专题/提示文本生命周期/证据/lifecycle.json',5,'0x6e1d90'),
        ('专题/界面系统/第二批/ida_ui_batch2_raw.json','0x6e93d0','0x6e93d0'),
    ]:
        f=json.loads((DOCS/path).read_bytes())['functions'][key]
        if 'idb_bytes_hex' in f:
            va=int(f['address'],16);old=bytes.fromhex(f['idb_bytes_hex'])
            asm=f['instructions']
        elif 'chunks' in f:
            chunk=f['chunks'][0];va=int(chunk['start'],16);old=bytes.fromhex(chunk['bytes_hex'])
            asm=f['assembly']
        else:
            chunk=f['byte_ranges'][0];va=int(chunk['va'],16);old=bytes.fromhex(chunk['idb_hex'])
            asm=f['assembly']
        assert read(va,len(old))==old
        old_sites=[int(x.get('va',x.get('ea')),16) for x in asm]
        assert old_sites==[i.address for i in bodies[address] if va<=i.address<va+len(old)]
        historical.append(dict(source=path,pointer='/functions/'+str(key),va=address,
            historical_instruction_count=len(asm),historical_bytes=len(old),
            scope='旧正文保留；当前新增声明尾块仅按本次IDA字节与PE解码单列'))
    bridges = {}
    for b in raw['verified_direct_bridges']:
        decoded = decode(b)
        assert len(decoded)==1 and decoded[0].mnemonic=='jmp'
        bridges[decoded[0].address]=int(decoded[0].op_str,16)
        assert bridges[decoded[0].address]==int(b['target_va'],16)
    for c in raw['calls']:
        i = instructions[int(c['site_va'],16)]
        assert i.mnemonic=='call' and int(i.op_str,16)==int(c['target_va'],16)
        target = int(i.op_str,16)
        for hop in c['bridges']:
            assert target==int(hop,16)
            target = bridges[target]
        assert target==int(c['implementation_va'],16)
    expected_calls = {i.address for b in bodies.values() for i in b if i.mnemonic=='call' and i.op_str.startswith('0x')}
    assert expected_calls=={int(c['site_va'],16) for c in raw['calls']}
    windows = raw['explicit_owner_windows']+[x['owner_window'] for es in raw['incoming'].values() for x in es if 'owner_window' in x]
    unique_windows = set()
    for w in windows:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        items = []
        for row in w['assembly']:
            decoded = decode(row['bytes'])
            assert len(decoded)==1 and decoded[0].address==int(row['site_va'],16)
            items.extend(decoded)
        assert all(a.address+a.size==b.address for a,b in zip(items,items[1:]))
        assert int(w['site_va'],16) in {i.address for i in items}
        unique_windows.add((w['owner_va'],w['site_va'],items[0].address,items[-1].address+items[-1].size))
    assert len(raw['data_windows'])==1
    va,prefix = audit(raw['data_windows'][0])
    assert va==0xa27600 and prefix==bytes.fromhex('725a6000')

    # 两个旧caller所有声明块直接复核；语义仅取外观描述局部填充段。
    caller_source = '专题/角色1416字段来源/证据/functions.json'
    caller_document = json.loads((DOCS/caller_source).read_bytes())
    callers = caller_document['functions']
    caller_counts = []
    for index in (27,28):
        f = callers[index]
        body = [i for c in f['chunk_byte_ranges'] for i in decode(c)]
        assert [i.address for i in body]==[int(x['va'],16) for x in f['assembly']]
        caller_counts.append(dict(va=f['va'],bytes=sum(i.size for i in body),instructions=len(body),
            scope='全部声明字节核对；只认外观填充路径语义'))

    # 逐条模拟初始化器的寄存器别名与存储宽度，边界外保持毒值。
    body = bodies['0x6423c0']
    regs, frame, writes = {'ecx':'this'}, {}, []
    for i in body:
        if i.mnemonic!='mov': continue
        dst,src = i.operands
        if src.type==X86_OP_IMM: value=src.imm
        elif src.type==X86_OP_REG: value=regs.get(i.reg_name(src.reg))
        elif src.type==X86_OP_MEM and i.reg_name(src.mem.base)=='ebp': value=frame.get(src.mem.disp)
        else: value=None
        if dst.type==X86_OP_REG: regs[i.reg_name(dst.reg)] = value
        elif dst.type==X86_OP_MEM:
            if i.reg_name(dst.mem.base)=='ebp': frame[dst.mem.disp]=value
            elif regs.get(i.reg_name(dst.mem.base))=='this':
                assert not dst.mem.index and value==0
                writes.append(dict(site=hex(i.address),offset=dst.mem.disp,width=dst.size,value=value))
    assert [(x['offset'],x['width']) for x in writes]==[(x,4) for x in range(0,60,4)]+[(60,1)]
    assert regs['eax']=='this'
    memory = bytearray([0xA5]*80)
    for w in writes: memory[8+w['offset']:8+w['offset']+w['width']]=bytes(w['width'])
    assert memory[:8]==bytes([0xA5]*8) and memory[8:69]==bytes(61) and memory[69:]==bytes([0xA5]*11)
    anchors = {}
    def anchor(va,mnemonic,op):
        i=instructions[va]
        assert (i.mnemonic,i.op_str)==(mnemonic,op),(hex(va),i.mnemonic,i.op_str)
        anchors[hex(va)]=dict(hex=i.bytes.hex(),mnemonic=mnemonic,operand=op)
    for row in [
        (0x6fc236,'call','0x605da6'),(0x6fc245,'mov','dword ptr [eax], 0xa27600'),
        (0x6fc23b,'mov','dword ptr [ebp - 4], 0'),(0x6fc259,'mov','byte ptr [ebp - 4], 1'),
        (0x6fc26b,'mov','dword ptr [ebp - 4], 0xffffffff'),
        (0x6fc24e,'add','ecx, 0x94'),(0x6fc254,'call','0x6118b3'),
        (0x6fc260,'add','ecx, 0x2b0'),(0x6fc266,'call','0x602acf'),
        (0x6e941b,'je','0x6e942a'),(0x6e9420,'call','0x5ff096'),
        (0x6e942a,'mov','dword ptr [ebp - 0x18], 0'),
        (0x6e1daa,'mov','dword ptr [ecx + 4], 0'),(0x6e1db4,'mov','dword ptr [edx + 0x30], 0'),
        (0x6e1dbe,'mov','dword ptr [eax + 0x38], 2'),
        (0x6424a1,'mov','dword ptr [eax], 0xfffffffe'),(0x6424aa,'mov','dword ptr [ecx + 4], 0xffffffff'),
        (0x6424b4,'mov','dword ptr [edx + 8], 0xffffffff'),(0x6424be,'mov','dword ptr [eax + 0xc], 0xffffffff'),
        (0x64254a,'mov','dword ptr [edx + 0x210], 0'),
        (0x642493,'add','ecx, 0x214'),(0x642559,'add','ecx, 0x214'),
        (0x7f441e,'add','ecx, 0x360'),(0x7f4424,'call','0x6007cf'),
        (0x7f4664,'add','ecx, 0x360'),(0x7f466a,'call','0x6007cf'),
    ]: anchor(*row)
    factory = bodies['0x6e93d0']
    assert any(i.mnemonic=='push' and i.op_str=='0x2fc' for i in factory)
    # 不把父槽间距当sizeof：仅算已见描述写入末字节2EC，距离分配末端仍有15字节。
    assert 0x2b0+61==0x2ed and 0x2fc-0x2ed==15
    fill_results=[]
    for start,end,stack_base in [(0x7f4393,0x7f4417,-0x6c),(0x7f45d9,0x7f465d,-0x48)]:
        body=[instructions[a] for a in sorted(instructions) if start<=a<end]
        stores=[]
        last_call=None
        for i in body:
            if i.mnemonic=='call': last_call=int(i.op_str,16)
            if i.mnemonic=='mov' and len(i.operands)==2:
                dst,src=i.operands
                if dst.type==X86_OP_MEM and i.reg_name(dst.mem.base)=='ebp' and src.type==X86_OP_REG:
                    stores.append(dict(site=hex(i.address),offset=dst.mem.disp-stack_base,width=dst.size,
                        source_register=i.reg_name(src.reg),getter_bridge=hex(last_call)))
        assert [(x['offset'],x['width']) for x in stores]==[(x,4) for x in [0,12,16,20,28,36,40,44,48,52,56]]+[(60,1)]
        fill_results.append(dict(start=hex(start),end=hex(end),writes=stores,unchanged_zero_dwords=[4,8,24,32]))
        transcript += ['// caller填充 '+hex(start)]+['// '+hex(i.address)+' '+i.bytes.hex()+' '+i.mnemonic+' '+i.op_str for i in body]
    assert [x['getter_bridge'] for x in fill_results[0]['writes']]==[x['getter_bridge'] for x in fill_results[1]['writes']]
    old_bridges = {x['va']:x for x in caller_document['thunks']}
    selected_old_bridges = {}
    for bridge in [x['getter_bridge'] for x in fill_results[0]['writes']]+['0x6007cf']:
        row=old_bridges[bridge]
        va,payload=audit(row)
        assert payload[0]==0xe9 and len(payload)==5
        target=va+5+struct.unpack_from('<i',payload,1)[0]
        assert target==int(row['target'],16)
        selected_old_bridges[bridge]=hex(target)
    assert selected_old_bridges['0x6007cf']=='0x642740'
    for path in fill_results:
        for row in path['writes']: row['getter_target']=selected_old_bridges[row['getter_bridge']]
    # 对补采FuncInfo前32B与完整已声明UnwindMap独立解码，不据自动类型名认原类。
    unwind_bytes=(HERE/'unwind_data/bounded_raw.json').read_bytes()
    assert sha(unwind_bytes)==UNWIND_SHA
    unwind_raw=json.loads(unwind_bytes)
    assert not unwind_raw['functions'] and not unwind_raw['seeds'] and len(unwind_raw['data_windows'])==7
    data={}
    for row in unwind_raw['data_windows']:
        addr,payload=audit(row)
        data[addr]=payload
    ctor_info=struct.unpack('<8I',data[0xa58b60])
    factory_info=struct.unpack('<8I',data[0xa57fcc])
    assert ctor_info==(0x19930520,2,0xa58b50,0,0,0,0,0)
    assert factory_info==(0x19930520,1,0xa57fc4,0,0,0,0,0xffffffff)
    ctor_map=[struct.unpack_from('<iI',data[0xa58b50],i*8) for i in range(2)]
    factory_map=[struct.unpack('<iI',data[0xa57fc4])]
    assert ctor_map==[(-1,0xa13eb0),(0,0xa13eb8)]
    assert factory_map==[(-1,0xa135b9)]
    unwind_bridges={}
    for addr,expected in [(0x605590,0x6e1dd0),(0x60002c,0x642580),(0x60657b,0x91fe50)]:
        b=data[addr]
        assert b[0]==0xe9 and addr+5+struct.unpack_from('<i',b,1)[0]==expected
        unwind_bridges[hex(addr)]=hex(expected)
    unwind_chains=[]
    for state in (0,1):
        actions=[]
        current=state
        while current>=0:
            following,action=ctor_map[current]
            actions.append(hex(action));current=following
        assert actions==(['0xa13eb0'] if state==0 else ['0xa13eb8','0xa13eb0'])
        unwind_chains.append(dict(state=state,actions=actions,end_state=current,
            scope='按表回溯状态，不模拟CRT异常运行'))
    # EH尾列实际指令与状态表；不把32B头前缀称完整FuncInfo。
    eh = []
    for va in ['0x6fc210','0x6e93d0']:
        eh += [dict(site=hex(i.address),mnemonic=i.mnemonic,operand=i.op_str)
               for i in bodies[va] if i.address>=0xa00000]
    reused=json.loads((HERE/'reused_sources.json').read_bytes())
    assert len(reused['records'])==18
    getter_bodies={}
    for record in reused['records']:
        source_bytes=(DOCS/record['source_path']).read_bytes()
        assert sha(source_bytes)==record['source_sha256']
        value=json.loads(source_bytes)
        for token in record['source_pointer'].strip('/').split('/'):
            value=value[int(token)] if isinstance(value,list) else value[token]
        assert json.loads(record['source_record_json'])==value
        if 'idb_bytes_hex' in value:
            old_chunks=[dict(va=value['address'],size=len(bytes.fromhex(value['idb_bytes_hex'])),
                idb_hex=value['idb_bytes_hex'],disk_hex=value['idb_bytes_hex'],matching=True)]
        elif 'chunks' in value and 'bytes_hex' in value['chunks'][0]:
            old_chunks=[dict(va=c['start'],size=len(bytes.fromhex(c['bytes_hex'])),
                idb_hex=c['bytes_hex'],disk_hex=c['bytes_hex'],matching=True) for c in value['chunks']]
        else: old_chunks=value.get('chunk_byte_ranges',value.get('chunks',value.get('byte_ranges')))
        b=[i for c in old_chunks for i in decode(c)]
        getter_bodies[int(record['reference_va'],16)]=b
        assert [x['hex'] for x in record['pe_instructions']]==[i.bytes.hex() for i in b]
        assert [int(x['site_va'],16) for x in record['pe_instructions']]==[i.address for i in b]
    getter_contracts=[]
    specs=[(0x691b70,0x28,4,None),(0x63f170,0x5b4,4,None),
        (0x7d7a00,0x90,4,0xfff),(0x7d7a30,0x94,4,0xfff),(0x7d7ac0,0xa4,4,0xfff),
        (0x728390,0xac,4,0xfff),(0x7283c0,0xb0,4,0xfff),(0x7283f0,0xb4,4,0xfff),
        (0x728420,0xb8,4,0xfff),(0x728450,0xbc,4,0xfff),(0x7d7b20,0xc0,4,0xfff),
        (0x7fd7a0,0x588,1,None)]
    for addr,offset,width,mask in specs:
        b=getter_bodies[addr]
        reads=[i for i in b if i.mnemonic=='mov' and len(i.operands)==2 and i.operands[0].type==X86_OP_REG
            and i.operands[1].type==X86_OP_MEM and i.reg_name(i.operands[1].mem.base)!='ebp']
        assert len(reads)==1 and reads[0].operands[1].mem.disp==offset and reads[0].operands[1].size==width
        masks=[i for i in b if i.mnemonic=='and']
        assert (not masks) if mask is None else (len(masks)==1 and masks[0].op_str=='eax, 0xfff')
        getter_contracts.append(dict(va=hex(addr),read_site=hex(reads[0].address),offset=hex(offset),width=width,mask=mask))
    for row in [(0x642762,'cmp','edx, dword ptr [ecx]'),(0x642764,'jne','0x642778'),
        (0x64276c,'mov','edx, dword ptr [eax + 0x2c]'),(0x64276f,'cmp','edx, dword ptr [ecx + 0x24]'),
        (0x642772,'je','0x642862'),(0x64279a,'movzx','eax, byte ptr [edx + 0x3c]')]:anchor(*row)
    formal=json.loads((HERE/'formal_functions.json').read_bytes())
    assert len(formal['functions'])==2
    for f,original in zip(formal['functions'],raw['functions']):
        assert all(f[k]==v for k,v in original.items())
    ledger=json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
    assert [x['va'] for x in ledger['functions']]==['0x6423c0','0x6fc210']
    binding={}
    for name,expected in FINAL_SHA.items():
        actual=sha((HERE.parent/name).read_bytes())
        assert actual==expected,name
        binding[name]=actual
    result=dict(status='PASS' if FINAL_SHA else '原证和限定语义预核通过；终稿待绑定',pe_sha256=PE_SHA,
        raw_sha256=RAW_SHA,body_statistics=[dict(va=k,bytes=sum(i.size for i in v),instructions=len(v)) for k,v in bodies.items()],
        unique_byte_ranges=len(ranges),bridges=len(bridges),calls=len(raw['calls']),
        windows=len(windows),unique_windows=len(unique_windows),prefix=dict(va='0xa27600',hex=prefix.hex(),first_slot='0x605a72',scope='只核首DWORD'),
        constructor_writes=writes,constructor_poison_boundary_check=True,semantic_anchors=anchors,
        caller_byte_checks=caller_counts,caller_fill_paths=fill_results,eh_tail_instructions=eh,
        sources=sources,historical_body_checks=historical,reused_caller_bridges=selected_old_bridges,unwind_sha256=UNWIND_SHA,
        unwind_metadata=dict(constructor_prefix=ctor_info,factory_prefix=factory_info,
            constructor_map=ctor_map,factory_map=factory_map,bridges=unwind_bridges,chains=unwind_chains),
        final_reused_records=len(reused['records']),getter_contracts=getter_contracts,
        reviewed_final_sha256=binding)
    (HERE/'independent_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf8')
    (HERE/'independent_assembly.txt').write_text('\n'.join(transcript)+'\n','utf8')
    print(result['status'],result['body_statistics'],result['unique_byte_ranges'])


if __name__=='__main__':
    main()
