"""槽池生产与归还：独立读 PE、原证及有限指令模型；不调用作者或 IDA。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '32bb1c22c33bd0ca58ba757e74943af2d1da4eb0514d7114c61c2f834ee0ca80'
NEW = ('0x6d75a0','0x62eae0','0x6dfc30','0x6dfd50','0x6d7690','0x6dbdf0')
OLD = ('0x6dfca0','0x6d7660','0x6dfd10')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--show', nargs=2)
    parser.add_argument('--final', action='store_true')
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    hashes, decoded, spans, counts = {}, {}, set(), {}
    def load(path):
        data = path.read_bytes(); hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
        return json.loads(data)
    def ptr(obj, value):
        for part in value.strip('/').split('/'):
            part = part.replace('~1','/').replace('~0','~')
            obj = obj[int(part)] if isinstance(obj,list) else obj[part]
        return obj
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    pe = struct.unpack_from('<I',image,60)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H',image,pe+24)[0] == 0x10b
    base = struct.unpack_from('<I',image,pe+52)[0]
    sec = pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections = [struct.unpack_from('<4I',image,sec+i*40+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
    def disk(va,size):
        found=[(rva,off) for _,rva,length,off in sections if base+rva<=va and va+size<=base+rva+length]
        assert len(found)==1 and size>0
        rva,off=found[0]; data=image[off+va-base-rva:off+va-base-rva+size]
        assert len(data)==size
        return data
    def audit(row, va=None):
        va=va if va is not None else int(row.get('start_va',row.get('va')),16)
        data=disk(va,row['size'])
        assert data.hex()==row['disk_hex'].lower()==row.get('idb_hex',row.get('ida_hex')).lower()
        if 'sha256' in row: assert hashlib.sha256(data).hexdigest()==row['sha256'].lower()
        assert row.get('matching',True)
        spans.add((va,len(data)))
        return data
    def decode(row,chunks=None):
        chunks=chunks if chunks is not None else row.get('chunk_byte_ranges',row.get('byte_ranges'))
        out=[]
        for chunk in chunks:
            data=audit(chunk); va=int(chunk.get('start_va',chunk.get('va')),16)
            instructions=list(cs.disasm(data,va));assert sum(i.size for i in instructions)==len(data)
            for ins in instructions: decoded[ins.address]=ins;out.append(hex(ins.address))
        assembly=row.get('assembly',row.get('instructions'))
        if assembly is not None:
            assert out==[x.get('site_va',x.get('va',x.get('ea'))) for x in assembly]
        return len(out)
    raw=load(HERE/'bounded_raw.json')
    assert hashlib.sha256((HERE/'bounded_raw.json').read_bytes()).hexdigest()==RAW_SHA
    assert raw['disk_sha256']==SHA and tuple(x['seed_va'] for x in raw['functions'])==NEW
    assert tuple(x['seed_va'] for x in raw['reused_seeds'])==OLD
    current={x['seed_va']:x['chunk_byte_ranges'] for x in raw['current_chunk_audits']}
    counts['new_instructions']=sum(decode(x) for x in raw['functions'])
    counts['new_bytes']=sum(c['size'] for x in raw['functions'] for c in x['chunk_byte_ranges'])
    counts['new_functions']=6
    for row in raw['functions']: assert current[row['seed_va']]==row['chunk_byte_ranges']
    art=load(DOCS/'专题/图像资源/证据/20261009_图像加载函数群.json')
    animation=load(DOCS/'专题/角色与精灵动画/证据/动画管理与骰子_IDA原始导出.json')
    push=animation['functions'][24]
    assert push['address']=='0x6dfca0'
    counts['reused_instructions']=decode(push,current['0x6dfca0'])
    for index,va in ((18,'0x6d7660'),(19,'0x6dfd10')):
        assert art['functions'][index]['va']==va
        counts['reused_instructions']+=decode(art['functions'][index],current[va])
    bridges={}
    for row in raw['verified_direct_bridges']:
        data=audit(row);va=int(row['start_va'],16)
        assert len(data)==5 and data[0]==0xe9
        target=va+5+struct.unpack_from('<i',data,1)[0]
        assert target==int(row['target_va'],16)
        bridges[va]=target
    for call in raw['calls']:
        ins=decoded[int(call['site_va'],16)]
        assert ins.mnemonic in ('call','jmp') and ins.operands[0].type==X86_OP_IMM
        target=ins.operands[0].imm;assert target==int(call['target_va'],16)
        for bridge in call['bridges']:
            assert int(bridge,16)==target;target=bridges[target]
        assert target==int(call['implementation_va'],16)
    windows=raw['explicit_owner_windows']+[x['owner_window'] for rows in raw['incoming'].values() for x in rows if 'owner_window' in x]
    assert [x['site_va'] for x in raw['explicit_owner_windows']]==['0x6d7d29','0x6d7e5d','0x7dea86','0x75c5dc','0x75c601','0x798824']
    counts.update(bridges=len(bridges),calls=len(raw['calls']),window_records=len(windows),window_items=0)
    for window in windows:
        assert window['site_va'] in [x['site_va'] for x in window['assembly']]
        last=None
        for row in window['assembly']:
            va=int(row['site_va'],16);data=audit(row['bytes'],va)
            assert last is None or last==va;last=va+len(data)
            if row['is_code']:
                instructions=list(cs.disasm(data,va));assert len(instructions)==1 and instructions[0].size==len(data)
                decoded[va]=instructions[0]
            counts['window_items']+=1
    assert not raw['strings'] and not raw['data_windows']
    for source in raw['reuse_sources']:
        assert hashlib.sha256((DOCS/source['path']).read_bytes()).hexdigest()==source['source_sha256']
    loader=load(DOCS/'专题/4019系列事件/证据/resource_loader_scope.json')['functions'][0]
    assert loader['va']=='0x6d8130'
    counts['loader_mechanical_instructions']=decode(loader)
    originals={};adapted={};body_count=0
    expected_sources={
        '0x6dfca0':('专题/角色与精灵动画/证据/动画管理与骰子_IDA原始导出.json','/functions/24'),
        '0x6d7660':('专题/图像资源/证据/20261009_图像加载函数群.json','/functions/18'),
        '0x6dfd10':('专题/图像资源/证据/20261009_图像加载函数群.json','/functions/19'),
        '0x6d8130':('专题/4019系列事件/证据/resource_loader_scope.json','/functions/0'),
        '0x627760':('专题/40B0系列事件/证据/monster_helpers.json','/functions/0'),
        '0x91f6d0':('专题/4060系列事件/证据/callees.json','/functions/10')}
    for filename,expected in (('formal_functions.json',NEW),('reused_functions.json',tuple(expected_sources))):
        formal=load(HERE/filename);adapted[filename]=formal
        assert formal['disk_sha256']==SHA and tuple(x['va'] for x in formal['functions'])==expected
        for row in formal['functions']:
            path=DOCS/row['source_path'];source=load(path)
            assert hashlib.sha256(path.read_bytes()).hexdigest()==row['source_sha256']
            original=ptr(source,row['source_pointer']);originals[row['va']]=original
            assert json.loads(row['source_record_json'])==original
            assert row['source_field_pointers']=={k:row['source_pointer']+'/'+k for k in original}
            assert not {'status','conclusion','unknown','original_record'}&row.keys()
            assert row['va']==original.get('seed_va',original.get('va',original.get('address')))
            if row['va'] in expected_sources:
                assert (row['source_path'],row['source_pointer'])==expected_sources[row['va']]
            else:
                assert row['source_path']=='专题/资源槽池生产与归还/证据/bounded_raw.json'
                assert row['source_pointer']=='/functions/'+str(NEW.index(row['va']))
            chunks=original.get('chunk_byte_ranges',original.get('chunks',original.get('byte_ranges')))
            if not chunks:
                ref=row['current_bytes_source']
                assert ref['source_sha256']==RAW_SHA and ref['source_path']=='专题/资源槽池生产与归还/证据/bounded_raw.json'
                chunks=ptr(raw,ref['source_pointer'])['chunk_byte_ranges']
                assert chunks==current[row['va']]
            expected_chunks=[];addresses=[]
            for chunk in chunks:
                start=chunk.get('start_va',chunk.get('va',chunk.get('start')))
                size=chunk['size'] if 'size' in chunk else int(chunk['end'],16)-int(start,16)
                expected_chunks.append(dict(start_va=start,size=size,original=chunk))
                payload=disk(int(start,16),size)
                for key in ('disk_hex','idb_hex','ida_hex','bytes_hex'):
                    if key in chunk:assert chunk[key].lower()==payload.hex()
                if 'sha256' in chunk:assert hashlib.sha256(payload).hexdigest()==chunk['sha256'].lower()
                heads=list(cs.disasm(payload,int(start,16)));assert sum(x.size for x in heads)==size
                spans.add((int(start,16),size))
                for ins in heads:addresses.append(hex(ins.address));decoded[ins.address]=ins
            assert row['normalized_chunks']==expected_chunks
            assembly=original.get('assembly',original.get('instructions'))
            assert addresses==[x.get('site_va',x.get('va',x.get('ea'))) for x in assembly]
            assert row['normalized_assembly']==[dict(site_va=x.get('site_va',x.get('va',x.get('address',x.get('ea')))),
                text=x['text'],is_code=x.get('is_code',True),original=x) for x in assembly]
            assert row['declared_chunks']==original.get('declared_chunks',[dict(start_va=x['start_va'],
                end_va=hex(int(x['start_va'],16)+x['size']),is_main=x['start_va']==row['va']) for x in expected_chunks])
            body_count+=len(addresses)
    manifest=load(TOPIC/'函数审阅清单.json')
    assert manifest['disk_sha256']==SHA and tuple(x['va'] for x in manifest['functions'])==NEW
    assert tuple(x['va'] for x in manifest['historical_contracts'])==tuple(expected_sources)
    ledger_anchors=0
    for row in manifest['functions']+manifest['historical_contracts']:
        matched=ptr(adapted[row['evidence_ref']['file']],row['evidence_ref']['pointer'])
        assert row['va']==matched['va'] and row['source_sha256']==matched['source_sha256']
        assert row['source_path']==matched['source_path'] and row['source_pointer']==matched['source_pointer']
        assert row['declared_chunks']==matched['declared_chunks']
        amap={x['site_va']:x['text'] for x in matched['normalized_assembly']}
        for a in row['semantic_anchors']:
            assert amap[a['va']]==a['original_text'] and int(a['va'],16) in decoded
            ledger_anchors+=1
    assert manifest['historical_contracts'][3]['status']=='部分分析'
    counts.update(author_body_instructions=body_count,manifest_records=12,author_anchors=ledger_anchors)
    offline_bridges={}
    for bridge,expected in ((0x60EFAA,0x62EB20),(0x60554A,0x627760),(0x60C3C7,0x6DC310)):
        value=disk(bridge,5);assert value[0]==0xe9
        actual=bridge+5+struct.unpack_from('<i',value,1)[0]
        assert actual==expected;offline_bridges[hex(bridge)]=hex(actual)
    historical_calls=0
    for original in originals.values():
        for call in original.get('calls',[]):
            site=int(call.get('site_va',call.get('site')),16);ins=decoded[site]
            assert ins.mnemonic in ('call','jmp')
            target=int(call.get('target_va',call.get('target')),16)
            if ins.operands[0].type==X86_OP_IMM:assert ins.operands[0].imm==target
            else:assert ins.bytes[:2]==b'\xff\x15' and struct.unpack_from('<I',ins.bytes,2)[0]==target
            for bridge in call.get('bridges',call.get('thunks',[])):
                assert target==int(bridge,16);value=disk(target,5);assert value[0]==0xe9
                actual=target+5+struct.unpack_from('<i',value,1)[0]
                offline_bridges[hex(target)]=hex(actual);target=actual
            assert target==int(call.get('implementation_va',call.get('implementation')),16)
            historical_calls+=1
    counts.update(historical_calls=historical_calls,offline_navigation_bridges=len(offline_bridges))
    anchors={
        0x6D75DB:('push','0x7530'),0x6D75E8:('mov','dword ptr [ebp - 0x14], 0x752f'),
        0x6D75F4:('sub','eax, 1'),0x6D75FA:('cmp','dword ptr [ebp - 0x14], 0'),
        0x6D75FE:('jl','0x6d760e'),0x6D7607:('call','0x60d21d'),
        0x62EAF1:('mov','dword ptr [eax], 0'),0x62EAFA:('mov','dword ptr [ecx + 8], 0'),
        0x6DFC4A:('mov','dword ptr [eax + 8], 0'),0x6DFC57:('mov','dword ptr [ecx + 4], edx'),
        0x6DFC5D:('shl','eax, 2'),0x6DFC61:('call','0x609997'),
        0x6DFC72:('mov','dword ptr [ecx], edx'),0x6DFC81:('ret','4'),
        0x6DFD64:('mov','edx, dword ptr [eax + 8]'),0x6DFD67:('xor','eax, eax'),
        0x6DFD69:('cmp','edx, dword ptr [ecx + 4]'),0x6DFD6C:('setge','al'),
        0x6DFCB1:('call','0x610724'),0x6DFCB6:('movzx','eax, al'),
        0x6DFCBB:('je','0x6dfcc1'),0x6DFCBD:('xor','eax, eax'),
        0x6DFCCF:('mov','dword ptr [ecx + edx*4], eax'),
        0x6DFCD8:('add','edx, 1'),0x6DFCDE:('mov','dword ptr [eax + 8], edx'),
        0x6DFCE1:('mov','eax, 1'),0x6DFD24:('sub','ecx, 1'),
        0x6DFD38:('mov','eax, dword ptr [eax + ecx*4]'),
        0x6D76A5:('call','0x60d21d'),0x6D76B7:('ret','4'),
        0x6DBE05:('add','ecx, 0x40'),0x6DBE08:('call','0x60d678'),
        0x6DBE10:('add','ecx, dword ptr [ebp + 8]'),
        0x6DBE13:('mov','byte ptr [ecx + 0x92a4c], 0'),0x6DBE27:('ret','4'),
        0x6D7D26:('add','ecx, 0x40'),0x6D7E4D:('push','0x1d4c0'),
        0x6D7E52:('push','0'),0x6D7E57:('add','eax, 0x580cc'),
        0x7DEA78:('mov','edx, dword ptr [ecx + 0x584]'),0x7DEA86:('call','0x60ef50'),
        0x75C5DC:('call','0x60c3c7'),0x75C601:('call','0x60ef50'),
        0x798821:('add','ecx, 0x40'),0x798824:('call','0x601896'),
        0xA12AF3:('jmp','0x60efaa'),
        0x6D8540:('cmp','dword ptr [ebp - 0x20], 0xb'),0x6D8544:('je','0x6d8550'),
        0x6D8546:('cmp','dword ptr [ebp - 0x20], 0xc'),0x6D854A:('jne','0x6d861c'),
        0x6D8553:('add','edx, 2'),0x6D85B9:('sub','eax, 0xb'),
        0x6D85D4:('mov','dword ptr [ecx + edx + 8], eax'),
        0x6D919F:('cmp','dword ptr [ebp - 0x28], 1'),0x6D91A3:('jne','0x6d92a9'),
        0x6D91A9:('mov','dword ptr [ebp - 0x18], 3'),0x6D924D:('mov','dword ptr [edx + ecx + 8], 0'),
        0x6D95DF:('cmp','dword ptr [ebp - 0x28], 1'),0x6D95E3:('jne','0x6d96fb'),
        0x6D95E9:('mov','dword ptr [ebp - 0x18], 3'),0x6D9699:('mov','dword ptr [ecx + eax + 8], 0')}
    for ea,expected in anchors.items():assert (decoded[ea].mnemonic,decoded[ea].op_str)==expected,(hex(ea),decoded[ea].op_str)
    counts['semantic_anchors']=len(anchors)
    # 十五个登记站并非十五类别：十二个记录数组中三类另有派生项登记。
    registration_sites=(0x6D8539,0x6D8615,0x6D888E,0x6D8B49,0x6D8E6E,0x6D9198,0x6D92A2,
        0x6D95D8,0x6D96F4,0x6D99CB,0x6D9C44,0x6D9F11,0x6DA18A,0x6DA457,0x6DA6D0)
    slot_sites=(0x6D84DB,0x6D8595,0x6D8851,0x6D8AF4,0x6D8DF6,0x6D9120,0x6D9200,
        0x6D9557,0x6D9646,0x6D996D,0x6D9C07,0x6D9EB3,0x6DA14D,0x6DA3F9,0x6DA693)
    array_fields=(0x3ABB0,0x3ABB0,0x3ABB8,0x3ABC0,0x3ABC8,0x3ABD0,0x3ABD0,
        0x3ABD8,0x3ABD8,0x3ABE0,0x3ABE8,0x3ABF0,0x3ABF8,0x3AC00,0x3AC08)
    loader_heads=[int(x['va'],16) for x in loader['assembly']]
    for site,pop,field in zip(registration_sites,slot_sites,array_fields):
        index=loader_heads.index(pop)
        assert decoded[loader_heads[index-2]].op_str=='ecx, dword ptr [ebp - 0x14]'
        assert decoded[loader_heads[index-1]].op_str=='ecx, 0x40'
        assert decoded[pop].mnemonic=='call' and decoded[pop].operands[0].imm==0x601896
        ins=decoded[site];assert ins.mnemonic=='mov' and ins.operands[0].type==X86_OP_MEM
        assert ins.operands[0].mem.disp==0x580CC and ins.operands[0].mem.scale==4
        candidates=[decoded[ea] for ea in loader_heads if pop<ea<site]
        assert any(any(o.type==X86_OP_MEM and o.mem.disp==field for o in x.operands) for x in candidates)
        assert any(x.mnemonic=='mov' and x.operands[0].type==X86_OP_MEM and x.operands[0].mem.disp==4
            and cs.reg_name(x.operands[1].reg)=='eax' for x in candidates)
        assert not any(x.group_name(g)=='jump' for x in candidates for g in x.groups)
    counts.update(loader_slot_sites=15,loader_record_array_fields=len(set(array_fields)))
    shared=load(HERE/'shared_sites.json')
    names=('road.dat','road.dat','thing.dat','event.dat','build.dat','vehicle.dat','vehicle.dat',
        'role.dat','role.dat','npc.dat','fx.dat','mood.dat','card.dat','other.dat','extend.dat')
    file_sites=(0x6D8283,0x6D8283,0x6D8631,0x6D88A5,0x6D8B65,0x6D8E8F,0x6D8E8F,
        0x6D92C3,0x6D92C3,0x6D9715,0x6D99E7,0x6D9C5B,0x6D9F2D,0x6DA1A1,0x6DA473)
    for item,site,pop,field,name,file_site in zip(shared['sites'],registration_sites,slot_sites,array_fields,names,file_sites):
        assert item['register_va']==hex(site) and item['pop_va']==hex(pop) and item['array_member']==hex(field)
        assert item['file']==name and item['file_push_va']==hex(file_site)
        push=decoded[file_site];assert push.mnemonic=='push' and push.operands[0].type==X86_OP_IMM
        target=push.operands[0].imm;assert item['filename_target_va']==hex(target)
        assert disk(target,len(name)+1)==name.encode()+b'\0'==bytes.fromhex(item['filename_hex'])
        assert item['source_path']=='专题/4019系列事件/证据/resource_loader_scope.json'
        assert item['source_sha256']==hashlib.sha256((DOCS/item['source_path']).read_bytes()).hexdigest()
        start=loader_heads.index(pop)-2;end=loader_heads.index(site)
        assert len(item['instructions'])==end-start+1
        for index,observation in zip(range(start,end+1),item['instructions']):
            assert observation['source_pointer']=='/functions/0/assembly/'+str(index)
            assert observation['original']==loader['assembly'][index]
            ins=decoded[loader_heads[index]]
            assert observation['disk_hex']==ins.bytes.hex()
            assert observation['decoded']==ins.mnemonic+' '+ins.op_str
    assert shared['site_count']==len(shared['sites'])==15 and shared['file_categories']==12
    if args.show:
        lo,hi=(int(x,0) for x in args.show)
        print('\n'.join(f'{ea:#x} {ins.mnemonic} {ins.op_str}' for ea,ins in sorted(decoded.items()) if lo<=ea<hi));return
    # 模型逐条执行当前PE解码；CRT分配和RTC按外部返回契约替代，非实机运行。
    mask=0xffffffff
    signed=lambda v: v if v<0x80000000 else v-0x100000000
    class Machine:
        def __init__(self):
            self.regs={x:0 for x in ('eax','ebx','ecx','edx','esi','edi','ebp','esp')}
            self.mem={};self.writes=[];self.reads=[];self.calls=[];self.zf=False;self.less=False;self.alloc=0x300000
        def put(self,address,value,size=4):
            for i in range(size):self.mem[(address+i)&mask]=(value>>(i*8))&255
        def get(self,address,size=4):
            self.reads.append((address,size))
            return sum(self.mem[(address+i)&mask]<<(i*8) for i in range(size))
        def addr(self,op):
            m=op.mem
            assert not m.segment
            return (self.regs.get(cs.reg_name(m.base),0)+self.regs.get(cs.reg_name(m.index),0)*m.scale+m.disp)&mask
        def regget(self,name):return self.regs['eax']&255 if name=='al' else self.regs[name]
        def value(self,op):
            if op.type==X86_OP_IMM:return op.imm&mask
            if op.type==X86_OP_REG:return self.regget(cs.reg_name(op.reg))
            assert op.type==X86_OP_MEM
            return self.get(self.addr(op),op.size)
        def assign(self,op,value):
            value&=(1<<(op.size*8))-1
            if op.type==X86_OP_REG:
                name=cs.reg_name(op.reg)
                if name=='al':self.regs['eax']=(self.regs['eax']&0xffffff00)|value
                else:self.regs[name]=value
            else:
                address=self.addr(op);self.put(address,value,op.size);self.writes.append((address,op.size,value))
        def run(self,entry,this,args=(),stop=None):
            self.regs.update(ecx=this,esp=0x100000,ebp=0x100100)
            self.put(0x100000,0xbad000)
            for i,value in enumerate(args):self.put(0x100004+i*4,value)
            pc=entry
            for steps in range(2000000):
                if pc==stop:return
                ins=decoded[pc];ops=ins.operands;nxt=pc+ins.size;m=ins.mnemonic
                if m=='mov':self.assign(ops[0],self.value(ops[1]))
                elif m=='movzx':self.assign(ops[0],self.value(ops[1]))
                elif m=='push':
                    value=self.value(ops[0]);self.regs['esp']-=4;self.put(self.regs['esp'],value)
                elif m=='pop':self.assign(ops[0],self.get(self.regs['esp']));self.regs['esp']+=4
                elif m in ('add','sub','xor','shl'):
                    a,b=self.value(ops[0]),self.value(ops[1])
                    value={'add':lambda:a+b,'sub':lambda:a-b,'xor':lambda:a^b,'shl':lambda:a<<(b&31)}[m]()&mask
                    self.assign(ops[0],value);self.zf=value==0;self.less=bool(value&0x80000000)
                elif m=='cmp':
                    a,b=self.value(ops[0]),self.value(ops[1]);self.zf=a==b;self.less=signed(a)<signed(b)
                elif m=='test':self.zf=(self.value(ops[0])&self.value(ops[1]))==0
                elif m=='imul':self.assign(ops[0],self.value(ops[1])*self.value(ops[2]))
                elif m in ('setge','setnl'):self.assign(ops[0],int(not self.less))
                elif m=='jmp':nxt=self.value(ops[0])
                elif m in ('je','jne','jl','jge'):
                    if {'je':self.zf,'jne':not self.zf,'jl':self.less,'jge':not self.less}[m]:nxt=self.value(ops[0])
                elif m=='call':
                    target=self.value(ops[0]);impl=bridges.get(target,target)
                    if impl==0x91F6D0:pass
                    elif impl==0x91BD80:
                        self.calls.append(('allocate',self.get(self.regs['esp'])));self.regs['eax']=self.alloc
                    elif impl in decoded:
                        self.regs['esp']-=4;self.put(self.regs['esp'],nxt);nxt=impl
                    else:raise AssertionError(('unknown call',hex(target)))
                elif m=='ret':
                    nxt=self.get(self.regs['esp']);self.regs['esp']+=4+(self.value(ops[0]) if ops else 0)
                    if nxt==0xbad000:return
                else:raise AssertionError((hex(pc),m))
                pc=nxt
            raise AssertionError('finite execution exceeded bound')
    tests=[];pool=0x200040;root=0x200000;storage=0x300000
    for count,capacity in ((0,0),(0,1),(1,1),(2,1),(-1,1),(1,-1),(-2,-1),(0x80000000,0x7fffffff)):
        machine=Machine();machine.put(pool+4,capacity&mask);machine.put(pool+8,count&mask)
        machine.run(0x6DFD50,pool)
        assert machine.regs['eax']==int(signed(count&mask)>=signed(capacity&mask))
        tests.append('signed_full_predicate')
    machine=Machine();machine.put(pool,storage);machine.put(pool+4,0x12345678);machine.put(pool+8,20)
    machine.run(0x62EAE0,pool)
    assert machine.get(pool)==0 and machine.get(pool+8)==0 and machine.get(pool+4)==0x12345678
    tests.append('constructor_preserves_capacity')
    for capacity,alloc in ((30000,storage),(0,0),(1,0),(-1,storage),(0x40000000,storage)):
        machine=Machine();machine.alloc=alloc;machine.put(pool,0x44440000);machine.put(pool+8,99)
        machine.run(0x6DFC30,pool,(capacity&mask,))
        assert machine.calls==[('allocate',(capacity*4)&mask)]
        assert machine.get(pool)==alloc and machine.get(pool+4)==capacity&mask and machine.get(pool+8)==0
        assert machine.regs['eax']==alloc
        tests.append('allocation_low32_and_no_null_gate')
    for entry in (0x6DFCA0,0x6D7690,0x6DBDF0):
        for count,cap,slot in ((0,2,12),(2,2,12),(3,2,12),(-1,2,12),(0,2,-1),(0,2,30000)):
            machine=Machine();machine.put(pool,storage);machine.put(pool+4,cap);machine.put(pool+8,count&mask)
            address=(storage+count*4)&mask;machine.put(address,0x9999)
            flag=(root+0x92a4c+slot)&mask;machine.put(flag,0x7a,1)
            reverse=(root+0x580cc+4*slot)&mask;machine.put(reverse,0xABCDEF00)
            machine.run(entry,root if entry==0x6DBDF0 else pool,(slot&mask,))
            success=count<cap
            assert machine.regs['eax']==int(success)
            assert machine.get(pool+8)==((count+1) if success else count)&mask
            assert machine.get(address)==(slot&mask if success else 0x9999)
            assert machine.get(flag,1)==(0 if entry==0x6DBDF0 else 0x7a)
            assert machine.get(reverse)==0xABCDEF00
            tests.append('push_or_return_boundary')
    machine=Machine();machine.put(pool,storage);machine.put(pool+4,3);machine.put(pool+8,0)
    machine.run(0x6DFCA0,pool,(7,));machine.run(0x6DFCA0,pool,(7,))
    assert machine.get(pool+8)==2 and machine.get(storage)==machine.get(storage+4)==7
    tests.append('duplicate_slot_accepted')
    # 开始于已核 this 入栈局部赋值处，结束于正常 SEH 清理前；只测构造业务路径。
    machine=Machine();machine.put(pool+4,0x9999)
    machine.run(0x6D75C9,pool,stop=0x6D760E)
    assert machine.calls==[('allocate',120000)] and machine.get(pool+4)==machine.get(pool+8)==30000
    assert all(machine.get(storage+i*4)==29999-i for i in range(30000))
    machine.run(0x6D7660,pool);assert machine.regs['eax']==0 and machine.get(pool+8)==29999
    machine.run(0x6D7660,pool);assert machine.regs['eax']==1 and machine.get(pool+8)==29998
    tests.append('full_initial_fill_then_pop_0_1')
    for site,pop,field in zip(registration_sites,slot_sites,array_fields):
        machine=Machine();machine.regs['eax']=123
        for off in range(0x10,0x44,4):machine.put(0x100100-off,1)
        for off,value in ((-0x14,root),(-0x1c,1),(-0x20,2),(-0x18,3),(-0x24,4)):
            machine.put(0x100100+off,value)
        for root_field in set(array_fields):machine.put(root+root_field,0x500000)
        machine.run(pop+decoded[pop].size,root,stop=site+decoded[site].size)
        record=machine.get(root+0x580CC+123*4)
        assert 0x500000<=record<0x505000 and machine.get(record+4)==123
        assert len([w for w in machine.writes if w[2]==123])==1
        tests.append('loader_same_pool_record_reverse_link')
    counts['finite_instruction_cases']=len(tests)
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    author_files=sorted(p for p in TOPIC.rglob('*') if p.is_file() and '__pycache__' not in p.parts
        and not p.name.startswith('independent_') and p.name!='独立审阅结论.txt')
    bindings={p.relative_to(TOPIC).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in author_files}
    if args.freeze or args.final:
        bindings['证据/independent_review.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        bindings['证据/独立审阅结论.txt']=hashlib.sha256((HERE/'独立审阅结论.txt').read_bytes()).hexdigest()
        binding_file=HERE/'independent_final_bindings.json'
        if args.freeze:
            assert not binding_file.exists(),'不覆盖已冻结指纹'
            binding_file.write_text(json.dumps(bindings,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        assert json.loads(binding_file.read_text(encoding='utf-8'))==bindings,'终稿变化，需重新人工审阅'
    result=dict(status='EVIDENCE_PASS',disk_sha256=SHA,counts=counts,unique_byte_ranges=len(spans),
        sources=hashes,offline_navigation_bridges=offline_bridges,
        limitations=['外部分配器和RTC为返回契约模型；未执行客户端','未声称析构及全部调用者业务完成'])
    output=HERE/'independent_evidence_validation.json'
    if args.freeze or args.final:
        result.update(status='PASS',author_final_files=len(author_files),final_bindings=bindings)
        output=HERE/'independent_validation.json'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
