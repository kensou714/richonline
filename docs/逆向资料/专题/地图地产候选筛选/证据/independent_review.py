"""地产候选筛选独立复核：只读当前PE与冻结证据，不访问IDA。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'dbf28909a2e4328fd31158367ecb9c806fbfd6554e32e38b11a9eadb8084f635'
SEEDS = (0x7E4660, 0x7E4750, 0x7E4830, 0x7E4930, 0x7E4A30)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pointer(node, path):
    for part in path.strip('/').split('/'):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def selection_models(decoded, implementations):
    """有限解释真实主体指令；旧callee只按已核短契约提供稳定合成读值。"""
    def signed(value, bits=32):
        value &= (1 << bits)-1
        return value-(1 << bits) if value & (1 << (bits-1)) else value

    def run(seed, ids, properties, owner=2, limit=5, excluded=99, count=None):
        instructions = {i.address:i for i in decoded[seed]}
        regs = dict(eax=0xA5A5A5A5, ebx=0, ecx=0x31000000, edx=0, esi=0, edi=0,
                    ebp=0x22000000, esp=0x20000000)
        start_sp, saved_bp = regs['esp'], regs['ebp']
        mem = {start_sp:0xDEAD0000,start_sp+4:owner & 0xFFFFFFFF,start_sp+8:limit & 0xFFFFFFFF}
        if seed == 0x7E4750:
            mem[start_sp+12] = excluded & 0xFFFFFFFF
        flags = (False,False)
        pc,steps = seed,0
        trace = []

        def register(name):
            if name in regs:
                return regs[name]
            root = {'ax':'eax','al':'eax','cx':'ecx','cl':'ecx','dx':'edx','dl':'edx'}[name]
            return regs[root] & (0xFFFF if len(name)==2 and name[1]=='x' else 0xFF)

        def address(op):
            value = op.mem.disp
            if op.mem.base:
                value += register(instructions[pc].reg_name(op.mem.base))
            if op.mem.index:
                value += register(instructions[pc].reg_name(op.mem.index))*op.mem.scale
            return value & 0xFFFFFFFF

        def value(op):
            if op.type == capstone.x86.X86_OP_IMM:
                return op.imm & ((1 << (op.size*8))-1)
            if op.type == capstone.x86.X86_OP_REG:
                return register(instructions[pc].reg_name(op.reg))
            assert op.type == capstone.x86.X86_OP_MEM and op.size == 4
            return mem[address(op)]

        def put(op,number):
            number &= (1 << (op.size*8))-1
            if op.type == capstone.x86.X86_OP_REG:
                name = instructions[pc].reg_name(op.reg)
                assert name in regs
                regs[name] = number
            else:
                assert op.type == capstone.x86.X86_OP_MEM and op.size == 4
                mem[address(op)] = number

        while True:
            assert pc in instructions and steps < 10000
            steps += 1
            ins = instructions[pc]
            op,args = ins.mnemonic,ins.operands
            next_pc = pc+ins.size
            if op == 'mov':
                put(args[0],value(args[1]))
            elif op in ('movsx','movzx'):
                number = value(args[1])
                put(args[0],signed(number,args[1].size*8) if op=='movsx' else number)
            elif op in ('add','sub'):
                put(args[0],value(args[0])+value(args[1])*(1 if op=='add' else -1))
            elif op == 'push':
                number=value(args[0]); regs['esp']-=4; mem[regs['esp']]=number
            elif op == 'pop':
                put(args[0],mem[regs['esp']]); regs['esp']+=4
            elif op in ('cmp','test'):
                left,right=value(args[0]),value(args[1])
                flags = ((left==right,signed(left)<signed(right)) if op=='cmp'
                         else ((left&right)==0,signed(left&right)<0))
            elif op == 'jmp':
                next_pc=value(args[0])
            elif op in ('je','jge','jg','jle'):
                zero,less=flags
                take={'je':zero,'jge':not less,'jg':not less and not zero,'jle':less or zero}[op]
                if take:
                    next_pc=value(args[0])
            elif op == 'call':
                target=implementations[(seed,pc)]
                if target==0x91F6D0:
                    assert flags[0] and regs['esp']==regs['ebp']
                else:
                    nargs={0x695040:0,0x695010:1,0x63E290:1,0x63E2D0:1,
                           0x6BC0D0:1,0x63F500:1,0x63F5B0:2,0x63E960:1}[target]
                    values=[signed(mem[regs['esp']+4*i]) for i in range(nargs)]
                    assert regs['ecx']==0x31000000+(0x46C if target in (0x695040,0x695010) else 0)
                    if target==0x695040:
                        result=len(ids) if count is None else count
                    elif target==0x695010:
                        result=ids[values[0]] & 0xFFFF
                    else:
                        kind,subtype,metric,prop_owner=properties[values[0]]
                        if target==0x63E290: result=int(signed(kind,8)==11)
                        elif target==0x63E2D0: result=int(signed(kind,8)==12)
                        elif target==0x6BC0D0: result=int(signed(subtype,8)==0)
                        elif target==0x63F500: result=int(signed(subtype,8)==1)
                        elif target==0x63F5B0: result=int(signed(prop_owner,8)==values[1])
                        elif target==0x63E960: result=signed(metric,8)
                    trace.append(dict(site_va=hex(pc),callee_va=hex(target),args=values,result=result))
                    regs['esp']+=4*nargs
                    regs['eax']=result & 0xFFFFFFFF
                    regs['ecx']=regs['edx']=0xBADC0DED
            elif op == 'ret':
                cleanup=12 if seed==0x7E4750 else 8
                assert args[0].imm==cleanup and regs['esp']==start_sp and regs['ebp']==saved_bp
                assert mem[start_sp]==0xDEAD0000
                return dict(return_eax=signed(regs['eax']),cleanup_bytes=cleanup,steps=steps,calls=trace)
            else:
                raise AssertionError((hex(pc),op))
            pc=next_pc

    scenarios=[]
    def check(seed,name,ids,properties,expected,**kwargs):
        result=run(seed,ids,properties,**kwargs)
        assert result['return_eax']==expected,(hex(seed),name,result['return_eax'],expected)
        scenarios.append(dict(va=hex(seed),case=name,expected=expected,inputs=dict(ids=ids,properties=properties,**kwargs),result=result))
        return result

    for seed in SEEDS:
        kind=12 if seed in (0x7E4750,0x7E4A30) else 11
        subtype=1 if seed==0x7E4930 else 0
        def prop(metric,owner=2,kind=kind,subtype=subtype):
            return (kind,subtype,metric,owner)
        check(seed,'空容器',[],{},-1)
        check(seed,'负计数直接失败',[10],{10:prop(2)},-1,count=-1)
        check(seed,'同值取首或末',[10,20],{10:prop(4),20:prop(4)},10 if seed in SEEDS[:2] else 20)
        check(seed,'与入口阈值相等',[10],{10:prop(5)},-1 if seed in SEEDS[:2] else 10)
        check(seed,'候选降序取最小',[10,20,30],{10:prop(4),20:prop(1),30:prop(3)},20)
        check(seed,'负数及零度量',[10,20,30],{10:prop(0x80),20:prop(0),30:prop(1)},10 if seed in SEEDS[:2] else 30)
        check(seed,'完整DWORD归属拒绝低BYTE碰撞',[10],{10:prop(1,0xFF)},-1,owner=255)
        check(seed,'归属负一按signed匹配',[10],{10:prop(1,0xFF)},10,owner=-1)
        check(seed,'WORD符号扩展不拒绝负编号',[0x8000],{-32768:prop(1)},-32768)
        check(seed,'WORD负一与失败哨兵碰撞',[0xFFFF],{-1:prop(1)},-1)
        result=check(seed,'类型先短路',[10,20],{10:prop(1,kind=9),20:prop(2)},20)
        assert all(c['callee_va'] not in ('0x63f5b0','0x63e960') for c in result['calls'] if c['args'] and c['args'][0]==10)
        if seed==0x7E4750:
            check(seed,'第三DWORD参数排除候选',[10,20],{10:prop(1),20:prop(2)},20,excluded=10)
            check(seed,'排除参数非低WORD比较',[10],{10:prop(1)},10,excluded=0x1000A)
        elif kind==11:
            check(seed,'子型短路',[10,20],{10:prop(1,subtype=6),20:prop(2)},20)
    return dict(scope='五主体有限指令解释；callee由已核旧短契约稳定合成，不执行游戏、不证明并发或容器有效性',
                cases=len(scenarios),scenarios=scenarios)


def audit(final=False):
    image = (ROOT/'RnClient.exe').read_bytes()
    assert sha(image) == PE_SHA
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe+24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe+52)[0]
    table = pe+24+struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<4I', image, table+40*i+8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]

    def read(va, size):
        offsets = [off+va-base-rva for _,rva,count,off in sections
                   if rva <= va-base and va-base+size <= rva+count]
        assert len(offsets) == 1, (hex(va), size)
        result = image[offsets[0]:offsets[0]+size]
        assert len(result) == size
        return result

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    equal_records = 0
    unique_ranges = set()

    def scan(node):
        nonlocal equal_records
        if isinstance(node, dict):
            blob = node.get('idb_hex', node.get('ida_hex'))
            if blob is not None and node.get('disk_hex') is not None:
                va = int(node.get('start_va', node.get('va')), 16)
                blob = bytes.fromhex(blob)
                assert len(blob) == node['size'] and blob == bytes.fromhex(node['disk_hex']) == read(va, len(blob))
                assert node.get('matching', node.get('equal')) is True
                if node.get('sha256'):
                    assert sha(blob) == node['sha256']
                equal_records += 1
                unique_ranges.add((va,len(blob)))
            for child in node.values():
                scan(child)
        elif isinstance(node, list):
            for child in node:
                scan(child)

    transcript = ['// 地产候选筛选；独立当前PE解码，不执行游戏；旧caller仅有限范围。']

    def decode_record(record, label):
        blocks = record.get('chunk_byte_ranges', record.get('byte_ranges', record.get('chunks', [])))
        assert blocks, (label, record.keys())
        instructions = []
        for block in blocks:
            va = int(block.get('start_va', block.get('va')), 16)
            chunk = list(decoder.disasm(read(va, block['size']), va))
            assert sum(i.size for i in chunk) == block['size']
            instructions.extend(chunk)
        rows = record.get('assembly', record.get('instructions', []))
        expected = [int(row.get('site_va', row.get('va')),16) for row in rows if row.get('is_code', True)]
        assert [i.address for i in instructions] == expected, label
        transcript.append('// '+label)
        transcript.extend('// %08X %s %s %s' % (i.address,i.bytes.hex(),i.mnemonic,i.op_str) for i in instructions)
        return instructions

    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == PE_SHA
    assert tuple(int(f['seed_va'],16) for f in raw['functions']) == SEEDS
    assert tuple(int(f['seed_va'],16) for f in raw['current_chunk_audits']) == SEEDS
    assert raw['reused_seeds'] == [] and raw['data_windows'] == [] and raw['data_references'] == []
    for original,current in zip(raw['functions'],raw['current_chunk_audits']):
        assert original['chunk_byte_ranges'] == current['chunk_byte_ranges']
    scan(raw)
    decoded = {va:decode_record(record, '新主体 '+hex(va)) for va,record in zip(SEEDS,raw['functions'])}
    direct = {(va,i.address):i.operands[0].imm for va,items in decoded.items() for i in items
              if i.mnemonic == 'call' and i.operands[0].type == capstone.x86.X86_OP_IMM}
    assert direct == {(int(row['seed_va'],16),int(row['site_va'],16)):int(row['target_va'],16) for row in raw['calls']}

    def bridge(va):
        blob = read(va,5)
        assert blob[0] == 0xE9
        return va+5+struct.unpack_from('<i',blob,1)[0]

    for call in raw['calls']:
        target = int(call['target_va'],16)
        for step in call['bridges']:
            assert target == int(step,16)
            target = bridge(target)
        assert target == int(call['implementation_va'],16)
    for row in raw['verified_direct_bridges']:
        assert bridge(int(row['start_va'],16)) == int(row['target_va'],16)
    navigation_windows = {}

    def navigation(row):
        assert row['owner_va']=='0x7c6640' and '有限' in row['pending_status']
        assert len(row['assembly'])==11
        addresses=[]
        for instruction in row['assembly']:
            va=int(instruction['site_va'],16)
            items=list(decoder.disasm(read(va,instruction['bytes']['size']),va))
            assert len(items)==1 and items[0].size==instruction['bytes']['size']
            addresses.append(va)
        assert int(row['site_va'],16) in addresses and len(set(addresses))==11
        key=(row['owner_va'],row['site_va'])
        if key in navigation_windows:
            assert navigation_windows[key]==row
        navigation_windows[key]=row

    assert len(raw['incoming'])==5 and len(raw['explicit_owner_windows'])==5
    incoming_count=0
    for seed,rows in raw['incoming'].items():
        assert int(seed,16) in SEEDS and len(rows)==2
        for row in rows:
            assert row['is_code'] is True
            site,target=int(row['site_va'],16),int(row['target_va'],16)
            ins,=list(decoder.disasm(read(site,5),site))
            assert ins.mnemonic in ('jmp','call') and ins.operands[0].type==capstone.x86.X86_OP_IMM
            assert ins.operands[0].imm==target
            if row['verified_bridge']:
                assert bridge(site)==int(row['final_implementation_va'],16)==int(seed,16)
            if row.get('owner_window'):
                navigation(row['owner_window'])
            incoming_count+=1
    for row in raw['explicit_owner_windows']:
        navigation(row)
    assert len(navigation_windows)==5
    for ref in raw['reuse_sources']:
        path=(DOCS/ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve()) and sha(path.read_bytes())==ref['source_sha256']
    formal_bytes = (HERE/'formal_functions.json').read_bytes()
    formal = json.loads(formal_bytes)
    assert formal['schema'] == 'richonline-property-selection-formal-1'
    assert formal['disk_sha256'] == PE_SHA and formal['raw_sha256'] == RAW_SHA
    source_cache = {}

    def source(ref):
        root = HERE.parent if ref['base'] == 'topic' else DOCS
        assert ref['base'] in ('topic','docs')
        path = (root/ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        blob = path.read_bytes()
        assert sha(blob) == ref['sha256']
        source_cache[str(path.relative_to(DOCS)).replace('\\','/')] = ref['sha256']
        return pointer(json.loads(blob),ref['json_pointer'])

    assert len(formal['functions']) == 5 and len(formal['dependency_contracts']) == 18
    assert [row['va'] for row in formal['dependency_contracts']]==[
        '0x695010','0x695040','0x63e290','0x63e2d0','0x6bc0d0','0x63f500','0x63f5b0','0x63e960',
        '0x63e3e0','0x63e410','0x63ec30','0x692940','0x692b00','0x693da0','0x63f2d0','0x7e3f30','0x7e4020','0x91f6d0']
    for index,(adapted,original) in enumerate(zip(formal['functions'],raw['functions'])):
        assert adapted['source'] == dict(base='topic',path='证据/bounded_raw.json',sha256=RAW_SHA,json_pointer='/functions/'+str(index))
        assert source(adapted['source']) == adapted['source_record'] == original
        assert adapted['va'] == original['seed_va'] and adapted['end_va'] == original['end_va']
        assert adapted['name'] == original['name'] and adapted['pseudocode'] == original['pseudocode']
        assert adapted['decompile_error'] == original['decompile_error']
        assert adapted['chunk_byte_ranges'] == original['chunk_byte_ranges']
        assert adapted['assembly'] == [dict(va=row['site_va'],text=row['text'],is_code=row['is_code']) for row in original['assembly']]
    dependencies = []
    for row in formal['dependency_contracts']:
        original = source(row['source'])
        assert original == row['source_record'] and original['va'] == row['va']
        scan(original)
        items = decode_record(original,'旧短契约 '+row['va'])
        dependencies.append(dict(va=row['va'], bytes=sum(i.size for i in items), instructions=len(items), source=row['source']))
    windows = []
    assert len(formal['caller_windows']) == 7
    expected_ranges=((0x7C66D2,0x7C673F),(0x7C67DF,0x7C6800),(0x7C8BAC,0x7C8BC9),
        (0x7C8DA2,0x7C8E6C),(0x7C8F5E,0x7C9259),(0x7CA1AA,0x7CA249),(0x7CA8CB,0x7CAB3C))
    assert tuple((int(row['start_va'],16),int(row['end_va'],16)) for row in formal['caller_windows'])==expected_ranges
    for row in formal['caller_windows']:
        old = source(row['source'])
        assert old['address'] == row['owner_va'] == '0x7c6640'
        assert row['source']['sha256']=='cf78c9f75c2f9729319a9efb70b8a7cf22a6350ccf47bfda6fa4844ee819e99b'
        lo,hi = int(row['start_va'],16),int(row['end_va'],16)
        assert row['source_byte_offset'] == lo-int(old['address'],16)
        old_blob = bytes.fromhex(old['bytes'])[row['source_byte_offset']:row['source_byte_offset']+hi-lo]
        assert old_blob == read(lo,hi-lo)
        expected = old['assembly'][row['source_assembly_start']:row['source_assembly_end_exclusive']]
        assert row['source_rows'] == expected
        assert row['assembly'] == [dict(va=va,text=text) for va,text in expected]
        assert int(old['assembly'][row['source_assembly_end_exclusive']][0],16) == hi
        assert int(expected[0][0],16) == lo
        scan(row['byte_audit'])
        items = list(decoder.disasm(old_blob,lo))
        assert sum(i.size for i in items) == hi-lo
        assert [i.address for i in items] == [int(va,16) for va,_ in expected]
        assert '有限' in row['window_status'] and '非完整' in row['window_status']
        transcript.append('// 旧caller有限范围 '+hex(lo)+'..'+hex(hi))
        transcript.extend('// %08X %s %s %s' % (i.address,i.bytes.hex(),i.mnemonic,i.op_str) for i in items)
        windows.append(dict(start_va=hex(lo),end_va=hex(hi),bytes=hi-lo,instructions=len(items)))
    caller_instructions={i.address:i for lo,hi in expected_ranges for i in decoder.disasm(read(lo,hi-lo),lo)}
    for site,op,operand in ((0x7C9031,'push','edx'),(0x7C9035,'push','eax'),(0x7C903F,'push','edx'),
                            (0x7C8FD7,'je','0x7c9018'),(0x7C9013,'jmp','0x7c90be'),
                            (0x7CA93D,'jne','0x7ca974'),(0x7CA978,'jne','0x7ca9af'),
                            (0x7CA9B3,'je','0x7cab1b')):
        assert caller_instructions[site].mnemonic==op and caller_instructions[site].op_str==operand
    for row in navigation_windows.values():
        for line in row['assembly']:
            assert int(line['site_va'],16) in caller_instructions
    assert len(formal['caller_navigation_bridges']) == 9
    for row in formal['caller_navigation_bridges']:
        va = int(row['va'],16)
        assert row['size'] == 5 and read(va,5).hex() == row['disk_hex']
        assert sha(read(va,5)) == row['sha256'] and bridge(va) == int(row['target_va'],16)
        assert '无本批IDA' in row['scope']
    caller=source(formal['caller_windows'][0]['source'])
    prologue=list(decoder.disasm(read(0x7C6640,41),0x7C6640))
    assert sum(i.size for i in prologue)==41 and len(prologue)==13
    assert bytes.fromhex(caller['bytes'])[:41]==read(0x7C6640,41)
    assert [i.address for i in prologue]==[int(row[0],16) for row in caller['assembly'][:13]]
    assert prologue[-1].address==0x7C6666 and prologue[-1].op_str=='dword ptr [ebp - 8], ecx'
    transcript.append('// 旧caller入口别名局部补核；不计七case或完整owner')
    transcript.extend('// %08X %s %s %s' % (i.address,i.bytes.hex(),i.mnemonic,i.op_str) for i in prologue)
    result = dict(status='独立机械初核；人工语义与终稿尚未PASS',disk_sha256=PE_SHA,raw_sha256=RAW_SHA,
        functions=[dict(va=hex(va),bytes=sum(i.size for i in items),instructions=len(items)) for va,items in decoded.items()],
        direct_calls=len(direct),formal_bridges=len(raw['verified_direct_bridges']),offline_navigation_bridges=9,
        raw_incoming_records=incoming_count,unique_current_navigation_windows=len(navigation_windows),
        old_dependencies=dependencies,finite_caller_windows=windows,source_files=source_cache,
        old_caller_prologue=dict(start_va='0x7c6640',end_va='0x7c6669',bytes=41,instructions=13,
            source=formal['caller_windows'][0]['source'],disk_hex=read(0x7C6640,41).hex(),
            sha256=sha(read(0x7C6640,41)),scope='旧来源bytes及前13条assembly对等；仅ECX到G别名，不提升owner'),
        equal_byte_records=equal_records,unique_equal_ranges=len(unique_ranges),
        selection_instruction_models=selection_models(decoded,{(int(row['seed_va'],16),int(row['site_va'],16)):
            int(row['implementation_va'],16) for row in raw['calls']}))
    if final:
        topic=HERE.parent
        manifest=json.loads((topic/'函数审阅清单.json').read_bytes())
        assert manifest['disk_sha256']==PE_SHA
        assert len(manifest['functions'])==19 and len({r['va'] for r in manifest['functions']})==19
        assert [int(r['va'],16) for r in manifest['functions'][:5]]==list(SEEDS)
        for index,row in enumerate(manifest['functions']):
            path,where=row['evidence'].split('#')
            origin=pointer(json.loads((topic/path).read_bytes()),where)
            assert origin.get('va',origin.get('start_va'))==row['va']
            assert row['unknown'] and row['conclusion']
            if index<5:
                assert row['status']=='完整函数静态审阅' and path=='证据/formal_functions.json'
                assert where=='/functions/'+str(index) and row['coverage_origin']=='本批新增完整主体'
            else:
                assert row['status']=='直接桥静态核验' and path=='证据/bounded_raw.json'
                assert where=='/verified_direct_bridges/'+str(index-5)
                assert origin==raw['verified_direct_bridges'][index-5]
        assert len(manifest['dependency_contracts'])==18 and len(manifest['windows'])==1
        for index,(row,origin) in enumerate(zip(manifest['dependency_contracts'],formal['dependency_contracts'])):
            assert row==dict(va=origin['va'],contract=origin['contract'],scope=origin['scope'],
                            evidence='证据/formal_functions.json#/dependency_contracts/'+str(index))
        window,=manifest['windows']
        assert not {'va','status','conclusion'}.intersection(window)
        assert window['owner_va']=='0x7c6640' and '有限' in window['window_status']
        assert window['evidence']==['证据/formal_functions.json#/caller_windows/'+str(i) for i in range(7)]+[
            '证据/bounded_raw.json#/explicit_owner_windows/'+str(i) for i in range(5)]
        author_path=HERE/'author_validation.json'
        author=json.loads(author_path.read_bytes())
        assert author['status']=='PASS' and author['disk_sha256']==PE_SHA and author['raw_sha256']==RAW_SHA
        assert [{k:r[k] for k in ('va','bytes','instructions')} for r in author['subjects']]==result['functions']
        assert author['dependencies']==dependencies and author['caller_windows']==windows
        assert (author['direct_calls'],author['indirect_calls'],author['ida_bridges'],
                author['offline_navigation_bridges'],author['incoming_entries'],author['unique_navigation_windows'])==(41,0,14,9,10,5)
        docs=sorted(topic.glob('*.txt'))
        assert [p.name[:2] for p in docs]==['00','01','02','03','04']
        for path in docs:
            assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf8').splitlines())
        assert '状态：静态独审 PASS' in (topic/'04_独立审阅.txt').read_text(encoding='utf8')
        expected_paths={str(p.relative_to(topic)).replace('\\','/') for p in docs if p.name[:2]!='04'} | {
            '函数审阅清单.json','证据/bounded_raw.json','证据/formal_functions.json','证据/export_bounded.py',
            '证据/build_formal.py','证据/build_review.py','证据/validate_author.py'}
        assert set(author['final_binding_sha256'])==expected_paths
        for path,digest in author['final_binding_sha256'].items():
            assert sha((topic/path).read_bytes())==digest
        result['status']='PASS'
        result['scope']='五完整主体静态审阅；旧18短契约和caller有限范围仅复用，不证明实机行为或全部调度器'
        result['final_binding_sha256']={**author['final_binding_sha256'],
            '04_独立审阅.txt':sha((topic/'04_独立审阅.txt').read_bytes()),
            '证据/author_validation.json':sha(author_path.read_bytes()),
            '证据/independent_review.py':sha(Path(__file__).read_bytes())}
    (HERE/'independent_assembly.txt').write_text('\n'.join(transcript)+'\n',encoding='utf8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--final',action='store_true')
    result = audit(parser.parse_args().final)
    (HERE/'independent_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(status=result['status'],fresh_functions=len(result['functions']),
        fresh_bytes=sum(row['bytes'] for row in result['functions']),
        fresh_instructions=sum(row['instructions'] for row in result['functions']),
        model_cases=result['selection_instruction_models']['cases'],
        old_dependency_bytes=sum(row['bytes'] for row in result['old_dependencies']),
        old_dependency_instructions=sum(row['instructions'] for row in result['old_dependencies']),
        old_caller_bytes=sum(row['bytes'] for row in result['finite_caller_windows']),
        old_caller_instructions=sum(row['instructions'] for row in result['finite_caller_windows'])),ensure_ascii=True))
