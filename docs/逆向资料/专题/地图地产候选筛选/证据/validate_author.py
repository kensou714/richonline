"""Current bytes, complete-body calls/ABI, bounded old-case bindings and manifest grades."""
import json
from pathlib import Path
import struct

import capstone
from build_formal import bind, digest, pe_reader, RAW_SHA, DEPENDENCIES, WINDOWS, CALLER, CALLER_POINTER

HERE = Path(__file__).resolve().parent
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = ('0x7e4660','0x7e4750','0x7e4830','0x7e4930','0x7e4a30')
DOCS = ('00_有限采证实施计划.txt','01_容器字段与五入口契约.txt',
        '02_旧调度器局部回退与消费.txt','03_证据分层与未决项.txt')


def validate():
    image, read = pe_reader()
    assert digest(image) == EXPECTED
    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    assert digest(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == EXPECTED and not raw['data_windows'] and not raw['reused_seeds']
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    assert formal['raw_sha256'] == RAW_SHA and formal['disk_sha256'] == EXPECTED
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    decoder.detail = True
    checked = []

    def walk(node):
        if isinstance(node,dict):
            payload = node.get('idb_hex',node.get('ida_hex'))
            if payload is not None and 'disk_hex' in node:
                va = int(node.get('start_va',node.get('va')),16)
                blob = bytes.fromhex(payload)
                assert len(blob) == node['size']
                assert blob == bytes.fromhex(node['disk_hex']) == read(va,len(blob))
                assert node.get('matching',node.get('equal')) is True
                if node.get('sha256'): assert digest(blob) == node['sha256']
                checked.append((hex(va),len(blob)))
            for child in node.values(): walk(child)
        elif isinstance(node,list):
            for child in node: walk(child)

    def decode(ranges):
        output = []
        for b in ranges:
            va = int(b.get('start_va',b.get('va')),16)
            payload = bytes.fromhex(b.get('idb_hex',b.get('ida_hex',b.get('disk_hex'))))
            ins = list(decoder.disasm(payload,va))
            assert sum(i.size for i in ins) == b['size'] == len(payload)
            output.extend(ins)
        assert len(output) == len({i.address for i in output})
        return output

    def source_record(source):
        binding, node = bind(source['path'],source['json_pointer'],source['base']=='topic')
        assert binding == source
        return node

    walk(raw)
    assert tuple(f['va'] for f in formal['functions']) == SEEDS
    subjects, direct, decoded = [], {}, {}
    for index,f in enumerate(formal['functions']):
        original = source_record(f['source'])
        assert original == f['source_record'] == raw['functions'][index]
        for key in ('end_va','name','pseudocode','decompile_error','chunk_byte_ranges'):
            assert f[key] == original[key]
        assert f['va'] == original['seed_va']
        assert f['assembly'] == [dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in original['assembly']]
        audit = next(a for a in raw['current_chunk_audits'] if a['seed_va']==f['va'])
        assert f['chunk_byte_ranges'] == audit['chunk_byte_ranges']
        instructions = decode(f['chunk_byte_ranges'])
        assert {i.address for i in instructions} == {int(i['va'],16) for i in f['assembly'] if i['is_code']}
        assert len(f['chunk_byte_ranges']) == 1
        block = f['chunk_byte_ranges'][0]
        assert int(f['end_va'],16) == int(block['start_va'],16)+block['size']
        decoded[f['va']] = {i.address:i for i in instructions}
        for i in instructions:
            if i.mnemonic == 'call':
                assert i.operands[0].type == capstone.x86.X86_OP_IMM
                direct[(f['va'],hex(i.address))] = hex(i.operands[0].imm)
        expected_ret = 12 if f['va']=='0x7e4750' else 8
        assert instructions[-1].mnemonic == 'ret' and instructions[-1].operands[0].imm == expected_ret
        subjects.append(dict(va=f['va'],bytes=block['size'],instructions=len(instructions),chunks=1,stack_argument_bytes=expected_ret))
    assert [x['bytes'] for x in subjects] == [230,215,246,246,223]
    assert direct == {(c['seed_va'],c['site_va']):c['target_va'] for c in raw['calls']}
    assert len(direct) == 41
    for index, va in enumerate(SEEDS):
        rows = decoded[va]
        movsx = [i for i in rows.values() if i.mnemonic=='movsx']
        assert len(movsx)==1 and movsx[0].op_str=='eax, ax'
        calls = [c for c in raw['calls'] if c['seed_va']==va and c['implementation_va']=='0x63e960']
        assert len(calls)==(2 if index<2 else 3)
    for va,at,mnemonic in (('0x7e4660',0x7E4717,'jge'),('0x7e4750',0x7E47F8,'jge'),
            ('0x7e4830',0x7E48E6,'jle'),('0x7e4830',0x7E48F7,'jg'),
            ('0x7e4930',0x7E49E6,'jle'),('0x7e4930',0x7E49F7,'jg'),
            ('0x7e4a30',0x7E4ACF,'jle'),('0x7e4a30',0x7E4AE0,'jg')):
        assert decoded[va][at].mnemonic==mnemonic

    def bridge(va):
        blob=read(va,5)
        assert blob[0]==0xE9
        return va+5+struct.unpack_from('<i',blob,1)[0]

    assert len(raw['verified_direct_bridges'])==len({b['start_va'] for b in raw['verified_direct_bridges']})==14
    for b in raw['verified_direct_bridges']:
        assert b['size']==5 and bridge(int(b['start_va'],16))==int(b['target_va'],16)
    for c in raw['calls']:
        target=int(c['target_va'],16)
        for step in c['bridges']:
            assert target==int(step,16)
            target=bridge(target)
        assert target==int(c['implementation_va'],16)
    assert len(formal['caller_navigation_bridges'])==9
    for b in formal['caller_navigation_bridges']:
        blob=read(int(b['va'],16),5)
        assert blob.hex()==b['disk_hex'] and digest(blob)==b['sha256']
        assert bridge(int(b['va'],16))==int(b['target_va'],16)
        assert 'idb_hex' not in b

    dependencies=[]
    assert len(formal['dependency_contracts'])==len(DEPENDENCIES)==18
    for dep, (path,index,contract) in zip(formal['dependency_contracts'],DEPENDENCIES):
        original=source_record(dep['source'])
        assert original==dep['source_record'] and dep['va']==original['va']
        assert dep['source']['path']==path and dep['source']['json_pointer']=='/functions/'+str(index)
        assert dep['contract']==contract
        walk(original)
        blocks=original.get('chunk_byte_ranges',original.get('byte_ranges'))
        instructions=decode(blocks)
        assert {i.address for i in instructions}=={int(i['va'],16) for i in original['assembly']}
        dependencies.append(dict(va=dep['va'],bytes=sum(b['size'] for b in blocks),instructions=len(instructions),source=dep['source']))

    caller_source,caller=bind(CALLER,CALLER_POINTER)
    caller_bytes=bytes.fromhex(caller['bytes'])
    windows=[]
    assert len(formal['caller_windows'])==len(WINDOWS)==7
    caller_instructions={}
    for w,(lo,hi,purpose) in zip(formal['caller_windows'],WINDOWS):
        assert w['source']==caller_source and w['owner_va']==caller['address']
        assert not {'va','status','conclusion'}.intersection(w)
        assert w['window_conclusion']==purpose and (int(w['start_va'],16),int(w['end_va'],16))==(lo,hi)
        begin,end=w['source_assembly_start'],w['source_assembly_end_exclusive']
        assert w['source_rows']==caller['assembly'][begin:end]
        assert w['assembly']==[dict(va=a,text=t) for a,t in w['source_rows']]
        assert int(caller['assembly'][begin][0],16)==lo and int(caller['assembly'][end][0],16)==hi
        off=w['source_byte_offset']
        assert off==lo-int(caller['address'],16)
        assert bytes.fromhex(w['byte_audit']['idb_hex'])==caller_bytes[off:off+hi-lo]
        walk(w['byte_audit'])
        instructions=decode([w['byte_audit']])
        assert [hex(i.address) for i in instructions]==[x['va'] for x in w['assembly']]
        caller_instructions.update({i.address:i for i in instructions})
        windows.append(dict(start_va=w['start_va'],end_va=w['end_va'],bytes=hi-lo,instructions=len(instructions)))
    for at in (0x7C9031,0x7C9035,0x7C903F): assert caller_instructions[at].mnemonic=='push'
    for at,target,mnemonic in ((0x7C8FD7,0x7C9018,'je'),(0x7C9013,0x7C90BE,'jmp'),
            (0x7CA93D,0x7CA974,'jne'),(0x7CA978,0x7CA9AF,'jne'),(0x7CA9B3,0x7CAB1B,'je')):
        instruction=caller_instructions[at]
        assert instruction.mnemonic==mnemonic and instruction.operands[0].imm==target

    navigation={}
    def window(w):
        key=(w['owner_va'],w['site_va'])
        if key in navigation: assert navigation[key]==w['assembly']
        navigation[key]=w['assembly']
        assert w['site_va'] in {i['site_va'] for i in w['assembly']}
        for row in w['assembly']:
            ins=decode([row['bytes']])
            assert len(ins)==1 and hex(ins[0].address)==row['site_va']
    incoming=0
    for seed,entries in raw['incoming'].items():
        assert seed in SEEDS
        for entry in entries:
            incoming+=1
            if entry['is_code']:
                va=int(entry['site_va'],16)
                instruction=next(decoder.disasm(read(va,5),va))
                assert instruction.mnemonic in ('call','jmp') and instruction.operands[0].imm==int(entry['target_va'],16)
            if entry.get('owner_window'): window(entry['owner_window'])
    for w in raw['explicit_owner_windows']: window(w)
    assert len(raw['explicit_owner_windows'])==5 and {w['owner_va'] for w in raw['explicit_owner_windows']}=={'0x7c6640'}

    manifest=json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
    assert len(manifest['functions'])==len({f['va'] for f in manifest['functions']})==19
    bodies=[f for f in manifest['functions'] if f['status']=='完整函数静态审阅']
    assert tuple(f['va'] for f in bodies)==SEEDS
    assert len(manifest['windows'])==1 and len(manifest['dependency_contracts'])==18
    for row in manifest['functions']+manifest['dependency_contracts']:
        path,pointer=row['evidence'].split('#'); _,node=bind(path,pointer,True)
        assert node.get('va',node.get('start_va'))==row['va']
    for w in manifest['windows']:
        assert not {'va','status','conclusion'}.intersection(w)
        for reference in w['evidence']:
            path,pointer=reference.split('#'); _,node=bind(path,pointer,True)
            assert node['owner_va']==w['owner_va']
    for name in DOCS:
        assert all(not line.strip() or line.startswith('//') for line in (HERE.parent/name).read_text(encoding='utf8').splitlines())
    paths=[HERE.parent/x for x in DOCS]+[HERE.parent/'函数审阅清单.json']+[
        HERE/x for x in ('bounded_raw.json','formal_functions.json','export_bounded.py','build_formal.py','build_review.py','validate_author.py')]
    return dict(status='PASS',scope='作者静态证据核验；不证明运行玩法/容量/动态稳定或网络响应',
        disk_sha256=EXPECTED,raw_sha256=RAW_SHA,subjects=subjects,dependencies=dependencies,
        caller_windows=windows,caller_source=caller_source,equal_byte_records=len(checked),
        direct_calls=len(direct),indirect_calls=0,ida_bridges=14,offline_navigation_bridges=9,
        incoming_entries=incoming,unique_navigation_windows=len(navigation),
        final_binding_sha256={str(p.relative_to(HERE.parent)).replace('\\','/'):digest(p.read_bytes()) for p in paths})


if __name__=='__main__':
    result=validate()
    (HERE/'author_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(status=result['status'],subjects=result['subjects'],direct_calls=result['direct_calls'],
        equal_byte_records=result['equal_byte_records'],caller_windows=result['caller_windows']),ensure_ascii=True))
