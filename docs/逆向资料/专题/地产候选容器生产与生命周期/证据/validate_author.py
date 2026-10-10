"""独立解码当前PE，核来源与有限语义锚；不会访问IDA或执行游戏。"""
import json
import struct
from pathlib import Path

import capstone
from build_formal import bind, digest, pe_reader, RAW_SHA, EXPECTED, WINDOWS

HERE = Path(__file__).resolve().parent
DOC_NAMES = ('00_有限采证实施计划.txt','01_容器字段与生命周期.txt',
             '02_地图生产顺序与筛选闭环.txt','03_来源分层与复核边界.txt')


def validate():
    image, read = pe_reader()
    raw_data = (HERE/'bounded_raw.json').read_bytes()
    assert digest(raw_data) == RAW_SHA
    raw = json.loads(raw_data)
    assert raw['disk_sha256'] == EXPECTED
    assert raw['prepared_wrapper_sha256'] == digest((HERE/'export_bounded.py').read_bytes())
    assert [s['seed_va'] for s in raw['seeds']] == ['0x7ecd50','0x7ecd80']
    assert not raw['data_windows'] and not raw['reused_seeds']
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    assert formal['disk_sha256'] == EXPECTED and formal['raw_sha256'] == RAW_SHA
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    decoded = {}
    checked = set()

    def decode(va, blob):
        assert blob == read(va,len(blob))
        ins = list(md.disasm(blob, va))
        assert ins and sum(i.size for i in ins) == len(blob)
        assert ins[0].address == va and ins[-1].address+ins[-1].size == va+len(blob)
        for i in ins:
            old = decoded.get(i.address)
            if old: assert old.bytes == i.bytes
            decoded[i.address] = i
        checked.add((va,len(blob)))
        return ins

    def ranges(blocks):
        result = []
        for b in blocks:
            payload = bytes.fromhex(b['idb_hex'])
            assert len(payload)==b['size'] and payload==bytes.fromhex(b['disk_hex']) and b['matching']
            if 'sha256' in b: assert digest(payload)==b['sha256']
            result += decode(int(b.get('start_va',b.get('va')),16),payload)
        return result

    def source(binding):
        same, original = bind(binding['path'],binding['json_pointer'],binding['base']=='topic')
        assert same == binding
        return original

    def bridge(va):
        blob = read(va,5)
        assert blob[0]==0xE9
        return va+5+struct.unpack_from('<i',blob,1)[0]

    subjects=[]
    direct={}
    for index, f in enumerate(formal['functions']):
        original=source(f['source'])
        assert original==f['source_record']==raw['functions'][index]
        for key in ('name','end_va','pseudocode','decompile_error','chunk_byte_ranges'):
            assert f[key]==original[key]
        assert f['assembly']==[dict(va=r['site_va'],text=r['text'],is_code=r['is_code']) for r in original['assembly']]
        audit=raw['current_chunk_audits'][index]
        assert audit['seed_va']==f['va'] and audit['chunk_byte_ranges']==f['chunk_byte_ranges']
        ins=ranges(f['chunk_byte_ranges'])
        assert [hex(i.address) for i in ins]==[r['va'] for r in f['assembly'] if r['is_code']]
        assert ins[-1].address+ins[-1].size==int(f['end_va'],16)
        assert ins[-1].mnemonic=='ret' and not ins[-1].op_str
        for i in ins:
            if i.mnemonic=='call': direct[(f['va'],hex(i.address))]=hex(i.operands[0].imm)
        subjects.append(dict(va=f['va'],bytes=sum(i.size for i in ins),instructions=len(ins),coverage_origin=f['coverage_origin']))
    assert [(f['bytes'],f['instructions']) for f in subjects]==[(31,11),(36,13)]
    assert direct=={(c['seed_va'],c['site_va']):c['target_va'] for c in raw['calls']}
    for c in raw['calls']:
        target=int(c['target_va'],16)
        for hop in c['bridges']:
            assert target==int(hop,16)
            target=bridge(target)
        assert target==int(c['implementation_va'],16)
    for b in raw['verified_direct_bridges']:
        ranges([b])
        assert bridge(int(b['start_va'],16))==int(b['target_va'],16)
    assert len(raw['verified_direct_bridges'])==4

    legacy=[]
    for index,f in enumerate(formal['legacy_reused_functions']):
        old=source(f['source'])
        assert 'source_record' not in f and isinstance(f['source_record_json'],str)
        assert old==json.loads(f['source_record_json']) and old['状态']=='已逐函数分析'
        audit=raw['legacy_reused_byte_audits'][index]
        assert f['va']==old['地址']==audit['seed_va']
        assert f['source']['sha256']==audit['source_sha256']
        assert f['source']['path']==audit['source_path'] and f['source']['json_pointer']==audit['source_pointer']
        rows=old['完整汇编']
        assert len(rows)==len(audit['instruction_audits'])
        for i,(row,current) in enumerate(zip(rows,audit['instruction_audits'])):
            blob=bytes.fromhex(row['字节核验']['IDB字节'])
            assert row['字节核验']['匹配'] and blob.hex()==row['字节核验']['磁盘字节']
            assert current['source_pointer']==f['source']['json_pointer']+f'/完整汇编/{i}'
            assert current['site_va']==row['地址'] and current['text']==row['汇编']
            assert current['matching'] and current['current_idb_hex']==current['current_disk_hex']==blob.hex()
            assert current['size']==len(blob) and current['sha256']==digest(blob)
            ins=decode(int(row['地址'],16),blob)
            assert len(ins)==1
        data=b''.join(bytes.fromhex(r['字节核验']['IDB字节']) for r in rows)
        ins=decode(int(f['va'],16),data)
        assert len(data)==old['大小']==audit['main_size']==audit['audited_instruction_bytes']
        assert [hex(i.address) for i in ins]==[r['地址'] for r in rows]
        assert ins[-1].mnemonic=='ret' and ins[-1].operands[0].imm==(8 if index==0 else 4)
        for call in old['直接调用']:
            at=int(call['调用点'],16)
            assert decoded[at].mnemonic=='call' and decoded[at].operands[0].imm==int(call['目标'],16)
            if call.get('转接核验'):
                assert read(int(call['目标'],16),5).hex()==call['转接核验']['IDB字节']==call['转接核验']['磁盘字节']
                assert bridge(int(call['目标'],16))==int(call['转接后目标'],16)
        legacy.append(dict(va=f['va'],bytes=len(data),instructions=len(ins),source=f['source']))
    assert [f['bytes'] for f in legacy]==[95,216,90,114]
    historical=[]
    for f in formal['historical_dependencies']:
        old=source(f['source'])
        assert old==f['source_record'] and f['va']==old['va'] and old['status']=='仅导出'
        ins=ranges(old['byte_ranges'])
        assert [hex(i.address) for i in ins]==[r['va'] for r in old['assembly']]
        for c in old['calls']:
            i=decoded[int(c['site'],16)]
            assert i.mnemonic=='call' and i.operands[0].imm==int(c['target'],16)
            target=int(c['target'],16)
            for hop in c['thunks']:
                assert target==int(hop,16)
                target=bridge(target)
            assert target==int(c['implementation'],16)
        historical.append(dict(va=f['va'],instructions=len(ins),source=f['source']))
    assert formal['historical_dependencies'][0]['source_record']['byte_ranges'][0]['idb_hex']==formal['functions'][1]['chunk_byte_ranges'][0]['idb_hex']

    windows=[]
    for w,(index,lo,hi,purpose) in zip(formal['caller_windows'],WINDOWS):
        owner=source(w['source'])
        assert w['owner_va']==owner['地址'] and w['source']['json_pointer']==f'/函数/{index}'
        assert (w['start_va'],w['end_va'],w['window_conclusion'])==(hex(lo),hex(hi),purpose)
        assert w['source_rows']==[owner['完整汇编'][i] for i in w['source_indices']]
        blob=b''.join(bytes.fromhex(r['字节核验']['IDB字节']) for r in w['source_rows'])
        assert blob.hex()==w['byte_audit']['idb_hex']
        ins=ranges([w['byte_audit']])
        assert [hex(i.address) for i in ins]==[r['va'] for r in w['assembly']]
        assert w['assembly']==[dict(va=r['地址'],text=r['汇编']) for r in w['source_rows']]
        assert len(blob)==hi-lo and not {'va','status','conclusion'}.intersection(w)
        windows.append(dict(start_va=hex(lo),end_va=hex(hi),instructions=len(ins),bytes=len(blob)))
    assert len(formal['caller_windows'])==len(WINDOWS)==10
    for b in formal['offline_navigation_bridges']:
        assert 'idb_hex' not in b
        blob=read(int(b['va'],16),5)
        assert blob.hex()==b['disk_hex'] and digest(blob)==b['sha256']
        assert bridge(int(b['va'],16))==int(b['target_va'],16)
    assert len(formal['offline_navigation_bridges'])==8
    navigation={}
    def nav(w):
        key=(w['owner_va'],w['site_va'])
        if key in navigation: assert navigation[key]==w['assembly']
        navigation[key]=w['assembly']
        for row in w['assembly']:
            ins=ranges([row['bytes']])
            assert len(ins)==1 and hex(ins[0].address)==row['site_va']
        assert w['site_va'] in {r['site_va'] for r in w['assembly']}
    for entries in raw['incoming'].values():
        for entry in entries:
            if entry['is_code']:
                at=int(entry['site_va'],16)
                i=next(md.disasm(read(at,5),at))
                assert i.mnemonic in ('call','jmp') and i.operands[0].imm==int(entry['target_va'],16)
            if entry.get('owner_window'): nav(entry['owner_window'])
    for w in raw['explicit_owner_windows']: nav(w)
    assert len(raw['explicit_owner_windows'])==12
    anchors={
        0x7ECD61:('mov','dword ptr [eax + 0xc], 0'), 0x7ECD68:('mov','eax, dword ptr [ebp - 4]'),
        0x7ECD8E:('mov','ecx, dword ptr [ebp - 4]'), 0x7ECF8A:('cmp','dword ptr [eax + 0xc], 0'),
        0x7ECFA8:('mov','dword ptr [ecx + 0xc], 0'), 0x7ECDCA:('mov','dword ptr [eax], 0'),
        0x7ECDE8:('shl','eax, 1'), 0x7ECDFC:('mov','dword ptr [ecx + 0xc], edx'),
        0x7ECE55:('jl','0x7eced0'), 0x7ECE69:('add','eax, dword ptr [ecx + 8]'),
        0x7ECE86:('mov','edx, dword ptr [ecx + 4]'), 0x7ECE89:('shl','edx, 1'),
        0x7ECEDB:('mov','dx, word ptr [ebp + 8]'), 0x7ECEDF:('mov','word ptr [eax + ecx*2], dx'),
        0x7ECEE8:('add','ecx, 1'), 0x7ECEF5:('sub','eax, 1'),
        0x7DF542:('push','0x10'),0x7DF544:('push','0x20'),0x7DF549:('add','ecx, 0x46c'),
        0x7DF9BC:('mov','dword ptr [ebp - 0x28], 0'),0x7DF9D4:('cmp','eax, dword ptr [edx + 0x24]'),
        0x7DF9D7:('jge','0x7dfccc'),0x7DFA16:('mov','byte ptr [ecx + eax], dl'),
        0x7DFA2B:('mov','byte ptr [edx + eax + 1], cl'),
        0x7DFB60:('mov','byte ptr [ecx + edx + 1], 0xff'),
        0x7DFC02:('je','0x7dfc96'),0x7DFC58:('je','0x7dfc83'),
        0x7DFC76:('add','ecx, 0x47c'),0x7DFC8B:('add','ecx, 0x46c'),0x7DFCC7:('jmp','0x7df9c5'),
    }
    for at,want in anchors.items():
        got=decoded[at]
        assert (got.mnemonic,got.op_str)==want,(hex(at),got.mnemonic,got.op_str,want)
    # 模型用于解释已核指令的边界，不执行分配器，也不把内存失败当成功。
    def signed16(n):
        n &= 0xFFFF
        return n if n<0x8000 else n-0x10000
    cases=[(32767,32767),(32768,-32768),(65535,-1),(65536,0)]
    assert all(signed16(a)==b for a,b in cases)
    cap=32
    allocations=[]
    for n in range(65):
        if n>=cap:
            old=cap;cap+=16;allocations.append((n,old,cap))
        assert n<cap
    assert allocations==[(32,32,48),(48,48,64),(64,64,80)]
    assert 32+0<=32 and 32-1<32
    manifest=json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
    assert len(manifest['functions'])==len({f['va'] for f in manifest['functions']})==6
    assert [f['va'] for f in manifest['functions'][:2]]==['0x7ecd50','0x7ecd80']
    assert len(manifest['dependency_contracts'])==5 and len(manifest['windows'])==3
    for f in manifest['functions']+manifest['dependency_contracts']:
        p,j=f['evidence'].split('#');_,node=bind(p,j,True)
        assert f['va']==node.get('va',node.get('start_va'))
    for w in manifest['windows']:
        assert not {'va','status','conclusion'}.intersection(w)
        for ref in w['evidence']:
            p,j=ref.split('#');_,node=bind(p,j,True)
            assert w['owner_va']==node['owner_va']
    for name in DOC_NAMES:
        assert all(not s.strip() or s.startswith('//') for s in (HERE.parent/name).read_text(encoding='utf8').splitlines())
    paths=[HERE.parent/n for n in DOC_NAMES]+[HERE.parent/'函数审阅清单.json']+[
        HERE/n for n in ('bounded_raw.json','formal_functions.json','export_bounded.py','build_formal.py','build_review.py','validate_author.py')]
    return dict(status='PASS',scope='当前字节与作者静态审阅；不证明动态有效尺寸、全体写者或失败分配安全',
        raw_sha256=RAW_SHA,disk_sha256=digest(image),subjects=subjects,legacy=legacy,historical=historical,
        owner_windows=windows,unique_byte_ranges=len(checked),unique_navigation_windows=len(navigation),
        instruction_anchors=len(anchors),ida_bridges=4,offline_bridges=8,word_model_cases=cases,
        normal_growth_model=allocations,global_new_subjects=1,reexported_subjects=1,
        final_binding_sha256={p.relative_to(HERE.parent).as_posix():digest(p.read_bytes()) for p in paths})


if __name__=='__main__':
    report=validate()
    (HERE/'author_validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:report[k] for k in ('status','subjects','unique_byte_ranges','instruction_anchors','global_new_subjects')},ensure_ascii=False))
