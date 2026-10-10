"""离线核字节、无损来源、调用桥、有限窗口、样本与语义锚；不执行客户端。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
DOCS=ROOT/'docs/逆向资料'
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA='b54d51310320c1d05b44407c76fd02177ad3f196b87f8175ef00dc24df8e75fa'


def pointer(obj,path):
    for k in path.strip('/').split('/'):
        obj=obj[int(k)] if isinstance(obj,list) else obj[k]
    return obj


def main():
    image=(ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==SHA
    pe=struct.unpack_from('<I',image,60)[0]
    base=struct.unpack_from('<I',image,pe+52)[0]
    tab=pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections=[struct.unpack_from('<4I',image,tab+40*i+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    decoder=Cs(CS_ARCH_X86,CS_MODE_32)
    counts=dict(byte_ranges=0,body_instructions=0,data_items=0,owner_items=0,anchors=0)
    sources,hashes,decoded,original_text={},{},{},{}
    listing=[]
    def disk(va,size):
        hits=[(r,o) for _,r,n,o in sections if base+r<=va and va+size<=base+r+n]
        assert len(hits)==1,(hex(va),size)
        r,o=hits[0]
        return image[o+va-base-r:o+va-base-r+size]
    def audit(r):
        va=int(r.get('start_va',r.get('va')),16);b=disk(va,r['size'])
        assert b.hex()==r['disk_hex'].lower()
        for k in ('idb_hex','ida_hex'):
            if k in r:assert b.hex()==r[k].lower()
        if 'sha256' in r:assert hashlib.sha256(b).hexdigest()==r['sha256']
        assert r.get('matching',r.get('equal',True)) is True
        counts['byte_ranges']+=1
        return b
    def load(name):
        b=(HERE/name).read_bytes();hashes[name]=hashlib.sha256(b).hexdigest();sources[name]=json.loads(b);return sources[name]
    bounded=load('bounded_raw.json')
    assert hashes['bounded_raw.json']==RAW_SHA and bounded['disk_sha256']==SHA
    assert [r['seed_va'] for r in bounded['functions']]==['0x6dfa10','0x6d76c0','0x6d7c00','0x6d7c30']
    assert [r['seed_va'] for r in bounded['reused_seeds']]==['0x6d7660','0x6dfd10']
    for filename in ('formal_functions.json','reused_functions.json'):
        for row in load(filename)['functions']:
            src=(DOCS/row['source_path']).read_bytes()
            assert hashlib.sha256(src).hexdigest()==row['source_sha256']
            original=pointer(json.loads(src),row['source_pointer'])
            assert row['source_field_pointers']=={k:row['source_pointer']+'/'+k for k in original}
            for k,v in original.items():assert row[k]==v
            if 'current_bytes_source' in row:
                ref=row['current_bytes_source'];assert ref['source_sha256']==RAW_SHA
                fresh=pointer(bounded,ref['source_pointer']);assert fresh['seed_va']==row['va']
                assert row['chunk_byte_ranges']==fresh['chunk_byte_ranges']
            assembly=original.get('assembly',original.get('instructions'))
            assert len(assembly)==len(row['normalized_assembly'])
            decoded[row['va']]={};original_text[row['va']]={}
            for orig,norm in zip(assembly,row['normalized_assembly']):
                assert norm['original']==orig and norm['text']==orig['text']
                assert norm['site_va']==orig.get('site_va',orig.get('va'))
                original_text[row['va']][norm['site_va']]=norm['text']
            assert len(row['declared_chunks'])==len(row['normalized_chunks'])
            listing.append('// '+row['va']+' '+row['adaptation_scope'])
            for declared,chunk in zip(row['declared_chunks'],row['normalized_chunks']):
                b=audit(chunk);start=int(chunk['start_va'],16);end=start+len(b)
                assert int(declared['start_va'],16)==start and int(declared['end_va'],16)==end
                items=[a for a in row['normalized_assembly'] if start<=int(a['site_va'],16)<end]
                assert items and int(items[0]['site_va'],16)==start
                for i,a in enumerate(items):
                    at=int(a['site_va'],16);stop=int(items[i+1]['site_va'],16) if i+1<len(items) else end
                    raw=disk(at,stop-at)
                    if a.get('normalized_item_kind')=='data' or not a['is_code']:
                        counts['data_items']+=1;text='声明数据 '+raw.hex()
                    else:
                        ins=list(decoder.disasm(raw,at));assert len(ins)==1 and ins[0].size==len(raw),(hex(at),raw.hex())
                        text=ins[0].mnemonic+' '+ins[0].op_str
                        decoded[row['va']][a['site_va']]=text
                        counts['body_instructions']+=1
                    listing.append('// '+hex(at)+' '+text)
    for r in bounded['current_chunk_audits']:
        for chunk in r['chunk_byte_ranges']:audit(chunk)
    bridges={}
    for b in bounded['verified_direct_bridges']:
        raw=audit(b);at=int(b['start_va'],16);assert len(raw)==5 and raw[0]==0xe9
        target=at+5+struct.unpack_from('<i',raw,1)[0];assert target==int(b['target_va'],16);bridges[at]=target
    def callcheck(call):
        at=int(call.get('site_va',call.get('site')),16);target=int(call.get('target_va',call.get('target')),16)
        raw=disk(at,6)
        if raw[:2]==b'\xff\x15':assert struct.unpack_from('<I',raw,2)[0]==target
        else:assert raw[0] in (0xe8,0xe9) and at+5+struct.unpack_from('<i',raw,1)[0]==target
        for bridge in call.get('bridges',call.get('thunks',[])):
            assert int(bridge,16)==target
            b=disk(target,5);assert b[0]==0xe9;target+=5+struct.unpack_from('<i',b,1)[0]
        assert target==int(call.get('implementation_va',call.get('implementation')),16)
    for call in bounded['calls']:callcheck(call)
    for row in sources['reused_functions.json']['functions']:
        for call in row.get('calls',[]):callcheck(call)
    windows=bounded['explicit_owner_windows']+[e['owner_window'] for entries in bounded['incoming'].values() for e in entries if 'owner_window' in e]
    for w in windows:
        previous=None
        for a in w['assembly']:
            raw=audit(a['bytes']);at=int(a['site_va'],16)
            assert previous is None or previous==at
            previous=at+len(raw);ins=list(decoder.disasm(raw,at))
            assert a['is_code'] and len(ins)==1 and ins[0].size==len(raw)
            counts['owner_items']+=1
    for r,expected in zip(bounded['data_windows'],(b'OTHER_%d\0',b'O_%d_S_%d\0',b'npid\0')):
        assert audit(r)==expected and b'\0' not in expected[:-1]
    assert len(bounded['data_windows'])==3 and not bounded['strings']
    # 额外只读磁盘观察：绑定loader压入的文件名字节；不是本批IDA字符串原证。
    filename_push=disk(0x6DA1A1,5)
    assert filename_push[0]==0x68
    filename_va=struct.unpack_from('<I',filename_push,1)[0]
    assert filename_va==0xA23EE0 and disk(filename_va,10)==b'other.dat\0'
    for ref in bounded['reuse_sources']:
        assert hashlib.sha256((DOCS/ref['path']).read_bytes()).hexdigest()==ref['source_sha256']
    ledger=json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
    assert len(ledger['functions'])==4 and len(ledger['historical_contracts'])==7
    for r in ledger['functions']+ledger['historical_contracts']:
        original=pointer(sources[r['evidence_ref']['file']],r['evidence_ref']['pointer'])
        assert r['va']==original['va'] and r['source_sha256']==original['source_sha256']
        assert r['declared_chunks']==original['declared_chunks'] and r['mechanical_items']==len(original['normalized_assembly'])
        for a in r['semantic_anchors']:
            assert a['original_text']==original_text[r['va']][a['va']]
            assert a['va'] in decoded[r['va']]
            counts['anchors']+=1
    # 核关键数值和分支，避免只靠原汇编文本自洽。
    tokens={'0x6d76d1':'0xffffffff','0x6d76db':'0xffffffff','0x6d76e5':'0xffffffff','0x6d7c11':'0','0x6d7c1a':'0','0x6d7c68':'0',
            '0x6da2a6':'0x4b0','0x6da28b':'jle','0x6da39d':'0x6da463','0x6da416':'+ 4]','0x6da457':'0x580cc',
            '0x6dfd24':'sub','0x6dfd38':'ecx*4','0x6dba1c':'0x12c4'}
    allcode={va:text for rows in decoded.values() for va,text in rows.items()}
    for va,t in tokens.items():assert t in allcode[va],(va,allcode[va])
    resource=load('resource_audit.json')
    assert resource==runpy.run_path(str(HERE/'resource_audit.py'))['inspect']()
    assert resource['group_count']==76 and resource['groups'][4]['loaded_prefix_count']==39
    for p in HERE.parent.glob('*.txt'):
        assert all(not s.strip() or s.startswith('//') for s in p.read_text('utf-8').splitlines())
    (HERE/'review_assembly.txt').write_text('\n'.join(listing)+'\n','utf-8')
    result=dict(status='PASS',disk_sha256=SHA,source_sha256=hashes,**counts,
                formal_functions=4,historical_records=7,new_bytes=216,new_instructions=70,
                loader_mechanical_instructions=len(decoded['0x6d8130']),direct_calls=len(bounded['calls']),
                formal_bridges=len(bridges),window_records=len(windows),resource_groups=76,
                offline_filename_observation=dict(site_va='0x6da1a1',target_va=hex(filename_va),size=10,
                                                  hex=disk(filename_va,10).hex(),scope='仅当前磁盘观察，非新增IDA声明字符串'),
                scope='完整机械字节核验不等于整个loader业务完成；样本不等于运行态')
    (HERE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='source_sha256'},ensure_ascii=False))


if __name__=='__main__':
    main()
