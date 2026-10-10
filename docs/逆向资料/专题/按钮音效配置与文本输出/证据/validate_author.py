"""验证当前PE、七主体双来源、指定复用、字符串和导航防误计。"""
import hashlib
import json
from pathlib import Path
import struct
import capstone

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
DOCS=ROOT/'docs/逆向资料'
EXPECTED='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def validate():
    image=(ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==EXPECTED
    pe=struct.unpack_from('<I',image,60)[0]
    base=struct.unpack_from('<I',image,pe+52)[0]
    table=pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections=[struct.unpack_from('<4I',image,table+i*40+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    def read(va,size):
        candidates=[(rva,off) for _,rva,n,off in sections if rva<=va-base and va-base+size<=rva+n]
        assert len(candidates)==1,(hex(va),size)
        rva,off=candidates[0]
        return image[off+va-base-rva:off+va-base-rva+size]
    checked=[]
    def walk(node):
        if isinstance(node,dict):
            payload=node.get('idb_hex',node.get('ida_hex'))
            if payload is not None:
                va=int(node.get('start_va',node.get('va')),16)
                blob=bytes.fromhex(payload)
                assert len(blob)==node['size']
                assert blob==bytes.fromhex(node['disk_hex'])==read(va,len(blob))
                assert node.get('matching',node.get('equal')) is True
                if node.get('sha256'):assert hashlib.sha256(blob).hexdigest()==node['sha256']
                checked.append((hex(va),len(blob)))
            for value in node.values():walk(value)
        elif isinstance(node,list):
            for value in node:walk(value)
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    raw_bytes=(HERE/'bounded_raw.json').read_bytes()
    raw=json.loads(raw_bytes)
    assert raw['disk_sha256']==EXPECTED
    walk(raw)
    formal=json.loads((HERE/'formal_functions.json').read_bytes())
    assert formal['source_sha256']==hashlib.sha256(raw_bytes).hexdigest()
    assert formal['disk_sha256']==EXPECTED and len(formal['functions'])==7
    subjects=[]
    for index,f in enumerate(formal['functions']):
        addresses=set()
        for block in f['chunk_byte_ranges']:
            decoded=list(decoder.disasm(bytes.fromhex(block['idb_hex']),int(block['va'],16)))
            assert sum(i.size for i in decoded)==block['size']
            addresses.update(i.address for i in decoded)
        assert len(f['chunk_byte_ranges'])==1
        assert addresses=={int(i['va'],16) for i in f['assembly'] if i.get('is_code',True)}
        block=f['chunk_byte_ranges'][0]
        assert int(f['end_va'],16)==int(block['va'],16)+block['size']
        assert f['declared_chunks']==[dict(start_va=block['va'],end_va=f['end_va'],is_main=True)]
        assert f['bytes_match_disk'] is True
        if index<6:
            original=raw['functions'][index]
            assert f['va']==original['seed_va']
            for key in ('end_va','name','pseudocode','decompile_error'):assert f[key]==original[key]
            assert f['assembly']==[dict(va=i['site_va'],text=i['text'],is_code=i['is_code']) for i in original['assembly']]
            assert f['source']==dict(path='证据/bounded_raw.json',sha256=formal['source_sha256'],json_pointer='/functions/'+str(index))
            expected_ranges=original['chunk_byte_ranges']
        else:
            legacy_path=DOCS/'专题/界面系统/第二批/ida_ui_batch2_raw.json'
            legacy_bytes=legacy_path.read_bytes()
            original=json.loads(legacy_bytes)['functions']['0x90b500']
            assert f['va']==original['address']=='0x90b500' and f['end_va']==original['end']
            assert f['name']==original['name'] and f['pseudocode']==original['pseudocode']
            assert f['assembly']==original['instructions'] and f['decompile_error'] is None
            assert bytes.fromhex(original['idb_bytes_hex'])==read(0x90B500,371)
            assert f['source']==dict(path='../界面系统/第二批/ida_ui_batch2_raw.json',
                sha256=hashlib.sha256(legacy_bytes).hexdigest(),json_pointer='/functions/0x90b500')
            audit_index,audit=next((i,a) for i,a in enumerate(raw['current_chunk_audits']) if a['seed_va']=='0x90b500')
            assert f['current_audit_source']==dict(path='证据/bounded_raw.json',sha256=formal['source_sha256'],
                                                   json_pointer='/current_chunk_audits/'+str(audit_index))
            expected_ranges=audit['chunk_byte_ranges']
        assert f['chunk_byte_ranges']==[dict(va=b['start_va'],**{k:v for k,v in b.items() if k!='start_va'}) for b in expected_ranges]
        subjects.append(dict(va=f['va'],bytes=block['size'],instructions=len(addresses),origin=f['coverage_origin']))
    dep=json.loads((HERE/'dependency_raw.json').read_bytes())
    assert dep['disk_sha256']==EXPECTED
    walk(dep)
    assert len(dep['functions'])==1
    f=dep['functions'][0]
    block=f['chunk_byte_ranges'][0]
    decoded=list(decoder.disasm(bytes.fromhex(block['idb_hex']),int(f['va'],16)))
    assert f['va']=='0x90bfb0' and sum(i.size for i in decoded)==44
    assert {i.address for i in decoded}=={int(i['va'],16) for i in f['assembly']}
    for b in raw['verified_direct_bridges']+dep['thunks']:
        va=int(b.get('start_va',b.get('va')),16)
        blob=bytes.fromhex(b['idb_hex'])
        assert len(blob)==5 and blob[0]==0xE9
        assert va+5+struct.unpack_from('<i',blob,1)[0]==int(b.get('target_va',b.get('target')),16)
    reused=[]
    for relative,vas in (
        ('专题/提示文本生命周期/证据/lifecycle.json',('0x8e06f0',)),
        ('专题/文本宽度到字符位置/证据/width_position.json',('0x8e1800','0x924fc0','0x8e0a00')),
        ('专题/文本解析高频接口/证据/entries.json',('0x90fa00','0x90f150')),
        ('专题/文本解析高频接口/证据/parsing_and_callers.json',('0x90ffb0','0x90fec0')),
    ):
        contents=(DOCS/relative).read_bytes()
        data=json.loads(contents)
        assert data['disk_sha256']==EXPECTED
        for va in vas:
            index,f=next((i,f) for i,f in enumerate(data['functions']) if f['va']==va)
            ranges=f.get('chunk_byte_ranges',f.get('byte_ranges',f.get('chunks')))
            walk(ranges)
            count=0
            for b in ranges:
                blob=bytes.fromhex(b.get('idb_hex',b.get('ida_hex')))
                decoded=list(decoder.disasm(blob,int(b.get('start_va',b.get('va')),16)))
                assert sum(i.size for i in decoded)==len(blob)
                count+=len(decoded)
            reused.append(dict(path=relative,va=va,json_pointer='/functions/'+str(index),
                               sha256=hashlib.sha256(contents).hexdigest(),instructions=count,
                               scope='指定复用契约；解析入口只导航不新增完整审阅'))
    strings=[]
    for row in raw['strings']:
        payload=bytes.fromhex(row['payload_hex'])
        assert row['unit_width']==1 and row['nul_hex']=='00'
        assert row['byte_audit']['idb_hex']==row['payload_hex']+'00'
        strings.append(dict(va=row['target_va'],ascii=payload.decode('ascii')))
    assert len(strings)==10
    manifest=json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
    assert len(manifest['windows'])==3
    assert all(not {'va','status','conclusion'}.intersection(w) for w in manifest['windows'])
    assert len({f['va'] for f in manifest['functions']})==len(manifest['functions'])
    assert sum(f['coverage_origin']=='本批新增完整主体' for f in manifest['functions'])==6
    assert sum(f['coverage_origin']=='本批新增短依赖完整主体' for f in manifest['functions'])==1
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    return dict(status='PASS',scope='作者静态验证，不证明运行时播放/渲染/输出成功',
        disk_sha256=EXPECTED,subjects=subjects,dependency=dict(va='0x90bfb0',bytes=44,instructions=12),
        strings=strings,reuse=reused,disk_range_records=len(checked),
        formal_sha256=hashlib.sha256((HERE/'formal_functions.json').read_bytes()).hexdigest(),
        raw_sha256=formal['source_sha256'],dependency_sha256=hashlib.sha256((HERE/'dependency_raw.json').read_bytes()).hexdigest())


if __name__=='__main__':
    result=validate()
    (HERE/'author_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':result['status'],'subjects':result['subjects'],'disk_ranges':result['disk_range_records']},ensure_ascii=True))
