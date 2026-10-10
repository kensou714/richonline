"""离线核当前PE、冻结原证、无损适配、来源指针与分级边界。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '15be75a1ad6266da6a0df0010c3316ec45619f2e78f05ae691ddc50f4a50c1d6'
SUPPLEMENT_SHA = '5211fcf04136f28f57a91453be58a22d8f01304f98393371726d06a4ef9770bf'
CONTAINER_SHA = '50b81df4ceb2447338eee2df17334ebc7cc75944b9cc725dc30db056d05071cc'


def pointer(value, path):
    for part in path.strip('/').split('/'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def validate():
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I',image,0x3C)[0]
    assert image[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H',image,pe+24)[0] == 0x10B
    base = struct.unpack_from('<I',image,pe+52)[0]
    table = pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections = [struct.unpack_from('<4I',image,table+40*i+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    decoder = Cs(CS_ARCH_X86,CS_MODE_32)
    ranges, bridges, heads, sources = set(), set(), set(), set()

    def disk(va,size):
        matches = [(rva,off) for _,rva,length,off in sections if 0 <= va-base-rva and va-base-rva+size <= length]
        assert len(matches) == 1, (hex(va),size)
        rva,off = matches[0]
        return image[off+va-base-rva:off+va-base-rva+size]

    def scan(value):
        if isinstance(value,dict):
            if 'idb_hex' in value and 'size' in value:
                va = int(value.get('start_va',value.get('va')),16)
                if value.get('disk_hex') is not None:
                    data = disk(va,value['size'])
                    assert data.hex() == value['idb_hex'] == value['disk_hex'], hex(va)
                    if value.get('sha256'):
                        assert hashlib.sha256(data).hexdigest() == value['sha256']
                    ranges.add((va,len(data)))
                    target = value.get('target_va',value.get('target'))
                    if target:
                        assert len(data)==5 and data[0]==0xE9
                        assert va+5+struct.unpack_from('<i',data,1)[0] == int(target,16)
                        bridges.add(va)
                else:
                    assert value.get('matching') is None
            for child in value.values():
                scan(child)
        elif isinstance(value,list):
            for child in value:
                scan(child)

    def declared(row):
        chunks = row.get('chunk_byte_ranges',row.get('byte_ranges',[]))
        assert chunks, row.get('va',row.get('seed_va'))
        known = set()
        for c in chunks:
            lo = int(c.get('va',c.get('start_va')),16)
            data = disk(lo,c['size'])
            decoded = list(decoder.disasm(data,lo))
            assert sum(x.size for x in decoded)==len(data),(hex(lo),len(data))
            known.update(x.address for x in decoded)
        for ins in row['assembly']:
            if ins.get('is_code',True):
                va = int(ins.get('va',ins.get('site_va')),16)
                assert va in known, ins
                heads.add(va)
        for c in row.get('declared_chunks',[]):
            lo,hi = int(c['start_va'],16),int(c['end_va'],16)
            assert any(int(x.get('va',x.get('start_va')),16)==lo and x['size']==hi-lo for x in chunks)

    payload = (HERE/'bounded_raw.json').read_bytes()
    assert hashlib.sha256(payload).hexdigest() == RAW_SHA
    raw = json.loads(payload)
    assert raw['schema']=='richonline-bounded-preparation-1' and raw['disk_sha256']==EXPECTED
    assert [x['seed_va'] for x in raw['seeds']]==['0x6b20a0','0x6b81d0','0x6ad9f0','0x73d560','0x6aebe0']
    assert not raw['data_windows'] and not raw['strings']
    scan(raw)
    for row in raw['functions']:
        declared(row)
    for ref in raw['reuse_sources']:
        source = ROOT/'docs/逆向资料'/ref['path']
        assert hashlib.sha256(source.read_bytes()).hexdigest()==ref['source_sha256'],ref['path']
        sources.add(str(source))
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    assert formal['disk_sha256']==EXPECTED and formal['source_sha256']==RAW_SHA
    assert [x['va'] for x in formal['functions']]==[x['seed_va'] for x in raw['functions']]
    scan(formal)
    for row in formal['functions']:
        old = pointer(raw,row['source']['json_pointer'])
        assert row['source']['sha256']==RAW_SHA and row['va']==old['seed_va']
        assert row['end_va']==old['end_va'] and row['pseudocode']==old['pseudocode'] and row['decompile_error']==old['decompile_error']
        assert row['assembly']==[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in old['assembly']]
        assert row['chunk_byte_ranges']==[dict(va=c['start_va'],**{k:v for k,v in c.items() if k!='start_va'}) for c in old['chunk_byte_ranges']]
        declared(row)
    reuse = json.loads((HERE/'reused_raw.json').read_bytes())
    assert len(reuse['records'])==8
    for record in reuse['records']:
        ref = record['source']
        source = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(source).hexdigest()==ref['sha256']
        assert pointer(json.loads(source),ref['pointer'])==record['original_record']
        scan(record['original_record'])
        declared(record['original_record'])
    # 指定旧主体块必须与新冻结raw的当前逐块审计同域相同，不补造旧声明块。
    old_ranges = reuse['records'][0]['original_record']['chunk_byte_ranges']
    current = next(x for x in raw['current_chunk_audits'] if x['seed_va']=='0x6aebe0')['chunk_byte_ranges']
    assert [(x['va'],x['size'],x['disk_hex']) for x in old_ranges] == [(x['start_va'],x['size'],x['disk_hex']) for x in current]
    navigation = json.loads((HERE/'source_navigation.json').read_bytes())
    assert navigation['bounded_owner_windows']==raw['explicit_owner_windows'] and navigation['bounded_incoming']==raw['incoming']
    for owner in navigation['owners']:
        assert not {'va','status','conclusion'} & owner.keys()
        ref = owner['source']
        source = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(source).hexdigest()==ref['sha256']
        assert pointer(json.loads(source),ref['pointer'])==owner['original_record']
        assert owner['original_record']['va']==owner['owner_va']
    network = json.loads((HERE/'network_production_navigation.json').read_bytes())
    ref = network['source']
    payload = (HERE/ref['path']).read_bytes()
    assert hashlib.sha256(payload).hexdigest()==ref['sha256']
    assert json.loads(payload)==network['original_document']
    for row in network['original_document']['functions']:
        ref = row['source']
        source = ROOT/'docs/逆向资料'/ref['path']
        assert hashlib.sha256(source.read_bytes()).hexdigest()==ref['sha256']
        original = json.loads(source.read_bytes())
        original_rows = original if isinstance(original,list) else original['functions']
        assert row['record'] in original_rows
        audited = row['current_range_audit']
        data = disk(int(audited['start_va'],16),audited['size'])
        assert data.hex()==audited['disk_hex']
        assert hashlib.sha256(data).hexdigest()==audited['sha256']
        legacy = row['legacy_version_record']
        assert legacy['matches_disk'] and legacy['idb_sha256']==legacy['disk_sha256']==audited['sha256']
        assert legacy['byte_count']==len(data)
        ranges.add((int(audited['start_va'],16),len(data)))
    supplement_payload=(HERE/'supplement_raw.json').read_bytes()
    assert hashlib.sha256(supplement_payload).hexdigest()==SUPPLEMENT_SHA
    supplement=json.loads(supplement_payload)
    supplement_formal=json.loads((HERE/'supplement_formal.json').read_bytes())
    assert supplement_formal['source_sha256']==SUPPLEMENT_SHA
    assert len(supplement_formal['functions'])==4
    scan(supplement)
    for row in supplement_formal['functions']:
        old=pointer(supplement,row['source']['json_pointer'])
        assert row['va']==old['seed_va'] and row['source']['sha256']==SUPPLEMENT_SHA
        assert row['end_va']==old['end_va'] and row['pseudocode']==old['pseudocode'] and row['decompile_error']==old['decompile_error']
        assert row['assembly']==[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in old['assembly']]
        assert row['chunk_byte_ranges']==[dict(va=c['start_va'],**{k:v for k,v in c.items() if k!='start_va'}) for c in old['chunk_byte_ranges']]
        scan(row)
        declared(row)
    assert [x for row in supplement_formal['functions'] for x in row['assembly'] if not x['is_code']]==[dict(va='0x922873',text='align 4',is_code=False)]
    historical=json.loads((HERE/'historical_crt_sources.json').read_bytes())
    assert len(historical['records'])==3
    for item in historical['records']:
        ref=item['source']
        payload=(HERE/ref['path']).read_bytes()
        assert hashlib.sha256(payload).hexdigest()==ref['sha256']
        old=pointer(json.loads(payload),ref['pointer'])
        assert old==item['original_record']
        if item['range_key']:
            current=next(x for x in supplement_formal['functions'] if x['va']==old['va'])
            assert [(c['va'],c['size'],c['disk_hex']) for c in old[item['range_key']]]==[(c['va'],c['size'],c['disk_hex']) for c in current['chunk_byte_ranges']]
    container_payload=(HERE/'container_dependency/bounded_raw.json').read_bytes()
    assert hashlib.sha256(container_payload).hexdigest()==CONTAINER_SHA
    container_raw=json.loads(container_payload)
    container_formal=json.loads((HERE/'container_formal.json').read_bytes())
    assert container_formal['source_sha256']==CONTAINER_SHA and len(container_formal['functions'])==2
    scan(container_raw)
    for row in container_formal['functions']:
        old=pointer(container_raw,row['source']['json_pointer'])
        assert row['va']==old['seed_va'] and row['source']['sha256']==CONTAINER_SHA
        assert row['end_va']==old['end_va'] and row['pseudocode']==old['pseudocode'] and row['decompile_error']==old['decompile_error']
        assert row['assembly']==[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in old['assembly']]
        assert row['chunk_byte_ranges']==[dict(va=c['start_va'],**{k:v for k,v in c.items() if k!='start_va'}) for c in old['chunk_byte_ranges']]
        scan(row)
        declared(row)
    template=json.loads((HERE/'container_template_navigation.json').read_bytes())
    ref=template['source']
    payload=(HERE/ref['path']).read_bytes()
    assert hashlib.sha256(payload).hexdigest()==ref['sha256'] and pointer(json.loads(payload),ref['pointer'])==template['original_record']
    for chunk in template['original_record']['function']['chunks']:
        data=disk(int(chunk['va'],16),chunk['size'])
        assert data.hex()==chunk['ida_hex']==chunk['disk_hex'] and hashlib.sha256(data).hexdigest()==chunk['sha256']
        ranges.add((int(chunk['va'],16),len(data)))
    review = json.loads((HERE.parent/'function_review.json').read_bytes())
    assert len(review['functions'])==10 and len(review['reused_reviews'])==1
    assert [x['va'] for x in review['functions']]==[x['va'] for x in formal['functions']+supplement_formal['functions']+container_formal['functions']]
    assert review['reused_reviews'][0]['va']=='0x6aebe0'
    for row in review['functions']+review['reused_reviews']:
        assert row['status']=='局部语义已审阅' and row['unknown'] and row['anchors']
        for ref in row['source_records']:
            source = (HERE.parent/ref['path']).read_bytes()
            assert hashlib.sha256(source).hexdigest()==ref['sha256']
            original = pointer(json.loads(source),ref['pointer'])
            assert original['va']==row['va'] and original.get('declared_chunks',[])==row['declared_chunks']
            assert original.get('chunk_byte_ranges',original.get('byte_ranges',[]))==row['original_byte_ranges']
        for anchor in row['anchors']:
            source = json.loads((HERE.parent/anchor['path']).read_bytes())
            assert pointer(source,anchor['pointer'])==anchor['value']
            assert int(anchor['site_va'],16) in heads
    # 作者只锁自己的正文；独审文件由独审锁指纹，避免并行编辑改变作者范围。
    docs = [p for p in HERE.parent.glob('*.txt') if p.name.startswith(('00_','01_','02_','03_','04_','05_'))]
    assert all(not line.strip() or line.startswith('//') for p in docs for line in p.read_text(encoding='utf-8').splitlines())
    result = dict(status='PASS',scope='四全局新主本体+六本轮采证依赖（四全局新、两旧CRT重采）+一旧指定主体与七旧短契约；85B870下层取槽内部未展开',
        global_new_functions=8,dependency_global_new_functions=4,reacquired_crt_functions=2,
        disk_sha256=EXPECTED,bounded_source_sha256=RAW_SHA,fresh_functions=4,fresh_declared_bytes=676,
        fresh_instruction_entries=sum(len(x['assembly']) for x in formal['functions']),
        supplementary_functions=4,supplementary_declared_bytes=sum(c['size'] for row in supplement_formal['functions'] for c in row['chunk_byte_ranges']),
        supplementary_instruction_entries=sum(x['is_code'] for row in supplement_formal['functions'] for x in row['assembly']),
        supplementary_noncode_entries=1,supplementary_sha256=SUPPLEMENT_SHA,
        container_functions=2,container_declared_bytes=187,container_instruction_entries=65,container_sha256=CONTAINER_SHA,
        reused_subject_reviews=1,reused_records=8,unique_saved_ranges=len(ranges),unique_verified_e9_bridges=len(bridges),
        old_network_navigation=4,
        instruction_heads=len(heads),bounded_reuse_sources=len(sources),
        documents={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in docs},
        limitation='所有review是局部静态语义；源码自动名、旧schema字段和owner原记录不晋升业务或完整函数覆盖。')
    (HERE/'author_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    print(json.dumps(validate(),ensure_ascii=True))
