"""离线核当前PE、声明块、桥、复用原文、来源散列及逐指令语义锚点。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def pointer(raw, path):
    for part in path.strip('/').split('/'):
        raw = raw[int(part)] if isinstance(raw,list) else raw[part]
    return raw


def validate():
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest()==EXPECTED
    pe = struct.unpack_from('<I',image,0x3C)[0]
    base = struct.unpack_from('<I',image,pe+52)[0]
    table = pe+24+struct.unpack_from('<H',image,pe+20)[0]
    sections = [struct.unpack_from('<4I',image,table+i*40+8) for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    decoder = Cs(CS_ARCH_X86,CS_MODE_32)
    ranges, bridges, heads = set(), set(), set()

    def disk(va,size):
        matches = [(rva,off) for _,rva,length,off in sections if 0<=va-base-rva and va-base-rva+size<=length]
        assert len(matches)==1,(hex(va),size)
        rva,off = matches[0]
        return image[off+va-base-rva:off+va-base-rva+size]

    def scan(value):
        if isinstance(value,dict):
            if 'idb_hex' in value and 'size' in value:
                va = int(value.get('start_va',value.get('va')),16)
                if value.get('disk_hex') is not None:
                    data = disk(va,value['size'])
                    assert data.hex()==value['idb_hex']==value['disk_hex']
                    if value.get('sha256'):
                        assert hashlib.sha256(data).hexdigest()==value['sha256']
                    ranges.add((va,len(data)))
                    target = value.get('target_va',value.get('target'))
                    if target:
                        assert len(data)==5 and data[0]==0xE9
                        assert va+5+struct.unpack_from('<i',data,1)[0]==int(target,16)
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
        known = set()
        for chunk in chunks:
            lo = int(chunk.get('va',chunk.get('start_va')),16)
            data = disk(lo,chunk['size'])
            decoded = list(decoder.disasm(data,lo))
            assert sum(x.size for x in decoded)==len(data),(row.get('va',row.get('seed_va')),hex(lo))
            known.update(x.address for x in decoded)
        for ins in row.get('assembly',[]):
            if isinstance(ins,dict) and ins.get('is_code',True):
                va = int(ins.get('va',ins.get('site_va')),16)
                assert va in known,(row.get('va'),ins)
                heads.add(va)
        for chunk in row.get('declared_chunks',[]):
            lo,hi = int(chunk['start_va'],16),int(chunk['end_va'],16)
            assert any(int(c.get('va',c.get('start_va')),16)==lo and c['size']==hi-lo for c in chunks)
        return bool(chunks)

    for name in ['bounded_raw.json','formal_functions.json','reused_6AAD70_current.json']:
        raw = json.loads((HERE/name).read_bytes())
        assert raw['disk_sha256']==EXPECTED
        scan(raw)
        for row in raw['functions']:
            assert declared(row)
    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    raw = json.loads(raw_bytes)
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    assert formal['source_sha256']==hashlib.sha256(raw_bytes).hexdigest()
    for row in formal['functions']:
        old = pointer(raw,row['source']['json_pointer'])
        assert row['source']['sha256']==formal['source_sha256']
        assert row['va']==old['seed_va'] and row['end_va']==old['end_va']
        assert row['pseudocode']==old['pseudocode']
        assert row['assembly']==[dict(va=i['site_va'],text=i['text'],is_code=i['is_code']) for i in old['assembly']]
        assert row['chunk_byte_ranges']==[dict(va=c['start_va'],**{k:v for k,v in c.items() if k!='start_va'}) for c in old['chunk_byte_ranges']]
    reused = json.loads((HERE/'reused_raw.json').read_bytes())
    weak = []
    for record in reused['records']:
        ref = record['source']
        source_bytes = (HERE/ref['path']).read_bytes()
        assert hashlib.sha256(source_bytes).hexdigest()==ref['sha256']
        old = record['original_record']
        assert pointer(json.loads(source_bytes),ref['pointer'])==old
        scan(old)
        if old.get('chunk_byte_ranges') or old.get('byte_ranges'):
            assert declared(old)
        elif old.get('bytes') and old.get('address'):
            # 此旧根getter只有主范围bytes；异常尾仍仅来源导航，不补造尾块。
            data = bytes.fromhex(old['bytes'])
            assert disk(int(old['address'],16),len(data))==data
            assert sum(x.size for x in decoder.disasm(data,int(old['address'],16)))==len(data)
        elif old.get('assembly') and all(isinstance(i,dict) and i.get('bytes') for i in old['assembly']):
            for ins in old['assembly']:
                data = bytes.fromhex(ins['bytes'])
                assert disk(int(ins['va'],16),len(data))==data
                decoded = list(decoder.disasm(data,int(ins['va'],16)))
                assert len(decoded)==1 and decoded[0].size==len(data)
        else:
            weak.append(record['va'])
    assert weak==['0x6aad70'],weak
    review = json.loads((HERE.parent/'function_review.json').read_bytes())
    for row in review['functions']+review['reused_reviews']:
        assert row['unknown'] and row['anchors']
        for ref in row['source_records']:
            payload = (HERE.parent/ref['path']).read_bytes()
            assert hashlib.sha256(payload).hexdigest()==ref['sha256']
            original = pointer(json.loads(payload),ref['pointer'])
            assert original['va']==row['va']
            assert original.get('declared_chunks',[])==row['declared_chunks']
            assert original.get('chunk_byte_ranges',original.get('byte_ranges',[]))==row['original_byte_ranges']
        for anchor in row['anchors']:
            assert pointer(json.loads((HERE.parent/anchor['path']).read_bytes()),anchor['pointer'])==anchor['value']
            assert int(anchor['site_va'],16) in heads
    docs = list(HERE.parent.glob('*.txt'))
    assert all(not line.strip() or line.startswith('//') for p in docs for line in p.read_text(encoding='utf-8').splitlines())
    fresh_bytes = sum(c['size'] for row in formal['functions'] for c in row['chunk_byte_ranges'])
    result = dict(status='PASS',disk_sha256=EXPECTED,fresh_functions=5,fresh_declared_bytes=fresh_bytes,
          fresh_instruction_entries=sum(len(x['assembly']) for x in formal['functions']),
          reused_subject_reviews=3,reused_records=len(reused['records']),
          unique_saved_ranges=len(ranges),unique_verified_e9_bridges=len(bridges),
          instruction_heads=len(heads),weak_original_navigation=weak,
          current_supplement='6AAD70完整当前块补证；新增入口0',
          documents={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in docs},
          limitation='静态局部审阅；旧627450只核主范围bytes，异常尾仅导航；旧6AAD70无VA文本由当前补证承担字节核验。')
    (HERE/'author_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    print(json.dumps(validate(),ensure_ascii=True))
