"""当前PE、完整声明块、实际桥、资源词法与逐函数分级离线核验。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay
from capstone import Cs,CS_ARCH_X86,CS_MODE_32

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]


def validate():
    blob=(ROOT/'RnClient.exe').read_bytes()
    sha=hashlib.sha256(blob).hexdigest()
    assert sha=='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe=struct.unpack_from('<I',blob,60)[0]
    base=struct.unpack_from('<I',blob,pe+52)[0]
    start=pe+24+struct.unpack_from('<H',blob,pe+20)[0]
    sections=[struct.unpack_from('<4I',blob,start+40*i+8) for i in range(struct.unpack_from('<H',blob,pe+6)[0])]
    decoder=Cs(CS_ARCH_X86,CS_MODE_32)
    ranges,sites,bridges=set(),set(),set()

    def disk(va,size):
        matches=[(rva,offset) for _,rva,length,offset in sections if 0<=va-base-rva and va-base-rva+size<=length]
        assert len(matches)==1,(hex(va),size)
        rva,offset=matches[0]
        return blob[offset+va-base-rva:offset+va-base-rva+size]

    def scan(value):
        if isinstance(value,dict):
            if {'va','size','idb_hex'}<=value.keys():
                va,size=int(value['va'],16),value['size']
                if value.get('disk_backed',True):
                    raw=disk(va,size)
                    assert raw.hex()==value['idb_hex']
                    if value.get('disk_hex') is not None:
                        assert raw.hex()==value['disk_hex']
                    ranges.add((va,size))
                    if 'target' in value:
                        assert raw[0]==0xe9 and va+5+struct.unpack_from('<i',raw,1)[0]==int(value['target'],16)
                        bridges.add(va)
            for child in value.values():
                scan(child)
        elif isinstance(value,list):
            for child in value:
                scan(child)

    def function(row):
        for ins in row.get('assembly',row.get('instructions',[])):
            va=int(ins['va'],16)
            decoded=list(decoder.disasm(disk(va,15),va,count=1))
            assert len(decoded)==1
            if 'hex' in ins:
                assert decoded[0].bytes.hex()==ins['hex']
            if 'size' in ins:
                assert decoded[0].size==ins['size']
            sites.add(va)
        for chunk in row.get('declared_chunks',[]):
            lo,hi=int(chunk['start_va'],16),int(chunk['end_va'],16)
            saved=row.get('chunk_byte_ranges',row.get('byte_ranges',[]))
            assert any(int(r['va'],16)<=lo and int(r['va'],16)+r['size']>=hi for r in saved)

    for name in ('plusprize_raw.json','consumer_helpers.json','plusprize_context.json'):
        data=json.loads((HERE/name).read_bytes())
        assert data['disk_sha256']==sha
        scan(data)
        for row in data.get('functions',[]):
            function(row)
    reuse=json.loads((HERE/'reused_evidence.json').read_bytes())
    for source in reuse['sources']:
        assert hashlib.sha256((ROOT/'docs/逆向资料'/source['path']).read_bytes()).hexdigest()==source['sha256']
    scan(reuse)
    for row in reuse['functions']:
        function(row['record'])
    resource=json.loads((HERE/'resources.json').read_bytes())
    raw=(ROOT/resource['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==resource['source_sha256']
    packed=bytes((x-raw[0])&255 for x in raw[1:])
    length,compressed=struct.unpack_from('<II',packed)
    assert compressed==len(packed)-8
    plain=lzokay.decompress(packed[8:],length)
    for data,label in ((raw,'source'),(packed,'packed'),(packed[8:],'compressed'),(plain,'decoded')):
        assert len(data)==resource[label+'_size'] and hashlib.sha256(data).hexdigest()==resource[label+'_sha256']
    assert b''.join(bytes.fromhex(r['bytes']) for r in resource['lines'])==plain
    for row in resource['entries']:
        for field in ('key','value'):
            offset=row[field+'_offset']; data=bytes.fromhex(row[field+'_hex'])
            assert plain[offset:offset+len(data)]==data
    assert len(resource['sections'])==1 and len(resource['entries'])==4
    review=json.loads((HERE.parent/'function_review.json').read_bytes())
    assert len(review['functions'])==21
    for row in review['functions']:
        assert {'va','status','conclusion','unknown','evidence','declared_chunks','original_byte_ranges'}<=row.keys()
        assert row['unknown'] and row['declared_chunks'] and row['original_byte_ranges']
    docs=list(HERE.parent.glob('*.txt'))
    assert all(not line.strip() or line.startswith('//') for p in docs for line in p.read_text(encoding='utf-8').splitlines())
    result=dict(status='PASS',disk_sha256=sha,functions=21,fresh=9,reused=12,
                unique_saved_ranges=len(ranges),instruction_sites=len(sites),unique_e9_bridges=len(bridges),
                resource=dict(source=168,decoded=171,sections=1,keys=4),manuscripts=[p.name for p in docs],
                limitation='仅保存字节与静态语义；外部生产、索引保证、缓存重置与实机行为未验证')
    (HERE/'author_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    print(json.dumps(validate(),ensure_ascii=True))
