"""作者离线校验：字段无损、PE字节、声明块、桥链与语义锚；不采IDA。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
DOCS=ROOT/'docs/逆向资料'
SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def pointer(value,path):
    for key in path.strip('/').split('/'):
        key=key.replace('~1','/').replace('~0','~')
        value=value[int(key)] if isinstance(value,list) else value[key]
    return value


def main():
    blob=(ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest()==SHA
    pe=struct.unpack_from('<I',blob,60)[0]
    assert blob[pe:pe+4]==b'PE\0\0'
    base=struct.unpack_from('<I',blob,pe+52)[0]
    at=pe+24+struct.unpack_from('<H',blob,pe+20)[0]
    sections=[struct.unpack_from('<4I',blob,at+40*i+8) for i in range(struct.unpack_from('<H',blob,pe+6)[0])]
    decoder=Cs(CS_ARCH_X86,CS_MODE_32)
    transcript,maps,sources,hashes=[],{},{},{}
    count=dict(byte_records=0,owner_items=0)
    def disk(va,size):
        matches=[(rva,off) for _,rva,raw,off in sections if base+rva<=va and va+size<=base+rva+raw]
        assert len(matches)==1,(hex(va),size)
        rva,off=matches[0]
        return blob[off+va-base-rva:off+va-base-rva+size]
    def audit(row,va=None):
        if va is None:
            va=int(row.get('start_va',row.get('va')),16)
        raw=disk(va,row['size'])
        assert raw.hex()==row['disk_hex'].lower()
        if 'idb_hex' in row: assert raw.hex()==row['idb_hex'].lower()
        assert row.get('matching',row.get('equal',True)) is True
        if 'sha256' in row: assert hashlib.sha256(raw).hexdigest()==row['sha256']
        count['byte_records']+=1
        return raw
    def load(filename):
        raw=(HERE/filename).read_bytes()
        hashes[filename]=hashlib.sha256(raw).hexdigest()
        value=json.loads(raw)
        assert value['disk_sha256']==SHA
        sources[filename]=value
        return value
    bounded=load('bounded_raw.json')
    for filename in ['formal_functions.json','reused_functions.json','formal_dependencies.json']:
        data=load(filename)
        for row in data['functions']:
            raw=(DOCS/row['source_path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==row['source_sha256']
            original=pointer(json.loads(raw),row['source_pointer'])
            for key,value in original.items():
                assert row[key]==value and pointer(json.loads(raw),row['source_field_pointers'][key])==value
            original_chunks=original.get('chunk_byte_ranges',original.get('chunks',original.get('byte_ranges')))
            expected_chunks=[dict(start_va=item.get('start_va',item.get('va',item.get('address'))),
                                  **{key:value for key,value in item.items() if key not in ('start_va','va','address')})
                             for item in original_chunks]
            assert row['normalized_chunks']==expected_chunks
            expected_assembly=[dict(site_va=item.get('site_va',item.get('va',item.get('address'))),
                                    text=item['text'],is_code=item.get('is_code',True),original=item)
                               for item in original.get('assembly',original.get('instructions'))]
            assert row['normalized_assembly']==expected_assembly
            decoded={}
            transcript.append('// '+row['va']+' / '+row['adaptation_scope'])
            for chunk in row['normalized_chunks']:
                raw=audit(chunk)
                start=int(chunk['start_va'],16)
                end=start+chunk['size']
                items=[item for item in row['normalized_assembly'] if start<=int(item['site_va'],16)<end]
                assert items and int(items[0]['site_va'],16)==start
                for index,item in enumerate(items):
                    va=int(item['site_va'],16)
                    stop=int(items[index+1]['site_va'],16) if index+1<len(items) else end
                    payload=disk(va,stop-va)
                    if item['is_code']:
                        ins=list(decoder.disasm(payload,va))
                        assert len(ins)==1 and ins[0].size==len(payload),(hex(va),stop)
                        text=ins[0].mnemonic+' '+ins[0].op_str
                        decoded[va]=text
                        original_ins=item['original']
                        if 'hex' in original_ins: assert original_ins['hex']==payload.hex()
                        if 'size' in original_ins: assert original_ins['size']==len(payload)
                    else: text='静态数据 '+payload.hex()
                    transcript.append('// '+hex(va)+' '+text)
            assert {item['start_va'] for item in row['declared_chunks']}=={item['start_va'] for item in row['normalized_chunks']}
            for declared,chunk in zip(row['declared_chunks'],row['normalized_chunks']):
                assert declared['start_va']==chunk['start_va']
                assert int(declared['end_va'],16)==int(chunk['start_va'],16)+chunk['size']
            maps[int(row['va'],16)]=decoded
    bridges={}
    for row in bounded['verified_direct_bridges']:
        raw=audit(row)
        va=int(row['start_va'],16)
        assert row['size']==5 and raw[0]==0xe9
        target=va+5+struct.unpack_from('<i',raw,1)[0]
        assert target==int(row['target_va'],16)
        bridges[va]=target
    for row in bounded['calls']:
        va=int(row['site_va'],16)
        ins=next(decoder.disasm(disk(va,16),va,count=1))
        target=int(row['target_va'],16)
        if ins.bytes[:2]==b'\xff\x15': assert struct.unpack_from('<I',ins.bytes,2)[0]==target
        else: assert ins.bytes[0] in (0xe8,0xe9) and va+5+struct.unpack_from('<i',ins.bytes,1)[0]==target
        for bridge in row['bridges']:
            assert target==int(bridge,16)
            target=bridges[target]
        assert target==int(row['implementation_va'],16)
    for row in bounded['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']: audit(chunk)
    windows=bounded['explicit_owner_windows']+[edge['owner_window'] for rows in bounded['incoming'].values() for edge in rows if 'owner_window' in edge]
    for window in windows:
        if window['owner_va'] is None:
            assert not window['assembly']
            continue
        transcript.append('// 局部窗口 owner='+window['owner_va']+' site='+window['site_va'])
        previous=None
        for item in window['assembly']:
            va=int(item['site_va'],16)
            raw=audit(item['bytes'],va)
            assert previous is None or previous==va
            previous=va+len(raw)
            if item['is_code']:
                ins=list(decoder.disasm(raw,va));assert len(ins)==1 and ins[0].size==len(raw)
                text=ins[0].mnemonic+' '+ins[0].op_str
            else: text='静态数据 '+raw.hex()
            transcript.append('// '+hex(va)+' '+text)
            count['owner_items']+=1
    for row in bounded['data_windows']: audit(row)
    for row in bounded['strings']:
        raw=audit(row['byte_audit']);width=row['unit_width'];payload=bytes.fromhex(row['payload_hex'])
        assert width in (1,2) and raw==payload+bytes(width) and bytes.fromhex(row['nul_hex'])==bytes(width)
        assert all(payload[i:i+width]!=bytes(width) for i in range(0,len(payload),width))
    for row in bounded['reuse_sources']:
        assert hashlib.sha256((DOCS/row['path']).read_bytes()).hexdigest()==row['source_sha256']
    (HERE/'review_assembly.txt').write_text('\n'.join(transcript)+'\n','utf-8')
    status='EVIDENCE_ONLY';anchors=0
    ledger_path=HERE.parent/'函数审阅清单.json'
    if ledger_path.exists():
        ledger=json.loads(ledger_path.read_text('utf-8'));assert ledger['disk_sha256']==SHA
        assert len(ledger['functions'])==len({row['va'] for row in ledger['functions']})
        for row in ledger['functions']:
            assert row['status'] and row['conclusion'] and row['unknown']
            for ref in row['evidence_refs']:
                source=pointer(sources[ref['file']],ref['pointer']);assert source['va']==row['va']
                assert row['declared_chunks']==source['declared_chunks']
                assert row['instruction_count']==sum(item['is_code'] for item in source['normalized_assembly'])
            for anchor in row['semantic_anchors']:
                text=maps[int(row['va'],16)][int(anchor['va'],16)]
                assert all(token in text for token in anchor['tokens']),(row['va'],anchor,text)
                anchors+=1
        assert len(ledger['owner_windows'])==len(bounded['explicit_owner_windows'])
        for row in ledger['owner_windows']:
            ref=row['evidence_ref'];source=pointer(sources[ref['file']],ref['pointer'])
            assert row['owner_va']==source['owner_va'] and row['site_va']==source['site_va']
            assembly=source['assembly'];last=assembly[-1]
            assert row['start_va']==assembly[0]['site_va']
            assert int(row['end_va'],16)==int(last['site_va'],16)+last['bytes']['size']
            assert row['status']=='局部窗口分析' and row['conclusion'] and row['unknown']
        historical=sources['reused_functions.json']['functions'][1:]
        assert len(ledger['historical_contracts'])==len(historical)
        for row,source in zip(ledger['historical_contracts'],historical):
            for key in ('va','source_path','source_pointer','source_sha256'):
                assert row[key]==source[key]
            assert row['instruction_count']==sum(item['is_code'] for item in source['normalized_assembly'])
        summary=ledger['summary']
        assert summary==dict(reviewed_functions=len(ledger['functions']),
                             complete=sum(row['status']=='完整分析' for row in ledger['functions']),
                             partial=sum(row['status']=='部分分析' for row in ledger['functions']),
                             owner_windows=len(ledger['owner_windows']),historical_contracts=len(historical),
                             historical_contract_instructions=sum(row['instruction_count'] for row in ledger['historical_contracts']))
        status='PASS'
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result=dict(status=status,disk_sha256=SHA,source_sha256=hashes,**count,functions=len(maps),
                decoded_instructions=sum(len(items) for items in maps.values()),semantic_anchors=anchors,
                boundary='作者离线核验；历史契约完整字节核验不等于本批新增完整语义审阅。')
    (HERE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps({key:value for key,value in result.items() if key!='source_sha256'},ensure_ascii=True))


if __name__=='__main__':
    main()
