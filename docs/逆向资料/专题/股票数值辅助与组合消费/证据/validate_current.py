"""离线核当前PE、来源无损适配、完整声明块、桥、调用与有限窗口。"""
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
    blob=(ROOT/'RnClient.exe').read_bytes();assert hashlib.sha256(blob).hexdigest()==SHA
    pe=struct.unpack_from('<I',blob,60)[0];base=struct.unpack_from('<I',blob,pe+52)[0]
    at=pe+24+struct.unpack_from('<H',blob,pe+20)[0]
    sections=[struct.unpack_from('<4I',blob,at+40*i+8) for i in range(struct.unpack_from('<H',blob,pe+6)[0])]
    decoder=Cs(CS_ARCH_X86,CS_MODE_32);sources={};hashes={};maps={};transcript=[]
    counts=dict(byte_records=0,owner_items=0)
    def disk(va,size):
        matches=[(rva,off) for _,rva,length,off in sections if base+rva<=va and va+size<=base+rva+length]
        assert len(matches)==1,(hex(va),size)
        rva,off=matches[0];return blob[off+va-base-rva:off+va-base-rva+size]
    def audit(row,va=None):
        va=int(row.get('start_va',row.get('va')),16) if va is None else va
        raw=disk(va,row['size']);assert raw.hex()==row['disk_hex'].lower()
        for key in ('idb_hex','ida_hex'):
            if key in row: assert raw.hex()==row[key].lower()
        assert row.get('matching',row.get('equal',True)) is True
        if 'sha256' in row: assert hashlib.sha256(raw).hexdigest()==row['sha256']
        counts['byte_records']+=1;return raw
    def load(name):
        raw=(HERE/name).read_bytes();hashes[name]=hashlib.sha256(raw).hexdigest()
        data=json.loads(raw);assert data['disk_sha256'].lower()==SHA
        sources[name]=data;return data
    bounded=load('bounded_raw.json');assert hashes['bounded_raw.json']=='f3eaa46e1dbb7b7549a9c0779e65387ce4fee25a93a1baddc238ec44c0aa4c04'
    expected_seeds=['0x6c1c80','0x6c1d00','0x6c1d80','0x6c08b0','0x6c0960','0x6c0bf0','0x6c0ce0']
    assert [row['seed_va'] for row in bounded['seeds']]==expected_seeds
    assert [row['seed_va'] for row in bounded['functions']]==expected_seeds and not bounded['reused_seeds']
    assert [row['seed_va'] for row in bounded['current_chunk_audits']]==expected_seeds
    names=['formal_functions.json','reused_functions.json']
    if (HERE/'formal_dependencies.json').exists(): names.append('formal_dependencies.json')
    for name in names:
        for row in load(name)['functions']:
            raw=(DOCS/row['source_path']).read_bytes();assert hashlib.sha256(raw).hexdigest()==row['source_sha256']
            document=json.loads(raw);original=pointer(document,row['source_pointer'])
            for key,value in original.items(): assert row[key]==value and pointer(document,row['source_field_pointers'][key])==value
            chunks=original.get('chunk_byte_ranges',original.get('chunks',original.get('byte_ranges')))
            expected=[dict(start_va=item.get('start_va',item.get('va',item.get('address'))),**{k:v for k,v in item.items() if k not in ('start_va','va','address')}) for item in chunks]
            assert row['normalized_chunks']==expected
            expected=[dict(site_va=item.get('site_va',item.get('va',item.get('address'))),text=item['text'],is_code=item.get('is_code',True),original=item) for item in original.get('assembly',original.get('instructions'))]
            assert row['normalized_assembly']==expected
            decoded={};transcript.append('// '+row['va']+' / '+row['adaptation_scope'])
            assert len(row['declared_chunks'])==len(row['normalized_chunks'])
            for declared,chunk in zip(row['declared_chunks'],row['normalized_chunks']):
                start=int(chunk['start_va'],16);end=start+chunk['size'];audit(chunk)
                assert declared['start_va']==chunk['start_va'] and int(declared['end_va'],16)==end
                items=[x for x in row['normalized_assembly'] if start<=int(x['site_va'],16)<end]
                assert items and int(items[0]['site_va'],16)==start
                for i,item in enumerate(items):
                    va=int(item['site_va'],16);stop=int(items[i+1]['site_va'],16) if i+1<len(items) else end;payload=disk(va,stop-va)
                    if item['is_code']:
                        ins=list(decoder.disasm(payload,va));assert len(ins)==1 and ins[0].size==len(payload)
                        text=ins[0].mnemonic+' '+ins[0].op_str;decoded[va]=text
                    else: text='静态数据 '+payload.hex()
                    transcript.append('// '+hex(va)+' '+text)
            maps[int(row['va'],16)]=decoded
    assert [row['va'] for row in sources['formal_functions.json']['functions']]==expected_seeds
    for row in sources['reused_functions.json']['functions']:
        for call in row.get('calls',[]):
            site=int(call.get('site_va',call.get('site')),16);target=int(call.get('target_va',call.get('target')),16)
            raw=disk(site,6)
            if raw[:2]==b'\xff\x15': assert struct.unpack_from('<I',raw,2)[0]==target
            else: assert raw[0] in (0xe8,0xe9) and site+5+struct.unpack_from('<i',raw,1)[0]==target
            for bridge in call.get('bridges',call.get('thunks',[])):
                assert target==int(bridge,16);raw=disk(target,5);assert raw[0]==0xe9
                target+=5+struct.unpack_from('<i',raw,1)[0]
            assert target==int(call.get('implementation_va',call.get('implementation')),16)
    helper=DOCS/'专题/地图选择字段与列表消费/证据/adapt_sources.py'
    assert sources['formal_functions.json']['adapter_helper_sha256']==hashlib.sha256(helper.read_bytes()).hexdigest()
    bridges={}
    for row in bounded['verified_direct_bridges']:
        raw=audit(row);va=int(row['start_va'],16);assert len(raw)==5 and raw[0]==0xe9
        target=va+5+struct.unpack_from('<i',raw,1)[0];assert target==int(row['target_va'],16);bridges[va]=target
    for row in bounded['calls']:
        va=int(row['site_va'],16);ins=next(decoder.disasm(disk(va,16),va,count=1));target=int(row['target_va'],16)
        if ins.bytes[:2]==b'\xff\x15': assert struct.unpack_from('<I',ins.bytes,2)[0]==target
        else: assert ins.bytes[0] in (0xe8,0xe9) and va+5+struct.unpack_from('<i',ins.bytes,1)[0]==target
        for bridge in row['bridges']: assert target==int(bridge,16);target=bridges[target]
        assert target==int(row['implementation_va'],16)
    for row in bounded['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']: audit(chunk)
    windows=bounded['explicit_owner_windows']+[edge['owner_window'] for rows in bounded['incoming'].values() for edge in rows if 'owner_window' in edge]
    for row in windows:
        if row['owner_va'] is None: assert not row['assembly'];continue
        previous=None;transcript.append('// 窗口owner='+row['owner_va']+' site='+row['site_va'])
        for item in row['assembly']:
            va=int(item['site_va'],16);raw=audit(item['bytes'],va);assert previous is None or previous==va;previous=va+len(raw)
            if item['is_code']:
                ins=list(decoder.disasm(raw,va));assert len(ins)==1 and ins[0].size==len(raw);text=ins[0].mnemonic+' '+ins[0].op_str
            else: text='静态数据 '+raw.hex()
            transcript.append('// '+hex(va)+' '+text);counts['owner_items']+=1
    for row in bounded['strings']:
        raw=audit(row['byte_audit']);width=row['unit_width'];payload=bytes.fromhex(row['payload_hex'])
        assert width in (1,2) and raw==payload+bytes(width) and bytes.fromhex(row['nul_hex'])==bytes(width)
        assert all(payload[i:i+width]!=bytes(width) for i in range(0,len(payload),width))
    for row in bounded['data_windows']: audit(row)
    for row in bounded['reuse_sources']: assert hashlib.sha256((DOCS/row['path']).read_bytes()).hexdigest()==row['source_sha256']
    (HERE/'review_assembly.txt').write_text('\n'.join(transcript)+'\n','utf-8')
    status='EVIDENCE_ONLY';anchors=0;ledger_path=HERE.parent/'函数审阅清单.json'
    if ledger_path.exists():
        ledger=json.loads(ledger_path.read_text('utf-8'));assert ledger['disk_sha256']==SHA
        assert len(ledger['functions'])==len({row['va'] for row in ledger['functions']})==7
        for row in ledger['functions']:
            assert row['status'] and row['conclusion'] and row['unknown']
            for ref in row['evidence_refs']:
                source=pointer(sources[ref['file']],ref['pointer']);assert source['va']==row['va']
                assert row['declared_chunks']==source['declared_chunks']
                assert row['instruction_count']==sum(x['is_code'] for x in source['normalized_assembly'])
            for anchor in row['semantic_anchors']:
                text=maps[int(row['va'],16)][int(anchor['va'],16)];assert all(token in text for token in anchor['tokens']);anchors+=1
        for row in ledger['historical_contracts']:
            ref=row['evidence_ref'];source=pointer(sources[ref['file']],ref['pointer'])
            assert row['va']==source['va'] and row['source_sha256']==source['source_sha256']
            assert row['instruction_count']==sum(x['is_code'] for x in source['normalized_assembly'])
            for anchor in row['semantic_anchors']:
                text=maps[int(row['va'],16)][int(anchor['va'],16)];assert all(token in text for token in anchor['tokens']);anchors+=1
        assert len(ledger['owner_windows'])==len(bounded['explicit_owner_windows'])==3
        for row in ledger['owner_windows']:
            ref=row['evidence_ref'];source=pointer(sources[ref['file']],ref['pointer']);assembly=source['assembly'];last=assembly[-1]
            assert row['owner_va']==source['owner_va'] and row['site_va']==source['site_va']
            assert row['start_va']==assembly[0]['site_va'] and int(row['end_va'],16)==int(last['site_va'],16)+last['bytes']['size']
            assert row['status']=='局部窗口分析' and row['unknown']
        summary=ledger['summary'];assert summary['reviewed_functions']==7 and summary['complete']==7 and summary['partial']==0
        assert summary['reviewed_instructions']==sum(x['instruction_count'] for x in ledger['functions'])==366
        assert summary['historical_contracts']==len(ledger['historical_contracts'])==2
        assert summary['historical_contract_instructions']==sum(x['instruction_count'] for x in ledger['historical_contracts'])==76
        assert summary['owner_windows']==3 and summary['direct_bridges']==len(bounded['verified_direct_bridges'])==10
        status='PASS'
    for path in HERE.parent.glob('*.txt'): assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result=dict(status=status,disk_sha256=SHA,source_sha256=hashes,**counts,functions=len(maps),decoded_instructions=sum(len(x) for x in maps.values()),semantic_anchors=anchors,boundary='声明块机械核验不扩大语义认领；窗口不认领owner整函数。')
    (HERE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8');print(json.dumps({k:v for k,v in result.items() if k!='source_sha256'},ensure_ascii=True))


if __name__=='__main__': main()
