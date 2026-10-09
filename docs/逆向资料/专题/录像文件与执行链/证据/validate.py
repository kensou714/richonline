"""独立从当前PE核验全部声明块，且重新解码资源与扫描现存样本。"""
import hashlib,json,re,struct
from collections import Counter
from pathlib import Path
import lzokay
ROOT=Path(r'F:\大富翁online\Richonline');HERE=Path(__file__).resolve().parent;TOP=HERE.parent
EXPECTED='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
blob=(ROOT/'RnClient.exe').read_bytes();assert hashlib.sha256(blob).hexdigest()==EXPECTED
pe=struct.unpack_from('<I',blob,60)[0];count=struct.unpack_from('<H',blob,pe+6)[0]
opt=struct.unpack_from('<H',blob,pe+20)[0];base=struct.unpack_from('<I',blob,pe+52)[0]
sections=[struct.unpack_from('<IIII',blob,pe+24+opt+40*i+8) for i in range(count)]
def disk(va,size):
    for _,rva,raw,offset in sections:
        delta=va-base-rva
        if 0<=delta and delta+size<=raw:return blob[offset+delta:offset+delta+size]
    raise AssertionError(('未映射字节',hex(va),size))
compares=0
def check(row,key='idb_hex',va_key='va'):
    global compares
    expected=bytes.fromhex(row[key]);size=row.get('size',len(expected))
    assert len(expected)==size,row
    assert disk(int(row[va_key],16),size)==expected,(row[va_key],key)
    if 'disk_hex' in row:assert bytes.fromhex(row['disk_hex'])==expected,row['va']
    if 'matching' in row:assert row['matching'] is True,row['va']
    compares+=1
groups=['startup_and_navigation.json','io_and_parser_navigation.json','controls_and_flow_navigation.json',
        'controls_and_queue_navigation.json','queue_and_ui_gate.json','replay_state_stubs.json','digest_helper.json']
functions={};thunks={};chunks=set();instructions=set()
for name in groups:
    group=json.loads((HERE/name).read_text(encoding='utf-8'));assert group['disk_sha256']==EXPECTED
    for f in group['functions']:
        declared={(int(c['start_va'],16),int(c['end_va'],16)) for c in f['declared_chunks']}
        complete={(int(c['va'],16),int(c['va'],16)+c['size']) for c in f['chunk_byte_ranges']}
        assert declared==complete,(name,f['va'],'声明块必须完整保存')
        assert all(end>start for start,end in declared)
        for r in f['byte_ranges']+f['chunk_byte_ranges']:check(r)
        for r in f['byte_ranges']:
            a=int(r['va'],16);assert any(s<=a and a+r['size']<=e for s,e in declared)
        for ins in f['assembly']:
            a=int(ins['va'],16);assert any(s<=a<e for s,e in declared)
            assert any(int(r['va'],16)<=a<int(r['va'],16)+r['size'] for r in f['byte_ranges'])
            instructions.add(a)
        if f['va'] in functions:assert functions[f['va']]['chunk_byte_ranges']==f['chunk_byte_ranges']
        functions[f['va']]=f;chunks.update((f['va'],s,e) for s,e in declared)
    for t in group['thunks']:
        check(t);raw=bytes.fromhex(t['idb_hex']);assert raw[0]==0xE9
        assert int(t['va'],16)+5+int.from_bytes(raw[1:],'little',signed=True)==int(t['target'],16)
        if t['va'] in thunks:assert thunks[t['va']]==t
        thunks[t['va']]=t
unbacked=[]
for name in ('control_data_navigation.json','state_and_switch_data.json','file_path_constants.json'):
    for row in json.loads((HERE/name).read_text(encoding='utf-8')):
        # A7C730位于无文件后备的虚拟范围；IDB的FFFF不得伪称当前磁盘原值。
        if name=='control_data_navigation.json' and row['va']=='0xa7c730':
            assert row['size']==20
            assert not any(0<=int(row['va'],16)-base-rva and int(row['va'],16)-base-rva+20<=raw for _,rva,raw,_ in sections)
            unbacked.append(dict(source=name,va=row['va'],size=row['size'],reason='无PE文件后备，IDB状态仅导航，正文不依赖。'))
        else:check(row)
windows=json.loads((HERE/'undeclared_io_windows.json').read_text(encoding='utf-8'))
for row in windows:
    assert len(bytes.fromhex(row['idb_hex']))==int(row['end_va'],16)-int(row['start_va'],16)
    check(row,va_key='start_va')
tables=json.loads((HERE/'binary_tables.json').read_text(encoding='utf-8'))
assert tables['disk_sha256']==EXPECTED
for row in tables['raw_ranges']:check(row,key='disk_hex')
assert disk(0x7062B0,3)==bytes.fromhex('ff2485');jump=int.from_bytes(disk(0x7062B3,4),'little')
for row in tables['switch_rows']:
    idx=disk(0x706E82+row['command']-90,1)[0];assert row['index']==idx
    assert int(row['target'],16)==int.from_bytes(disk(jump+4*idx,4),'little')
assert all(row['target']=='0x706c80' for row in tables['switch_rows'] if row['command'] in (150,151,160,161))
state=int.from_bytes(disk(0x624D96,4),'little')
for row in tables['state_table_window']:
    pointer=int.from_bytes(disk(state+4*row['index'],4),'little');assert pointer==int(row['pointer'],16)
    if row['resolved'] is not None:
        raw=disk(pointer,5);dest=pointer+5+int.from_bytes(raw[1:],'little',signed=True) if raw[0]==0xE9 else pointer
        assert dest==int(row['resolved'],16)
assert tables['digest_helper_bridge']['target']=='0x81b980'
for va in ('0x6258f0','0x625900'):assert disk(int(va,16),10).hex()=='558becb8010000005dc3'
review=json.loads((TOP/'function_review.json').read_text(encoding='utf-8'))
assert {r['va'] for r in review['functions']}==set(functions)
for r in review['functions']:
    assert r['declared_chunks']==functions[r['va']]['declared_chunks']
    assert r['status']==r['level'] and r['conclusion']==r['summary'] and r['evidence']==r['sources']
    assert r['unknown'] and r['full_dependency_closure'] is False
for name,sha in review['script_sha256'].items():assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==sha
raw=(ROOT/'Data/RichStr.kpd').read_bytes();evidence=json.loads((HERE/'recording_texts.json').read_text(encoding='utf-8'))
assert hashlib.sha256(raw).hexdigest()==evidence['source_sha256']
packed=bytes((x-raw[0])&255 for x in raw[1:]);size,compressed=struct.unpack_from('<II',packed)
assert compressed==len(packed)-8;plain=lzokay.decompress(packed[8:],size)
assert len(plain)==size and hashlib.sha256(plain).hexdigest()==evidence['decoded_sha256']
text=plain.decode('cp950','strict');assert text.encode('cp950')==plain
wanted={r['id'] for r in evidence['entries']};entries=[]
for block in text.split('[ITEM]')[1:]:
    match=re.search(r'^\s*indx\s*=\s*(\d+)',block,re.M)
    if match and int(match[1]) in wanted:entries.append(dict(id=int(match[1]),lines=[s for s in block.splitlines() if '=' in s and not s.lstrip().startswith('//')]))
assert entries==evidence['entries']
samples=[]
for p in ROOT.rglob('*'):
    if p.is_file() and p.suffix.casefold()=='.rcd':
        b=p.read_bytes();samples.append(dict(path=str(p.relative_to(ROOT)),size=len(b),sha256=hashlib.sha256(b).hexdigest(),first64=b[:64].hex()))
saved=json.loads((HERE/'sample_inventory.json').read_text(encoding='utf-8'))
assert sorted(samples,key=lambda x:x['path'])==sorted(saved['samples'],key=lambda x:x['path'])
docs=list(TOP.glob('*.txt'))
for p in docs:
    for i,line in enumerate(p.read_text(encoding='utf-8-sig').splitlines(),1):assert not line.strip() or line.startswith('//'),(p.name,i)
result=dict(exe_sha256=EXPECTED,unique_functions=len(functions),declared_chunks=len(chunks),
            instruction_addresses=len(instructions),unique_thunks=len(thunks),byte_comparisons=compares,
            raw_windows=len(windows),unbacked_idb_ranges=unbacked,resource_entries=len(entries),rcd_samples=len(samples),comment_style_docs=len(docs),
            manual_levels=dict(Counter(r['level'] for r in review['functions'])),mismatches=0,
            boundary='本验证只证明原证与当前文件一致及清单覆盖；不证明未分析函数语义或动态可达性。')
(TOP/'验证结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
