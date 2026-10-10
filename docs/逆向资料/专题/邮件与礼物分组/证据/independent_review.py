"""独审只读复验原证、有限规则与资源；audit(db)无写入副作用。"""
import hashlib
import importlib.util
import json
import struct
import sys
from collections import Counter
from itertools import product
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
PARTIAL = {0x69df50,0x69e600,0x6aebe0,0x6aef10,0x6af1e0,0x6af490,0x6af4d0,
           0x757640,0x759dd0,0x828f60,0x843bc0,0x91fbb0}


def read(name):
    return json.loads((HERE/name).read_text(encoding='utf-8-sig'))


def resources_check():
    import lzokay
    resource = read('resources.json')
    assert len(resource['records']) == 2
    counts = []
    for record in resource['records']:
        raw = (ROOT/record['source']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == record['source_sha256']
        if record['source'].endswith('.kpd'):
            expanded, packed = struct.unpack('<II',bytes((x-raw[0]) & 255 for x in raw[1:9]))
            assert packed == len(raw)-9
            plain = lzokay.decompress(bytes((x-raw[0]) & 255 for x in raw[9:]),expanded)
            assert len(plain) == expanded
        else:
            key = b'RichNet'
            plain = bytes((x-key[i%7]) & 255 for i,x in enumerate(raw))
        assert hashlib.sha256(plain).hexdigest() == record['decoded_sha256']
        text = plain.decode('gbk')
        assert text.encode('gbk') == plain and record['strict_roundtrip']
        lines = text.splitlines()
        for section in record['sections']:
            index = section['line']-1
            assert lines[index].strip() == '['+section['section']+']'
            assert lines[index:index+len(section['raw_lines'])] == section['raw_lines']
            fields = {}
            for line in section['raw_lines'][1:]:
                if '=' in line and not line.strip().startswith('//'):
                    key,value = line.split('=',1)
                    fields[key.strip().lower()] = value.strip()
            assert fields == section['fields']
        if record['source'].endswith('.kpd'):
            assert len(record['sections']) == 1
            fields = record['sections'][0]['fields']
            assert fields['indx'] == '108' and fields['file'] == 'L_MailSystem.ui'
        else:
            ids = {'2','3','4','1000','2000','3000','1001','3001'}
            ids |= {str(i+j) for i in range(1010,1121,10) for j in range(4)}
            ids |= {str(i+j) for i in range(3010,3121,10) for j in range(4)}
            assert Counter(s['fields']['id'] for s in record['sections']) == Counter(ids)
        counts.append(len(record['sections']))
    assert counts == [1,104]
    return counts


def model_check():
    spec = importlib.util.spec_from_file_location('mail_model_independent',TOPIC/'model.py')
    model = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = model
    spec.loader.exec_module(model)
    predicate = 0
    for third,fifth in product(range(256),repeat=2):
        code = bytes([0,255,0,third,255,fifth,0,255])
        assert model.special_encoding(model.Entry(1,encoding=code)) == (third==49 and fifth==50)
        predicate += 1
    assert not model.special_encoding(None)
    for code in [b'',b'1234567']:
        try:
            model.special_encoding(model.Entry(1,encoding=code))
        except ValueError:
            pass
        else:
            raise AssertionError('模型未拒绝短证据输入')
    types = [(-1,0,False,0),(1,2,False,0),(1,0,True,1),(1,0,False,0),
             (1,1,False,0),(1,0,False,1),(1,1,False,1),(0xffffffff,1,False,0),
             (1,0,False,0x80000000)]
    signed = lambda x: (x & 0xffffffff)-(0x100000000 if x & 0x80000000 else 0)
    cases = query_cases = threshold_cases = 0
    def make(rows):
        return [model.Entry(first,second=10+i,category=category,
                            encoding=b'aaa1a2aa' if special else b'abcdefgh',gift=gift)
                for i,(first,category,special,gift) in enumerate(rows)]
    def reference(rows):
        eligible = [i for category in (0,1) for i in range(len(rows)-1,-1,-1)
                    if signed(rows[i][0])!=-1 and rows[i][1]==category and not rows[i][2]]
        ordinary_all = [i for i in eligible if signed(rows[i][3])<=0]
        gifts = [i for i in eligible if signed(rows[i][3])>0]
        return ordinary_all[:70],gifts,[(i,rows[i][0],10+i) for i in ordinary_all[70:]]
    for length in range(5):
        for rows in product(types,repeat=length):
            actual = make(rows)
            expected = reference(rows)
            assert model.group(actual) == expected
            removed = {i for i,_,_ in expected[2]}
            assert all((e.first,e.second)==(-1,-1) if i in removed else (e.first,e.second)==(rows[i][0],10+i)
                       for i,e in enumerate(actual))
            for argument in (0,1,-1,255,256,-256,257):
                candidates = [i for i,r in enumerate(rows) if signed(r[0])!=-1 and r[1]==0]
                enabled = bool(argument & 255)
                count = sum(not enabled or not rows[i][2] for i in candidates)
                first = next((i for i in candidates if rows[i][2]==enabled),None)
                assert model.category_zero_count(make(rows),argument) == count
                assert model.category_zero_first(make(rows),argument) == first
                query_cases += 1
            cases += 1
    for total in (0,1,69,70,71,99,100):
        for split in range(total+1):
            for pattern in range(4):
                rows = [(1,0 if i<split else 1,pattern==3 and i%7==0,
                         1 if pattern==1 or pattern==2 and i%3==0 else 0)
                        for i in range(total)]
                actual = make(rows)
                assert model.group(actual) == reference(rows)
                assert not model.group(actual)[2]
                threshold_cases += 1
    return dict(predicate_cases=predicate, group_cases=cases,
                query_cases=query_cases, threshold_cases=threshold_cases,
                limitation='有限串行规则；不执行客户端、内存复制、失效请求或线上回执。')


def audit(db=None):
    blob = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I',blob,60)[0]
    base = struct.unpack_from('<I',blob,pe+52)[0]
    optional = struct.unpack_from('<H',blob,pe+20)[0]
    count = struct.unpack_from('<H',blob,pe+6)[0]
    sections = [(blob[pe+24+optional+40*i:pe+24+optional+40*i+8].rstrip(b'\0').decode('ascii'),
                 *struct.unpack_from('<IIII',blob,pe+24+optional+40*i+8)) for i in range(count)]
    ranges, comparisons = {},0
    def disk(va,size):
        for _,_,rva,length,offset in sections:
            d = va-base-rva
            if 0<=d and d+size<=length:
                return blob[offset+d:offset+d+size]
        return None
    def check(row):
        nonlocal comparisons
        va,size = int(row['va'],16),row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw)==size and raw==disk(va,size)==bytes.fromhex(row['disk_hex']) and row['matching']
        assert (va,size) not in ranges or ranges[(va,size)]==raw
        ranges[(va,size)] = raw
        comparisons += 1
        return raw
    evidence = read('functions.json')
    assert evidence['disk_sha256'] == SHA
    functions = {f['va']:f for f in evidence['functions']}
    assert len(functions)==len(evidence['functions'])==25
    thunks = {}
    for row in evidence['thunks']:
        raw = check(row)
        assert raw[0]==0xe9 and int(row['va'],16)+5+struct.unpack_from('<i',raw,1)[0]==int(row['target'],16)
        assert row['va'] not in thunks
        thunks[row['va']] = row['target']
    assembly_entries = calls = refs = chunks = tails = 0
    embedded_data = []
    unresolved_calls = []
    for f in functions.values():
        declared = {(int(c['start_va'],16),int(c['end_va'],16),c['is_main']) for c in f['declared_chunks']}
        assert {(s,e) for s,e,_ in declared}=={(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges']+f['chunk_byte_ranges']:
            check(row)
        assembly = {int(i['va'],16):i['text'] for i in f['assembly']}
        assert len(assembly)==len(f['assembly'])
        assert all(any(s<=va<e for s,e,_ in declared) for va in assembly)
        embedded_data.extend(i for i in f['assembly'] if i['text'].startswith(('db ','dw ','dd ','align ')))
        resolved_sites = {c['site'] for c in f['calls']}
        unresolved_calls.extend(i for i in f['assembly'] if i['text'].startswith('call ') and i['va'] not in resolved_sites)
        if db is not None:
            live = db.functions.get_at(int(f['va'],16))
            assert live.start_ea==int(f['va'],16) and live.end_ea==int(f['end_va'],16)
            live_chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea,c.end_ea,c.is_main) for c in live_chunks}==declared
            actual = {i.ea:db.instructions.get_disassembly(i) for c in live_chunks for i in db.instructions.get_between(c.start_ea,c.end_ea)}
            assert actual==assembly, ('完整声明块',f['va'])
            assert {(hex(x.from_ea),int(x.type)) for x in db.xrefs.to_ea(live.start_ea)}=={(r['source'],r['kind']) for r in f['references']}
        for row in f['calls']:
            va = int(row['site'],16)
            raw = disk(va,6)
            if raw[0]==0xe8:
                target = va+5+struct.unpack_from('<i',raw,1)[0]
            else:
                assert raw[:2]==b'\xff\x15'
                target = struct.unpack_from('<I',raw,2)[0]
            assert hex(target)==row['target'] and va in assembly
            for bridge in row['thunks']:
                assert bridge==hex(target)
                target = int(thunks[bridge],16)
            assert hex(target)==row['implementation']
            calls += 1
        assembly_entries += len(assembly)
        refs += len(f['references'])
        chunks += len(declared)
        tails += sum(not main for _,_,main in declared)
    data = read('data.json')
    assert data['disk_sha256']==SHA
    virtual = []
    for row in data['byte_ranges']:
        if row['disk_mapped']:
            raw = check(row)
            assert struct.unpack('<IIiII',raw)==(1,0x6a9319,-24,9,0x6a9325)
        else:
            va,size = int(row['va'],16),row['size']
            assert disk(va,size) is None and row['disk_hex'] is None and row['matching'] is None
            sec = next(s for s in sections if s[0]==row['mapping']['section'])
            name,vs,rva,rs,ro = sec
            d = va-base-rva
            assert rs<=d and d+size<=vs
            assert row['mapping']==dict(section=name,section_rva=hex(rva),virtual_size=vs,
                raw_size=rs,raw_offset=ro,relative_offset=d,classification='仅虚拟区')
            assert va==0xa80d1c and bytes.fromhex(row['idb_hex'])==b'\xff'*4
            virtual.append((va,size,bytes.fromhex(row['idb_hex'])))
    for target,rows in data['xrefs'].items():
        if db is not None:
            actual = set()
            for x in db.xrefs.to_ea(int(target,16)):
                owner = db.functions.get_at(x.from_ea)
                bridges = []
                if db.bytes.get_bytes_at(x.from_ea,5)[0]==0xe9:
                    for y in db.xrefs.to_ea(x.from_ea):
                        caller = db.functions.get_at(y.from_ea)
                        bridges.append((hex(y.from_ea),int(y.type),hex(caller.start_ea) if caller else None))
                actual.add((hex(x.from_ea),int(x.type),hex(owner.start_ea) if owner else None,tuple(sorted(bridges))))
            expected = {(r['source'],r['kind'],r['function'],tuple(sorted((b['site'],b['kind'],b['function']) for b in r['bridge_callers']))) for r in rows}
            assert actual==expected, ('直接导航',target)
    assert Counter(r['kind'] for r in data['xrefs']['0xa80d1c'])=={2:1,3:2}
    # 补充作者原证以外的最小原始数据，闭合case50路由、构造回调桥及局部真实大小。
    supplemental = []
    for va,size in ((0x82a387,1),(0x82a319,4),(0x60953c,5),(0x6a8c92,20)):
        raw = disk(va,size)
        if db is not None:
            assert db.bytes.get_bytes_at(va,size)==raw
        supplemental.append(dict(va=hex(va),size=size,disk_hex=raw.hex(),
            live_compared=db is not None,classification='独审新增数据/桥，不新增函数覆盖'))
    assert disk(0x828faf,7)==bytes.fromhex('0fb69155a38200')
    assert disk(0x828fb6,7)==bytes.fromhex('ff249595a28200')
    assert disk(0x82a355+50,1)==b'\x21'
    assert struct.unpack('<I',disk(0x82a295+33*4,4))[0]==0x829f0e
    assert 0x60953c+5+struct.unpack_from('<i',disk(0x60953c,5),1)[0]==0x6b8170
    assert struct.unpack('<IIiII',disk(0x6a8c92,20))==(1,0x6a8c9a,-16,8,0x6a8ca6)
    if db is not None:
        for (va,size),raw in ranges.items():
            assert db.bytes.get_bytes_at(va,size)==raw
        for va,size,raw in virtual:
            assert db.bytes.get_bytes_at(va,size)==raw
    review = json.loads((TOPIC/'函数审阅清单.json').read_text(encoding='utf-8-sig'))
    assert {r['va'] for r in review['functions']}==set(functions)
    for row in review['functions']:
        assert row['status']==('局部路径已核' if int(row['va'],16) in PARTIAL else '局部语义已审阅')
        assert row['conclusion'] and row['unknown'] and row['evidence']=='证据/functions.json'
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    covered = set()
    for va,size in ranges:
        covered.update(range(va,va+size))
    return dict(pe_sha256=SHA,mode='live' if db is not None else 'local',functions=25,
                statuses=dict(Counter(r['status'] for r in review['functions'])),assembly_entries=assembly_entries,
                embedded_data=embedded_data,resolved_calls=calls,unresolved_call_entries=len(unresolved_calls),
                function_references=refs,declared_chunks=chunks,nonmain_chunks=tails,
                thunks=len(thunks),comparisons=comparisons,unique_ranges=len(ranges),union_bytes=len(covered),
                virtual_only_ranges=len(virtual),supplemental=supplemental,
                resource_sections=resources_check(),model=model_check(),differences=0,
                limitation='限定局部语义及路径；仅虚拟区IDA值不是磁盘初值，未闭合线上协议或实机可达性。')


def export_assembly():
    lines = ['// 独审阅读副本：25入口的全部声明块；保存不代表全部业务语义完成。']
    for f in read('functions.json')['functions']:
        lines.extend(['//','// '+f['va']+' '+f['name']])
        lines.extend('// 块 '+c['start_va']+'..'+c['end_va']+' main='+str(c['is_main']) for c in f['declared_chunks'])
        lines.extend('// '+i['va']+' '+i['text'] for i in f['assembly'])
    (HERE/'independent_assembly.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':
    result = audit()
    (HERE/'independent_local.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    export_assembly()
    print(json.dumps(result,ensure_ascii=False))
