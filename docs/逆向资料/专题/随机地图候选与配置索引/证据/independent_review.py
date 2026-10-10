"""独立核对静态原证与有限模型；不执行客户端，不获取或变更IDA租约。"""
from collections import Counter
from contextlib import redirect_stdout
from itertools import product
from pathlib import Path
import configparser
import hashlib
import io
import json
import re
import runpy
import struct
import sys
import lzokay

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = Path(r'F:\大富翁online\Richonline')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = ['functions_raw.json', 'dependencies_raw.json', 'supplement_raw.json']


def reproduce():
    text_writer, byte_writer, search = Path.write_text, Path.write_bytes, list(sys.path)
    old_model = sys.modules.pop('model', None)
    captured = {}
    def capture_text(path, text, *args, **kwargs):
        captured[path.resolve()] = text
        return len(text)
    def capture_bytes(path, data):
        captured[path.resolve()] = data
        return len(data)
    try:
        sys.path.insert(0, str(HERE))
        Path.write_text, Path.write_bytes = capture_text, capture_bytes
        with redirect_stdout(io.StringIO()):
            for name in ['build_review.py', 'model.py', 'inspect_resources.py', 'validate.py']:
                runpy.run_path(str(HERE/name), run_name='__main__')
    finally:
        Path.write_text, Path.write_bytes, sys.path[:] = text_writer, byte_writer, search
        sys.modules.pop('model', None)
        if old_model is not None:
            sys.modules['model'] = old_model
    for path, data in captured.items():
        if isinstance(data, bytes):
            assert data == path.read_bytes(), str(path)
        elif path.suffix == '.json':
            a, b = json.loads(data), json.loads(path.read_text('utf-8'))
            if path.name == 'validation.json':
                # 独审记录加入目录会改变文档数量，作者原始统计不作为语义差异。
                assert a.pop('documents') == len(list(TOPIC.glob('*.txt')))
                b.pop('documents')
            assert a == b, str(path)
        else:
            assert data == path.read_text('utf-8'), str(path)
    return len(captured)


def audit(db=None):
    raw = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    pe = struct.unpack_from('<I', raw, 60)[0]
    base = struct.unpack_from('<I', raw, pe+52)[0]
    opt = struct.unpack_from('<H', raw, pe+20)[0]
    sections = [struct.unpack_from('<IIII', raw, pe+24+opt+40*i+8)
                for i in range(struct.unpack_from('<H', raw, pe+6)[0])]
    def disk(va, size):
        for _, rva, length, at in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= length:
                return raw[at+delta:at+delta+size]
        raise AssertionError((hex(va), size))
    byte_map, spans, functions, thunks, ins, chunks = {}, set(), {}, {}, {}, set()
    comparisons = calls = 0
    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        expected = bytes.fromhex(row['idb_hex'])
        assert len(expected) == size and disk(va, size) == expected
        if 'disk_hex' in row:
            assert row['disk_hex'] == expected.hex() and row['matching'] is True
        if db is not None:
            assert db.bytes.get_bytes_at(va, size) == expected
        for n, value in enumerate(expected):
            assert byte_map.get(va+n, value) == value
            byte_map[va+n] = value
        comparisons += 1
        spans.add((va, size))
    for name in SOURCES:
        source = json.loads((HERE/name).read_text('utf-8'))
        assert source['disk_sha256'] == SHA
        for row in source['thunks']:
            check(row)
            va, code = int(row['va'], 16), bytes.fromhex(row['idb_hex'])
            assert len(code) == 5 and code[0] == 0xE9
            assert va+5+struct.unpack_from('<i', code, 1)[0] == int(row['target'], 16)
            assert thunks.get(va, row) == row
            thunks[va] = row
        for f in source['functions']:
            va = int(f['va'], 16)
            assert va not in functions and f['bytes_match_disk'] is True
            functions[va] = f
            declared = {(int(c['start_va'],16),int(c['end_va'],16),c['is_main']) for c in f['declared_chunks']}
            assert {(s,e) for s,e,_ in declared} == {(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges']}
            for r in f['byte_ranges']+f['chunk_byte_ranges']:
                check(r)
            chunks.update((va,s,e) for s,e,_ in declared)
            for i in f['assembly']:
                address = int(i['va'],16)
                assert any(s <= address < e for s,e,_ in declared)
                assert ins.get(address,i['text']) == i['text']
                ins[address] = i['text']
            for call in f['calls']:
                site, target = int(call['site'],16), int(call['target'],16)
                code = disk(site,6)
                if code[0] in (0xE8,0xE9):
                    assert site+5+struct.unpack_from('<i',code,1)[0] == target
                else:
                    assert code[:2] == b'\xff\x15' and struct.unpack_from('<I',code,2)[0] == target
                calls += 1
            if db is not None:
                live = db.functions.get_at(va)
                assert live.start_ea == va and live.end_ea == int(f['end_va'],16)
                lc = list(db.functions.get_chunks(live))
                assert {(c.start_ea,c.end_ea,c.is_main) for c in lc} == declared
                assert {i.ea:db.instructions.get_disassembly(i) for c in lc for i in db.instructions.get_between(c.start_ea,c.end_ea)} == {int(i['va'],16):i['text'] for i in f['assembly']}
                edges = [dict(site=hex(i.ea),target=hex(x.to_ea)) for c in lc for i in db.instructions.get_between(c.start_ea,c.end_ea) for x in db.xrefs.from_ea(i.ea) if x.type in (16,17)]
                assert edges == [{k:c[k] for k in ('site','target')} for c in f['calls']]
    assert len(functions) == 32 and len(chunks) == 36 and len(ins) == 1722
    for row in json.loads((HERE/'data_raw.json').read_text('utf-8')):
        check(row)
    table = struct.unpack('<4I',disk(0x6AAB34,16))
    assert table == (0x6AAADC,0x6AAAEE,0x6AAB06,0x6AAAD0)
    assert disk(0xA239D0,19) == b'Data\\RandomMap.kpd\0'
    navigation = json.loads((HERE/'inbound.json').read_text('utf-8'))
    nav_count = 0
    for group in navigation:
        for edge in group['edges']:
            row = dict(va=edge['site'],size=5,idb_hex=edge['idb_hex'])
            check(row)
            va, code = int(edge['site'],16),bytes.fromhex(edge['idb_hex'])
            assert code[0] in (0xE8,0xE9)
            assert va+5+struct.unpack_from('<i',code,1)[0] == int(edge['target'],16)
            assert edge['bridge'] == (code[0] == 0xE9)
            if db is not None:
                owner = db.functions.get_at(va)
                assert (hex(owner.start_ea) if owner else None) == edge['owner']
            nav_count += 1
        if db is not None:
            for target in {group['target']} | {e['target'] for e in group['edges']}:
                assert {(hex(x.from_ea),int(x.type)) for x in db.xrefs.to_ea(int(target,16))} == {(e['site'],e['kind']) for e in group['edges'] if e['target']==target}
    assert nav_count == 45
    anchors = {0x6AA489:'movzx   edx, al',0x6AA4A9:'jnb     short loc_6AA4B6',0x6AA4AE:'add     ecx, 1',0x6AA4C3:'jz      short loc_6AA510',0x6AAAC4:'ja      short def_6AAAC9; jumptable 006AAAC9 default case',0x6AAB22:'xor     al, al; jumptable 006AAAC9 default case',0x7E9642:'jge     short loc_7E967C',0x7E9671:'mov     eax, [edx+eax+108h]',0x6BA66F:'jbe     short loc_6BA683',0x6BA99E:'jz      short loc_6BA9B5',0x6BA9AB:'rep movsd'}
    for address, text in anchors.items():
        assert ins[address] == text,(hex(address),ins.get(address))
    asm = {va:'\n'.join(i['text'] for i in f['assembly']) for va,f in functions.items()}
    assert asm[0x6AA530].count('idiv    ecx') == 9
    assert asm[0x6AA530].index('timeGetTime') < asm[0x6AA530].index('j__srand') < asm[0x6AA530].index('arg_0')
    assert 'cld' not in asm[0x6BA970] and 'j__rand' not in asm[0x6AA450]
    expected_groups = ['CM_SMALL','CM_BIG','CM_ALL','PK_SMALL','PK_BIG','PK_ALL','KO_SMALL','KO_BIG','KO_ALL']
    loaded_groups = re.findall(r'"((?:CM|PK|KO)_(?:SMALL|BIG|ALL))"',asm[0x6A9D50])
    assert loaded_groups == expected_groups
    assert [int(m,16) for m in re.findall(r'add     ecx, ([0-9A-F]+)h',asm[0x6A9D50])] == [0x548+16*i for i in range(9)]
    model = runpy.run_path(str(HERE/'model.py'))
    bounds = [(table[i], min([a for a in table if a>table[i]]+[0x6AAB22])) for i in range(4)]
    derived = {i:{int(m) for m in re.findall(r'cmp     \[ebp\+var_C\], (\d+)', '\n'.join(ins[a] for a in sorted(ins) if s<=a<e))} for i,(s,e) in enumerate(bounds)}
    assert derived == {0:{0,3},1:{0,1,3},2:{0,1,2,3},3:{3}}
    matrix_cases = 0
    for threshold in [-0x80000000,-1,0,1,2,3,4,0x7FFFFFFF,0xFFFFFFFF]:
        for category in [-0x80000000,-1,0,1,2,3,4,0x7FFFFFFF,0xFFFFFFFF]:
            allowed = category in derived.get(threshold & 0xFFFFFFFF,set())
            assert model['allow'](threshold,category) == allowed
            matrix_cases += 1
    ring_cases = 0
    for count in range(1,10):
        for bits in product([False,True],repeat=count):
            for start in range(count):
                current, visited, chosen = start, [], None
                while True:
                    visited.append(current)
                    if bits[current]:
                        chosen = current
                        break
                    current = 0 if current>=count-1 else current+1
                    if current==start:
                        break
                oracle = next((p for p in list(range(start,count))+list(range(start)) if bits[p]),None)
                assert model['select'](start,bits)==(oracle,visited) and chosen==oracle
                assert len(visited)<=count and len(set(visited))==len(visited)
                ring_cases += 1
    assert ring_cases == 8194
    assert Counter(model['select'](i,[True,False,False,True])[0] for i in range(4)) == {0:1,3:3}
    for start,bits in [(0,[]),(-1,[True]),(1,[True])]:
        try:
            model['select'](start,bits)
        except AssertionError:
            pass
        else:
            raise AssertionError('模型应拒绝非法起点')
    resources = json.loads((HERE/'resources.json').read_text('utf-8'))
    parsers = {}
    for row in resources['resources']:
        packed = (ROOT/row['path']).read_bytes()
        assert len(packed)==row['source_size'] and hashlib.sha256(packed).hexdigest()==row['source_sha256']
        assert packed[0]==row['key']
        decoded_header = bytes((b-packed[0])%256 for b in packed[1:])
        n,m = struct.unpack_from('<II',decoded_header)
        assert (n,m)==(row['decoded_size'],row['compressed_size']) and len(decoded_header)==m+8
        plain = lzokay.decompress(decoded_header[8:],n)
        assert plain==(HERE/(Path(row['path']).name+'.decoded.bin')).read_bytes()
        assert hashlib.sha256(plain).hexdigest()==row['decoded_sha256']
        parser = configparser.ConfigParser(interpolation=None,strict=True)
        parser.optionxform = str
        parser.read_string(plain.decode('ascii').rstrip('\0'))
        parsers[Path(row['path']).name]=parser
    candidate = parsers['RandomMap.kpd']
    assert candidate.sections()==expected_groups
    groups, unique = {}, {}
    membership = {v for s in parsers['MapList.kpd'].sections() for _,v in parsers['MapList.kpd'].items(s)}
    for i,row in enumerate(resources['groups']):
        section = row['section']
        assert int(row['object_offset'],16)==0x548+16*i
        pairs = list(candidate.items(section))
        assert pairs==[(e['key'],e['value']) for e in row['entries']]
        assert [k for k,_ in pairs]==['map%02d' % n for n in range(1,len(pairs)+1)]
        groups[section] = [v for _,v in pairs]
        for e in row['entries']:
            value = e['value']
            assert value in membership and len(value.encode('ascii'))==e['value_size']<128
            path = ROOT/'Map'/value
            content = path.read_bytes()
            assert e['disk_path']=='Map/'+value and e['disk_exists'] is True
            assert hashlib.sha256(content).hexdigest()==e['disk_sha256']
            summary = e['emp_summary']
            version,mode=struct.unpack_from('<I',content,16)[0],struct.unpack_from('<I',content,23288)[0]
            assert summary['file_size']==len(content) and summary['version_at_16']==version
            assert summary['mode_offset']==23288 and summary['mode']==mode
            assert mode=={'CM':0,'PK':1,'KO':4}[section[:2]]
            assert unique.get(value,(version,mode))==(version,mode)
            unique[value]=(version,mode)
    assert len(unique)==54 and sum(map(len,groups.values()))==111
    assert [len(groups[s]) for s in expected_groups]==[16,9,25,22,4,26,3,3,3]
    for prefix in ['CM','PK']:
        assert groups[prefix+'_ALL']==groups[prefix+'_SMALL']+groups[prefix+'_BIG']
    assert groups['KO_SMALL']==groups['KO_BIG']==['QJ_GW_01.emp','QJ_SM_01.emp','QJ_HD_01.emp']
    assert groups['KO_ALL']==['QJ_GW_01.emp','QJ_HD_01.emp','QJ_SM_01.emp']
    assert Counter(v for v,m in unique.values() if m==0)=={1:23,3:2}
    assert Counter(v for v,m in unique.values() if m==1)=={1:24,3:2}
    assert Counter(v for v,m in unique.values() if m==4)=={3:3}
    review = json.loads((HERE/'function_review.json').read_text('utf-8'))
    assert Counter(f['status'] for f in review['functions'])=={'局部语义已审阅':29,'部分分析':3}
    assert {int(f['va'],16) for f in review['functions']}==set(functions)
    assert {int(f['va'],16) for f in review['functions'] if f['status']=='部分分析'}=={0x628C60,0x6B92E0,0x6BA620}
    for path in TOPIC.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    reproduced = reproduce()
    return dict(ida_live=db is not None,disk_sha256=SHA,functions=len(functions),declared_chunks=len(chunks),instruction_addresses=len(ins),byte_comparisons=comparisons,unique_verified_bytes=len(byte_map),unique_spans=len(spans),attached_thunks=len(thunks),call_edges=calls,navigation_records=nav_count,data_records=2,matrix_cases=matrix_cases,ring_cases=ring_cases,bounded_model_rejections=3,resource_groups=9,resource_records=111,unique_emp_files=54,author_outputs_reproduced=reproduced,mismatches=0,scope='静态声明块、原资源及有限环筛选模型；不执行原函数，不证明异常清理、运行时MapList或真实菜单可达性。')


if __name__ == '__main__':
    result = audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result,ensure_ascii=True))
