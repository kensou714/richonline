"""用当前PE核对新原证及复用范围，验证关键ABI、字段和生命周期模型。"""
import hashlib
import json
import struct
from collections import Counter
from evidence_sources import HERE, NEW_FILES, records
from model_interfaces import check_model

SHA='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def check():
    root=HERE.parents[3]
    blob=(root/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest()==SHA
    pe=struct.unpack_from('<I',blob,0x3C)[0]
    base=struct.unpack_from('<I',blob,pe+52)[0]
    n,opt=struct.unpack_from('<H',blob,pe+6)[0],struct.unpack_from('<H',blob,pe+20)[0]
    sections=[struct.unpack_from('<IIII',blob,pe+24+opt+40*i+8) for i in range(n)]
    def disk(va,size):
        for _,rva,rawsize,offset in sections:
            relative=va-base-rva
            if 0<=relative and relative+size<=rawsize:
                return blob[offset+relative:offset+relative+size]
        raise AssertionError(('PE映射失败',hex(va),size))
    spans=[]
    def compare(row):
        va,size=int(row['va'],16),row['size']
        raw=bytes.fromhex(row['idb_hex'])
        assert len(raw)==size and raw==disk(va,size)
        if row.get('disk_hex') is not None:
            assert bytes.fromhex(row['disk_hex'])==raw
        spans.append((va,size))
    entries=records()
    functions={int(e['function']['va'],16):e['function'] for e in entries}
    assert len(functions)==len(entries)==24
    manifests=json.loads((HERE/'function_review.json').read_text(encoding='utf-8'))
    assert manifests['disk_sha256']==SHA and len(manifests['functions'])==24
    mapped={int(r['va'],16):r for r in manifests['functions']}
    sources={}
    thunks={}
    for e in entries:
        f=e['function'];va=int(f['va'],16)
        source_path=HERE/e['source']
        if e['source'] not in sources:
            sources[e['source']]=json.loads(source_path.read_text(encoding='utf-8'))
        source=sources[e['source']]
        if source.get('disk_sha256') is not None:
            assert source['disk_sha256']==SHA
        row=mapped[va]
        assert row['evidence']==e['source']+'#'+e['pointer']
        assert row['declared_chunks']==f.get('declared_chunks')
        assert row['newly_analyzed']!=e['reused']
        assert row['source_fingerprint']==e['source_fingerprint']
        for r in f['byte_ranges']+f.get('chunk_byte_ranges',[]):
            compare(r)
        if e['source'].startswith('证据/'):
            assert [(int(c['start_va'],16),int(c['end_va'],16)-int(c['start_va'],16)) for c in f['declared_chunks']]==[(int(r['va'],16),r['size']) for r in f['chunk_byte_ranges']]
        needed={t for c in f.get('calls',[]) for t in c.get('thunks',[])}
        for t in source.get('thunks',[]):
            if t['va'] not in needed:
                continue
            compare(t)
            raw=bytes.fromhex(t['idb_hex']);address=int(t['va'],16)
            assert len(raw)==5 and raw[0]==0xE9
            assert address+5+int.from_bytes(raw[1:],'little',signed=True)==int(t['target'],16)
            thunks[address]=t
    navigation=[]
    for name in ('navigation.json','local_navigation.json'):
        data=json.loads((HERE/'证据'/name).read_text(encoding='utf-8'))
        for r in data['references']:
            raw=bytes.fromhex(r['raw5']);va=int(r['site'],16)
            assert len(raw)==5 and disk(va,5)==raw
            spans.append((va,5));navigation.append(r)
            if r['kind'] in (16,17,19) and raw[0] in (0xE8,0xE9):
                assert va+5+int.from_bytes(raw[1:],'little',signed=True)==int(r['target'],16)
    def asm(va):
        return '\n'.join(i['text'] for i in functions[va]['assembly'])
    def calls(va):
        return [int(c['implementation'],16) for c in functions[va].get('calls',[])]
    assert 'mov     eax, [eax+158h]' in asm(0x728120)
    assert 'mov     eax, [eax+15Ch]' in asm(0x728060)
    assert '+158h]' in asm(0x8E31B0) and '+15Ch]' in asm(0x8E3340)
    assert calls(0x715140).count(0x728120)==1 and calls(0x715140).count(0x728060)==1
    assert calls(0x715140).count(0x8E31B0)==1 and calls(0x715140).count(0x8E3340)==1
    prior_cards=json.loads((HERE.parent/'道具与卡片操作/函数审阅清单.json').read_text(encoding='utf-8'))
    assert int(prior_cards[19]['ea'],16)==0x7113A0
    assert not mapped[0x7113A0]['newly_analyzed']
    for va,expect in ((0x727F10,[0x727F50]),(0x727F50,[0x8F4050,0x8E0590]),
                      (0x727EC0,[0x8E0650,0x8FAE70]),(0x727FE0,[0x8E0650,0x8F41B0])):
        assert calls(va)[:len(expect)]==expect
        assert 'mov     [ebp+var_4], ecx' in asm(va)
        assert 'mov     ecx, [ebp+var_4]' in asm(va)
    for va in (0x727EC0,0x727FE0):
        assert 'mov     al, [ebp+arg_4]' in asm(va) and 'retn    8' in asm(va)
    for va in (0x727F10,0x727F50):
        assert 'retn    4' in asm(va)
    assert 'fld     dword ptr [eax+21Ch]' in asm(0x727F90)
    assert 'mov     al, [eax+6]' in asm(0x727FC0)
    assert calls(0x736D10).count(0x727FC0)==1
    input_write=asm(0x81DCA0);input_clear=asm(0x81DEC0)
    assert '203h' in input_write and 'byte ptr [ecx+6], 1' in input_write
    assert 'byte ptr [edx+6], 0' in input_clear
    assert 'imul    eax, 2710h' in asm(0x728150) and 'add     cx, 1' in asm(0x728150)
    assert 'mov     [edx+eax*2], cx' in asm(0x728150)
    assert 'movzx   eax, word ptr [edx+eax*2]' in asm(0x7281B0)
    for va in (0x728150,0x7281B0):
        assert '0EA0h' in asm(va) and 'retn    8' in asm(va)
        assert not any(i['text'].startswith(('cmp ', 'test ')) for i in functions[va]['assembly'])
    assert 'imul    eax, 184h' in asm(0x728220)
    assert 'cmp     dword ptr [edx+eax+180h], 0FFFFFFFFh' in asm(0x728220)
    assert 'setnz   cl' in asm(0x728220) and 'mov     al, cl' in asm(0x728220)
    assert 0x7281B0 in calls(0x7113A0) and 0x728150 in calls(0x7113A0)
    assert 'add     eax, 1' in asm(0x7113A0) and 'jle     short loc_7117DD' in asm(0x7113A0)
    assert 0x728220 in calls(0x712750) and 'cmp     [ebp+var_2C], 6' in asm(0x712750)
    conversion=functions[0x8E0590]
    by_va={int(i['va'],16):i['text'] for i in conversion['assembly']}
    for address,text in ((0x8E0590,'sub     esp, 104h'),(0x8E05DA,'lea     eax, [esp+10Ch+MultiByteStr]'),
                         (0x8E05E0,'add     esp, 104h'),(0x8E05E6,'retn'),
                         (0x8E060C,'lea     eax, [esp+108h+MultiByteStr]'),
                         (0x8E0611,'add     esp, 104h'),(0x8E0617,'retn')):
        assert by_va[address]==text
    # 直接核对ESP相对编码，返回栈地址结论不依赖IDA局部变量显示名。
    for address,hexbytes in ((0x8E0590,'81ec04010000'),(0x8E05DA,'8d442408'),
                             (0x8E05E0,'81c404010000c3'),(0x8E060C,'8d442404'),
                             (0x8E0611,'81c404010000c3')):
        expected=bytes.fromhex(hexbytes)
        assert disk(address,len(expected))==expected
    assert 'mov     eax, [eax+38h]' in asm(0x8E0590) and 'call    eax' in asm(0x8E0590)
    assert 'push    104h; cbMultiByte' in asm(0x8E0590)
    assert 'push    0; CodePage' in asm(0x8E0590)
    assert 'jge     short loc_8F4071' in asm(0x8F4050)
    assert '[ecx+324h]' in asm(0x8F4050) and '[ecx+250h]' in asm(0x8F4050)
    edit=asm(0x8FAE70)
    for text in ('mov     eax, 500Ch','mov     al, [esi+370h]',
                 'mov     [eax], bp','mov     [ecx+eax], dx','mov     [ecx], bp','retn    8'):
        assert text in edit
    for file in HERE.glob('*.txt'):
        assert all(not l.strip() or l.startswith('//') for l in file.read_text(encoding='utf-8').splitlines())
    covered=set()
    for va,size in spans:
        covered.update(range(va,va+size))
    new=[r for r in manifests['functions'] if r['newly_analyzed']]
    result=dict(pe_sha256=SHA,functions=len(entries),new_local_functions=len(new),reused_functions=len(entries)-len(new),
                new_declared_chunks=sum(len(r['declared_chunks']) for r in new),new_declared_bytes=sum(r['declared_bytes'] for r in new),
                span_records=len(spans),unique_spans=len(set(spans)),unique_verified_bytes=len(covered),
                unique_attached_thunks=len(thunks),navigation_records=len(navigation),
                navigation_calls=sum(r['kind']==17 for r in navigation),
                navigation_e9=sum(r.get('thunk',False) for r in navigation),
                status_counts=dict(Counter(r['status'] for r in manifests['functions'])),
                byte_mismatches=0,model=check_model(),
                source_hashes={path:hashlib.sha256((HERE/path).read_bytes()).hexdigest() for path in sources},
                limitation='局部静态与有界模型；旧输入原证单独核字节，不提升其整文件指纹或依赖完成状态。')
    (HERE/'验证结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    return result


if __name__=='__main__':
    print(json.dumps(check(),ensure_ascii=False))
