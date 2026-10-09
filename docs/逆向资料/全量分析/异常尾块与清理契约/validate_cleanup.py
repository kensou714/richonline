"""对异常清理证据执行可重复的磁盘字节、展开链和文档格式核验。"""
import ast
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]

def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    opt = struct.unpack_from('<H', blob, pe+20)[0]
    sections = []
    for i in range(struct.unpack_from('<H',blob,pe+6)[0]):
        at = pe+24+opt+40*i
        _,rva,size,off = struct.unpack_from('<IIII',blob,at+8)
        sections.append((base+rva,size,off))
    def check(span):
        va = int(span.get('va',span.get('start_va','0')),16)
        size = span['size']
        for start,count,off in sections:
            if start<=va and va+size<=start+count:
                assert blob[off+va-start:off+va-start+size].hex()==span['disk_hex']==span['idb_hex'], hex(va)
                assert span['matching']
                return
        raise AssertionError(('未映射PE范围',hex(va),size))
    evidence = json.loads((HERE/'cleanup_evidence.json').read_text(encoding='utf-8'))
    assert evidence['disk_sha256']==hashlib.sha256(blob).hexdigest()
    contracts = json.loads((HERE/'cleanup_contracts.json').read_text(encoding='utf-8'))
    assert len(evidence['records'])==len(contracts['records'])==239
    actions = 0
    unique_actions = set()
    for r in evidence['records']:
        check(r['main_bytes']); check(r['tail'])
        assert r['chunk_parents']==[r['function_va']]
        fi=r['func_info']
        if not fi:
            continue
        check(fi['bytes']);check(fi['unwind_bytes'])
        table=fi['unwind_entries']
        assert len(table)==fi['max_state']
        for state in table:
            unique_actions.add(state['action'])
            assert int(r['tail']['va'],16)<=int(state['action'],16)<int(r['tail']['end_va'],16)
            current=state['state']; seen=set()
            while current>=0:
                assert current not in seen and current<len(table)
                seen.add(current);current=table[current]['to_state']
            assert current==-1
        actions += len(table)
    assert actions==376
    assert len(unique_actions)==375
    check(evidence['seh_scope']['bytes'])
    for name in ['cleanup_targets_full.json','unwind_runtime.json']:
        group=json.loads((HERE/name).read_text(encoding='utf-8'))
        assert group['disk_sha256']==evidence['disk_sha256']
        for f in group['functions']:
            for span in f['byte_ranges']:check(span)
            if name == 'unwind_runtime.json':
                covered = {va for span in f['byte_ranges'] for va in range(int(span['va'],16),int(span['va'],16)+span['size'])}
                for chunk in f['declared_chunks']:
                    assert set(range(int(chunk['start_va'],16),int(chunk['end_va'],16))) <= covered, (f['va'],chunk)
        for thunk in group['thunks']:check(thunk)
    for p in HERE.glob('*.py'):ast.parse(p.read_text(encoding='utf-8'))
    for p in HERE.rglob('*.txt'):
        assert all(not l.strip() or l.startswith('//') for l in p.read_text(encoding='utf-8').splitlines()),p.name
    # 逐136函数检查，单纯相同尾模板不构成主构造时序的证明。
    factory_count=0
    for r in evidence['records']:
        tail=r['tail']['assembly']
        if len(tail)!=7 or 'operator delete(void *)' not in tail[2]['text'] or '[ebp+var_14]' not in tail[0]['text']:
            continue
        assembly=r['main_assembly']
        proof=False
        for n,i in enumerate(assembly):
            if not re.search(r'mov\s+\[ebp\+var_4\], 0$',i['text']):continue
            before=assembly[max(0,n-4):n]
            after=assembly[n+1:n+9]
            proof |= (any('operator new(uint)' in v['text'] for v in before) and
                any(re.search(r'mov\s+\[ebp\+var_14\], eax',v['text']) for v in before) and
                any(v['text'].strip().startswith('call ') for v in after) and
                r['func_info']['unwind_entries']==[dict(state=0,to_state=-1,action=r['tail']['va'])])
        assert proof,r['function_va']
        factory_count+=1
    assert factory_count==136
    reviews=json.loads((HERE/'function_review.json').read_text(encoding='utf-8'))
    assert reviews['disk_sha256']==evidence['disk_sha256']
    assert {r['va'] for r in reviews['functions']}=={r['function_va'] for r in evidence['records']}
    assert len(reviews['functions'])==239
    for r in reviews['functions']:
        assert r['status']=='异常尾块局部契约已核' and not r['full_dependency_closure']
        assert all(r[k] for k in ('conclusion','unknown','evidence'))
    return dict(records=239,state_action_items=actions,unique_action_entries=len(unique_actions),new_construction_failure_contracts=factory_count,
                pe_hash=evidence['disk_sha256'],byte_mismatches=0)

if __name__=='__main__':
    print(main())
