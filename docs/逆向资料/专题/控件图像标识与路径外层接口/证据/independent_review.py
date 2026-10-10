"""独立复核控件外层接口；仅读原证、PE和可选IDA数据库，不执行原函数。"""
from collections import Counter
from contextlib import redirect_stdout
from itertools import product
from pathlib import Path
import hashlib
import io
import json
import runpy
import struct

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SETTERS = {0x6FA840: (1, 0x8E1C70), 0x6FA890: (2, 0x8E1C70),
           0x6FA8E0: (3, 0x8E1C70), 0x6FA960: (0, 0x8E1DB0),
           0x6FA9E0: (1, 0x8E1DB0), 0x6FAA60: (2, 0x8E1DB0),
           0x6FAAE0: (3, 0x8E1DB0)}
GETTERS = {0x6FA930: 200, 0x6FA9B0: 240, 0x6FAA30: 280, 0x6FAAB0: 320}
EXCLUDED = {0x6FA5C0, 0x6FA610, 0x6FA6B0, 0x6FA700, 0x6FA730,
            0x6FA760, 0x6FA790, 0x6FA7C0}


def reproduce():
    original = Path.write_text
    captured = {}
    def capture(path, value, *args, **kwargs):
        captured[path.resolve()] = value
        return len(value)
    try:
        Path.write_text = capture
        with redirect_stdout(io.StringIO()):
            runpy.run_path(str(HERE/'validate_wrapper.py'), run_name='__main__')
    finally:
        Path.write_text = original
    assert set(captured) == {(HERE/'validation.json').resolve()}
    for path, value in captured.items():
        assert json.loads(value) == json.loads(path.read_text('utf-8'))
    return len(captured)


def audit(db=None):
    data = json.loads((HERE/'wrapper.json').read_text('utf-8'))
    image = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == data['disk_sha256'] == SHA
    assert data['idb_input_sha256'] != SHA
    if db is not None:
        import ida_bytes
        import ida_funcs
        import ida_nalt
        import idautils
        import idc
        assert ida_nalt.retrieve_input_file_sha256().hex() == data['idb_input_sha256']
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[pe:pe+4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe+52)[0]
    opt = struct.unpack_from('<H', image, pe+20)[0]
    sections = [struct.unpack_from('<IIII', image, pe+24+opt+40*i+8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]
    def disk(va, size):
        for _, rva, raw_size, raw in sections:
            offset = va-base-rva
            if 0 <= offset and offset+size <= raw_size:
                return image[raw+offset:raw+offset+size]
        raise AssertionError((hex(va), size))
    byte_map, spans, incoming_bytes = {}, set(), {}
    comparisons = 0
    def check(row):
        nonlocal comparisons
        va, size = int(row['va'],16), row['size']
        raw = bytes.fromhex(row['ida_hex'])
        assert len(raw) == size and row['equal'] is True
        assert raw.hex() == row['disk_hex'] and raw == disk(va,size)
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        if db is not None:
            assert db.bytes.get_bytes_at(va,size) == raw
        for i, value in enumerate(raw):
            assert byte_map.get(va+i,value) == value
            byte_map[va+i] = value
        spans.add((va,size)); comparisons += 1
    def target(va, raw):
        if raw[0] in (0xE8,0xE9):
            assert len(raw) == 5
            return va+5+struct.unpack_from('<i',raw,1)[0]
        assert raw[0] == 0xEB and len(raw) == 2
        return va+2+struct.unpack_from('<b',raw,1)[0]
    bridges = {}
    for row in data['thunks']:
        check(row)
        va, raw = int(row['va'],16), bytes.fromhex(row['ida_hex'])
        assert raw[0] == 0xE9 and va not in bridges
        bridges[va] = target(va,raw)
        assert bridges[va] == int(row['target'],16)
    def resolve(va):
        seen = set()
        while va in bridges:
            assert va not in seen
            seen.add(va); va = bridges[va]
        return va
    def live_instructions(start,end):
        return [dict(va=hex(a), size=idc.get_item_size(a),
                     hex=ida_bytes.get_bytes(a,idc.get_item_size(a)).hex(),
                     text=idc.generate_disasm_line(a,0) or '')
                for a in idautils.Heads(start,end) if ida_bytes.is_code(ida_bytes.get_full_flags(a))]
    functions, ins, instruction_count, near_edges, chunk_count = {}, {}, 0, 0, 0
    for f in data['functions']:
        va = int(f['va'],16)
        assert va not in functions
        functions[va] = f
        chunks = []
        for c in f['chunks']:
            check(c)
            start,end = int(c['va'],16),int(c['end'],16)
            assert end-start == c['size']
            chunks.append((start,end)); chunk_count += 1
        for i in f['instructions']:
            a, raw = int(i['va'],16),bytes.fromhex(i['hex'])
            assert len(raw) == i['size'] and disk(a,len(raw)) == raw
            assert sum(s<=a and a+len(raw)<=e for s,e in chunks) == 1
            assert a not in ins
            ins[a] = i['text']; instruction_count += 1
        for c in f['calls']:
            site = int(c['site'],16)
            raw = bytes.fromhex(next(i['hex'] for i in f['instructions'] if int(i['va'],16)==site))
            dest = target(site,raw)
            assert dest == int(c['target'],16) and resolve(dest) == int(c['resolved'],16)
            near_edges += 1
        if db is not None:
            live = ida_funcs.get_func(va)
            assert live and live.start_ea == va
            assert list(idautils.Chunks(va)) == chunks
            assert [i for s,e in chunks for i in live_instructions(s,e)] == f['instructions']
            live_edges = [dict(site=hex(a),target=hex(idc.get_operand_value(a,0)))
                          for s,e in chunks for a in idautils.Heads(s,e)
                          if ida_bytes.is_code(ida_bytes.get_full_flags(a))
                          and idc.print_insn_mnem(a) in ('call','jmp')
                          and idc.get_operand_type(a,0) in (idc.o_near,idc.o_far)]
            assert live_edges == [{k:c[k] for k in ('site','target')} for c in f['calls']]
    assert set(functions) == set(SETTERS)|set(GETTERS)|EXCLUDED|{0x7809D0}
    assert set(functions) == {int(data['scope']['main'],16)}|{int(x,16) for x in data['scope']['selected_functions']}
    for row in data['caller_navigation']:
        assert row['incoming'] in data['incoming']
        check(row['window'])
        start,size = int(row['window']['va'],16),row['window']['size']
        for i in row['instructions']:
            a = int(i['va'],16)
            assert start <= a and a+i['size'] <= start+size
            assert disk(a,i['size']).hex() == i['hex']
        if db is not None:
            assert live_instructions(start,start+size) == row['instructions']
    for row in data['incoming']:
        site, entry = int(row['site'],16),int(row['entry'],16)
        assert row['iscode'] is True and row['type'] == 17
        raw = disk(site,5)
        assert raw[0] == 0xE8 and target(site,raw) == entry
        assert resolve(entry) == int(row['resolved'],16) == 0x6FA8E0
        incoming_bytes.update({site+i:value for i,value in enumerate(raw)})
        if db is not None:
            assert db.bytes.get_bytes_at(site,5) == raw
            owner = ida_funcs.get_func(site)
            assert owner and hex(owner.start_ea) == row['caller']
    if db is not None:
        entries = {0x6FA8E0}|{va for va in bridges if resolve(va)==0x6FA8E0}
        live_incoming = []
        for entry in sorted(entries):
            for x in idautils.XrefsTo(entry,0):
                owner = ida_funcs.get_func(x.frm)
                caller = owner.start_ea if owner else None
                if caller not in entries:
                    live_incoming.append(dict(site=hex(x.frm),entry=hex(entry),resolved=hex(0x6FA8E0),
                                              caller=hex(caller) if caller else None,
                                              iscode=bool(x.iscode),type=int(x.type)))
        assert live_incoming == data['incoming']
    # 包装自身只建立调用栈：模型停在底层调用之前，不执行或复述底层状态更新。
    wrapper_cases = 0
    for va,(index,callee) in SETTERS.items():
        rows = functions[va]['instructions']
        body = [r['text'].split(';',1)[0].strip() for r in rows]
        arg = 'lpString' if callee == 0x8E1DB0 else 'arg_0'
        assert body[4:12] == ['mov     [ebp+var_4], ecx',f'mov     eax, [ebp+{arg}]',
                             'push    eax',f'push    {index}','mov     ecx, [ebp+var_4]',
                             'add     ecx, 0A4h','push    ecx','mov     ecx, [ebp+var_4]']
        assert functions[va]['calls'][0]['resolved'] == hex(callee)
        assert body[-1] == 'retn    4' and body[13] == 'add     esp, 4'
        for owner,argvalue in product([0,1,0x100000,0xFFFFFF80,0xFFFFFFFF],repeat=2):
            values = {'ecx':owner, f'[ebp+{arg}]':argvalue}
            pushed = []
            for text in body[4:12]:
                op, operands = text.split(None,1)
                if op == 'push':
                    pushed.append(values[operands] if operands in values else int(operands))
                else:
                    left,right = operands.split(', ')
                    value = values[right] if right in values else int(right[:-1],16)
                    values[left] = value if op == 'mov' else (values[left]+value)&0xFFFFFFFF
            assert values['ecx'] == owner and list(reversed(pushed)) == [(owner+164)&0xFFFFFFFF,index,argvalue]
            wrapper_cases += 1
    getter_cases = 0
    for va,offset in GETTERS.items():
        body = [r['text'] for r in functions[va]['instructions']]
        assert len(body)==10 and not functions[va]['calls']
        assert body[5]=='mov     eax, [ebp+var_4]' and body[6].startswith('mov     eax, [eax+')
        raw = bytes.fromhex(functions[va]['instructions'][6]['hex'])
        assert raw == b'\x8b\x80'+struct.pack('<I',offset) and body[-1]=='retn'
        assert offset == 164+36+40*list(GETTERS).index(va)
        for pointer in [0,1,0x100000,0x80000000,0xFFFFFFFF]:
            # 单DWORD读取不复制内容；模型保留原始指针位型，包括NULL。
            memory = {offset:pointer}
            assert memory[offset] == pointer
            getter_cases += 1
    for va,offset in [(0x6FA700,20736),(0x6FA730,20740),(0x6FA760,20732),(0x6FA790,20832)]:
        assert ins[va+14]=='mov     eax, [ebp+var_4]'
        assert bytes.fromhex(functions[va]['instructions'][7]['hex']) == b'\x89\x88'+struct.pack('<I',offset)
        assert not functions[va]['calls']
    assert ins[0x6FA7D1] == 'mov     eax, [eax+190h]'
    assert ins[0x6FA621] == 'and     eax, 2' and ins[0x6FA632].startswith('push    84h')
    assert functions[0x6FA5C0]['calls'][0]['resolved']=='0x6e1dd0'
    assert functions[0x6FA6B0]['calls'][0]['resolved']=='0x8e02f0'
    assert ins[0x7809E6]=='cmp     eax, 5' and ins[0x7809E9].startswith('jnz ')
    assert ins[0x7809EE]=='cmp     dword ptr [eax+48h], 0FFFFFFFFh'
    assert ins[0x7809F2].startswith('jz ') and ins[0x7809F4]=='push    0FFFFFFFFh'
    assert ins[0x7809F6]=='mov     ecx, [ebp+arg_0]' and ins[0x780A1E]=='mov     al, 1'
    assert ins[0x780A13]=='add     ecx, 0D0h'
    assert [c['resolved'] for c in functions[0x7809D0]['calls'][:5]] == [
        '0x7278e0','0x6fa8e0','0x629f50','0x629f20','0x642b30']
    review = json.loads((HERE/'function_review.json').read_text('utf-8'))
    assert {int(x,16) for x in review} == set(functions)
    assert {int(x,16) for x,r in review.items() if r['status']=='静态局部语义已审阅'} == set(SETTERS)|set(GETTERS)
    assert {int(x,16) for x,r in review.items() if r['status']=='调用消费局部审阅'} == {0x7809D0}
    assert {int(x,16) for x,r in review.items() if r['status']=='相邻候选排除主范围'} == EXCLUDED
    for path in TOPIC.glob('*.txt'):
        assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    outputs = reproduce()
    return dict(ida_live=db is not None,disk_sha256=SHA,idb_input_sha256=data['idb_input_sha256'],
                whole_idb_identity_claimed=False,functions=len(functions),chunks=chunk_count,
                instructions=instruction_count,range_comparisons=comparisons,unique_spans=len(spans),
                unique_range_bytes=len(byte_map),thunks=len(bridges),near_edges=near_edges,
                incoming=len(data['incoming']),incoming_call_bytes=len(incoming_bytes),
                navigation_windows=len(data['caller_navigation']),setter_model_cases=wrapper_cases,
                getter_value_cases=getter_cases,review_counts=dict(Counter(r['status'] for r in review.values())),
                author_outputs_reproduced=outputs,mismatches=0,
                scope='20外层函数及5局部窗口；底层复用不重复审阅，有限栈参数模型不执行原函数，不证明清图、加载成功或所有权闭环。')


if __name__ == '__main__':
    result = audit()
    (HERE/'independent_local_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result,ensure_ascii=True))
