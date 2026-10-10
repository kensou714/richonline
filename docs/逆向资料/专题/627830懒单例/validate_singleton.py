"""核验PE原证、字段关键指令、真实switch字节和有限生命周期模型。"""
import hashlib
import json
import struct
from pathlib import Path
from model_lifetime import check_model

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def check():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    n, opt = struct.unpack_from('<H', blob, pe + 6)[0], struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt + 40*i + 8) for i in range(n)]
    def disk(va, size):
        for virtual, rva, rawsize, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= rawsize:
                return blob[offset+relative:offset+relative+size]
        raise AssertionError(('PE范围未映射', hex(va), size))
    spans, functions, thunks = [], {}, {}
    filenames = ('seeds.json', 'lifetime_and_facade.json', 'gate_and_delete.json')
    for filename in filenames:
        data = json.loads((HERE / '证据' / filename).read_text(encoding='utf-8'))
        assert data['disk_sha256'] == SHA
        for f in data['functions']:
            address = int(f['va'],16)
            assert address not in functions
            functions[address] = (f, filename)
            assert [(int(c['start_va'],16), int(c['end_va'],16)-int(c['start_va'],16)) for c in f['declared_chunks']] == [(int(r['va'],16),r['size']) for r in f['chunk_byte_ranges']]
            for row in f['byte_ranges'] + f['chunk_byte_ranges']:
                assert bytes.fromhex(row['idb_hex']) == bytes.fromhex(row['disk_hex']) == disk(int(row['va'],16),row['size'])
                spans.append((int(row['va'],16),row['size']))
        for t in data['thunks']:
            raw = bytes.fromhex(t['idb_hex'])
            va = int(t['va'],16)
            assert raw == disk(va,5) and raw[0] == 0xE9
            assert va + 5 + int.from_bytes(raw[1:],'little',signed=True) == int(t['target'],16)
            thunks[va] = t
            spans.append((va,5))
    manifest = json.loads((HERE / 'function_review.json').read_text(encoding='utf-8'))
    assert manifest['disk_sha256'] == SHA and len(manifest['functions']) == len(functions) == 15
    for row in manifest['functions']:
        function, filename = functions[int(row['va'],16)]
        assert row['declared_chunks'] == function['declared_chunks']
        assert row['evidence'].startswith('证据/'+filename+'#/functions/')
        index = int(row['evidence'].rsplit('/',1)[1])
        source = json.loads((HERE / '证据' / filename).read_text(encoding='utf-8'))
        assert source['functions'][index]['va'] == row['va']
    def asm(va):
        return '\n'.join(i['text'] for i in functions[va][0]['assembly'])
    def calls(va):
        return [int(c['implementation'],16) for c in functions[va][0]['calls']]
    assert 'push    14h' in asm(0x627830) and calls(0x627830).count(0x6DD250) == 1
    assert 'mov     dword_A766BC, ecx' in asm(0x627830)
    assert 'add     eax, 5' in asm(0x6DF790)
    assert not any(i['text'].startswith(('cmp ', 'test ', 'jz ', 'jnz ')) for i in functions[0x6DF790][0]['assembly'])
    ctor = asm(0x6DD250)
    assert calls(0x6DD250)[:2] == [0x627520,0x6DF790]
    for text in ('mov     [ecx+10h], eax', '[edx+0Ch], 0', '[eax+8], 0', '[ecx+4], 0', '[edx], 0'):
        assert text in ctor
    gate = asm(0x6DFC10)
    assert 'mov     ecx, [eax+10h]' in gate and 'mov     al, [ecx]' in gate
    assert 'byte ptr [edx+4], 1' in asm(0x698C70) and 'byte ptr [eax+6], 0' in asm(0x698C70)
    assert '+5]' not in asm(0x698C70)
    assert calls(0x6DD2B0).count(0x6DFBA0) == 4 and '+10h]' not in asm(0x6DD2B0)
    for va, dependency in ((0x6298E0,0x6DD2B0),(0x6DFBA0,0x8150E0)):
        assert calls(va)[:2] == [dependency,0x91FC60]
        assert 'and     eax, 1' in asm(va) and 'retn    4' in asm(va)
    assert calls(0x6DD3D0).count(0x815060) == calls(0x6DD3D0).count(0x815340) == 4
    assert 0x6DD2B0 not in calls(0x6DD3D0) and '+10h]' not in asm(0x6DD3D0)
    for va, stack in ((0x6DD600,'14h'),(0x6DD710,'14h'),(0x6DD810,'10h'),(0x6DD880,'10h')):
        assert calls(va)[0] == 0x6DFC10 and 'movzx   eax, al' in asm(va)
        assert 'retn    '+stack in asm(va)
    assert calls(0x6DD880).count(0x627830) == 2 and calls(0x6DD880).count(0x6DD710) == 2
    navigation = json.loads((HERE / '证据/navigation.json').read_text(encoding='utf-8'))
    call_refs = [r for r in navigation['references'] if r['kind'] == 17 and int(r['target'],16) == 0x5FF014]
    assert len(call_refs) == 52
    assert sum(r['function'] is not None for r in call_refs) == 47
    assert len({r['function'] for r in call_refs if r['function'] is not None}) == 22
    assert sum(int(r['target'],16) == 0xA766BC for r in navigation['references']) == 6
    for r in navigation['chains'] + navigation['globals']:
        assert disk(int(r['va'],16),r['size']) == bytes.fromhex(r['idb_hex'])
        spans.append((int(r['va'],16),r['size']))
    for r in navigation['references']:
        raw = bytes.fromhex(r['raw5'])
        assert len(raw) == 5 and disk(int(r['site'],16),5) == raw
        spans.append((int(r['site'],16),5))
        if r['kind'] in (16,17,19) and raw[0] in (0xE8,0xE9):
            assert int(r['site'],16)+5+int.from_bytes(raw[1:],'little',signed=True) == int(r['target'],16)
    # 使用原始跳转表证明真实路由，避免依赖伪码被省略的switch。
    table_data = json.loads((HERE / '证据/switch_windows.json').read_text(encoding='utf-8'))
    for r in table_data['spans']:
        assert disk(int(r['va'],16),r['size']) == bytes.fromhex(r['idb_hex'])
        spans.append((int(r['va'],16),r['size']))
    tables = [(0x6DD6E8,0x6DD6FC,[0x6DD66E,0x6DD67C,0x6DD68B,0x6DD69A],0x6DD6A7),
              (0x6DD7E2,0x6DD7F6,[0x6DD768,0x6DD776,0x6DD785,0x6DD794],0x6DD7A1),
              (0x6DDB32,0x6DDB46,[0x6DD90A,0x6DD91B,0x6DD92D,0x6DD93F],0x6DD94F),
              (0x6DDD6D,0x6DDD81,[0x6DDD3B,0x6DDD45,0x6DDD50,0x6DDD5B],0x6DDD64)]
    routing_checks = 0
    for pointers, indices, legal_targets, default in tables:
        targets = struct.unpack('<5I',disk(pointers,20))
        for size,index in zip(range(12,25),disk(indices,13)):
            expected = dict(zip((12,14,16,24),legal_targets)).get(size,default)
            assert targets[index] == expected, (hex(pointers),size,hex(targets[index]),hex(expected))
            routing_checks += 1
    shutdown_path = HERE.parent / '事件文字记录器/证据/shutdown.json'
    shutdown = json.loads(shutdown_path.read_text(encoding='utf-8'))
    assert shutdown['disk_sha256'] == SHA
    f = next(f for f in shutdown['functions'] if int(f['va'],16)==0x624080)
    row = next(r for r in f['byte_ranges'] if int(r['va'],16)<=0x624A3D and int(r['va'],16)+r['size']>=0x624B35)
    relative = 0x624A3D-int(row['va'],16)
    assert bytes.fromhex(row['idb_hex'])[relative:relative+0xF8] == disk(0x624A3D,0xF8)
    spans.append((0x624A3D,0xF8))
    for file in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in file.read_text(encoding='utf-8').splitlines())
    covered = set()
    for va,size in spans:
        covered.update(range(va,va+size))
    stats = dict(pe_sha256=SHA, functions=15, new_local_functions=9, reused_functions=6,
                 declared_chunks=sum(len(f['declared_chunks']) for f,_ in functions.values()),
                 new_declared_bytes=sum(r['declared_bytes'] for r in manifest['functions'] if r['newly_analyzed']),
                 reused_declared_bytes=sum(r['declared_bytes'] for r in manifest['functions'] if not r['newly_analyzed']),
                 span_records=len(spans), unique_spans=len(set(spans)), unique_bytes=len(covered),
                 attached_unique_thunks=len(thunks), navigation_records=len(navigation['references']),
                 navigation_call_sites=52, navigation_owned_sites=47,
                 navigation_unowned_sites=5, navigation_owned_functions=22,
                 data_windows=4, data_window_bytes=179, shutdown_reused_window_bytes=248,
                 switch_route_checks=routing_checks, byte_mismatches=0, model=check_model(),
                 limitation='局部静态原证与串行模型；运行开关写入者、SEH作用域、D3D/GDI未执行。')
    (HERE / '验证结果.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    return stats


if __name__ == '__main__':
    print(json.dumps(check(),ensure_ascii=False))
