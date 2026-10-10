"""独审只读核对完整声明块、调用桥、导航、字号表与所有权模型。"""
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
SOURCES = ('seeds.json', 'lifetime_and_facade.json', 'gate_and_delete.json')


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def audit(db=None):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    count = struct.unpack_from('<H', blob, pe+6)[0]
    optional = struct.unpack_from('<H', blob, pe+20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8) for i in range(count)]
    ranges, comparisons = {}, 0

    def disk(va, size):
        for _, rva, length, offset in sections:
            d = va-base-rva
            if 0 <= d and d+size <= length:
                return blob[offset+d:offset+d+size]
        raise AssertionError(('无PE后备', hex(va), size))

    def check(row):
        nonlocal comparisons
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == size and raw == disk(va, size)
        if 'disk_hex' in row:
            assert raw == bytes.fromhex(row['disk_hex']) and row['matching']
        assert (va, size) not in ranges or ranges[(va, size)] == raw
        ranges[(va, size)] = raw
        comparisons += 1
        return raw

    functions, thunks = {}, {}
    for filename in SOURCES:
        source = read(HERE / filename)
        assert source['disk_sha256'] == SHA
        for f in source['functions']:
            assert f['va'] not in functions
            functions[f['va']] = f
        for row in source['thunks']:
            raw = check(row)
            va = int(row['va'], 16)
            assert raw[0] == 0xe9 and va+5+struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
            assert row['va'] not in thunks or thunks[row['va']] == row['target']
            thunks[row['va']] = row['target']
    instructions = calls = references = chunks = tails = 0
    for f in functions.values():
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16), c['is_main']) for c in f['declared_chunks']}
        assert {(s, e) for s, e, _ in declared} == {(int(r['va'], 16), int(r['va'], 16)+r['size']) for r in f['chunk_byte_ranges']}
        for row in f['byte_ranges']+f['chunk_byte_ranges']:
            check(row)
        assembly = {int(i['va'], 16): i['text'] for i in f['assembly']}
        assert len(assembly) == len(f['assembly'])
        assert all(any(s <= a < e for s, e, _ in declared) for a in assembly)
        if db is not None:
            live = db.functions.get_at(int(f['va'], 16))
            assert live.start_ea == int(f['va'], 16) and live.end_ea == int(f['end_va'], 16)
            live_chunks = list(db.functions.get_chunks(live))
            assert {(c.start_ea, c.end_ea, c.is_main) for c in live_chunks} == declared
            actual = {i.ea: db.instructions.get_disassembly(i) for c in live_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
            assert actual == assembly, ('完整汇编', f['va'])
            assert {(hex(x.from_ea), int(x.type)) for x in db.xrefs.to_ea(live.start_ea)} == {(r['source'], r['kind']) for r in f['references']}
        for row in f['calls']:
            va = int(row['site'], 16)
            raw = disk(va, 6)
            if raw[0] == 0xe8:
                target = va+5+struct.unpack_from('<i', raw, 1)[0]
            else:
                assert raw[:2] == b'\xff\x15', (f['va'], row)
                target = struct.unpack_from('<I', raw, 2)[0]
            assert hex(target) == row['target'] and va in assembly
            for bridge in row['thunks']:
                assert bridge == hex(target)
                target = int(thunks[bridge], 16)
            assert hex(target) == row['implementation']
            calls += 1
        instructions += len(assembly)
        chunks += len(declared)
        tails += sum(not main for _, _, main in declared)
        references += len(f['references'])
    nav = read(HERE / 'navigation.json')
    for row in nav['chains']+nav['globals']:
        raw = check(row)
        if 'target' in row:
            va = int(row['va'], 16)
            assert raw[0] == 0xe9 and va+5+struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
    expected_nav = {(r['site'], r['target'], r['kind'], r['function']) for r in nav['references']}
    assert len(expected_nav) == len(nav['references'])
    call_nav = [r for r in nav['references'] if r['target']=='0x5ff014' and r['kind']==17]
    assert len(call_nav) == 52
    assert sum(r['function'] is not None for r in call_nav) == 47
    assert len({r['function'] for r in call_nav if r['function'] is not None}) == 22
    assert Counter((r['target'],r['kind']) for r in nav['references']) == {
        ('0x5ff014',17):52, ('0xa766bc',3):4, ('0xa766bc',2):2, ('0x627830',19):1}
    for row in nav['references']:
        check(dict(va=row['site'], size=5, idb_hex=row['raw5']))
    if db is not None:
        actual_nav, pending, seen = set(), [0x627830, 0xa766bc], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in db.xrefs.to_ea(target):
                owner = db.functions.get_at(x.from_ea)
                actual_nav.add((hex(x.from_ea), hex(target), int(x.type), hex(owner.start_ea) if owner else None))
                raw = db.bytes.get_bytes_at(x.from_ea, 5)
                if raw and raw[0] == 0xe9 and x.type == 19:
                    pending.append(x.from_ea)
        assert actual_nav == expected_nav, ('导航差异', sorted(actual_nav-expected_nav), sorted(expected_nav-actual_nav))
    windows = read(HERE / 'switch_windows.json')
    for row in windows['spans']:
        check(row)
    tables = [(0x6dd6e8,0x6dd6fc,[0x6dd66e,0x6dd67c,0x6dd68b,0x6dd69a],0x6dd6a7),
              (0x6dd7e2,0x6dd7f6,[0x6dd768,0x6dd776,0x6dd785,0x6dd794],0x6dd7a1),
              (0x6ddb32,0x6ddb46,[0x6dd90a,0x6dd91b,0x6dd92d,0x6dd93f],0x6dd94f),
              (0x6ddd6d,0x6ddd81,[0x6ddd3b,0x6ddd45,0x6ddd50,0x6ddd5b],0x6ddd64)]
    route_checks = 0
    for ptr, index, legal, default in tables:
        targets = struct.unpack('<5I', disk(ptr, 20))
        indices = disk(index, 13)
        assert targets == tuple(legal+[default])
        for size in list(range(-1024, 1025))+[-2147483648,2147483647]:
            normalized = (size-12) & 0xffffffff
            actual = targets[indices[normalized]] if normalized <= 12 else default
            assert actual == dict(zip((12,14,16,24),legal)).get(size,default)
            route_checks += 1
    shutdown = read(TOPIC.parent / '事件文字记录器/证据/shutdown.json')
    assert shutdown['disk_sha256'] == SHA
    f = next(f for f in shutdown['functions'] if f['va'] == '0x624080')
    row = next(r for r in f['byte_ranges'] if int(r['va'],16) <= 0x624a3d and int(r['va'],16)+r['size'] >= 0x624b35)
    start = 0x624a3d-int(row['va'],16)
    check(dict(va='0x624a3d',size=248,idb_hex=bytes.fromhex(row['idb_hex'])[start:start+248].hex()))
    if db is not None:
        for (va,size), raw in ranges.items():
            assert db.bytes.get_bytes_at(va,size) == raw, ('live字节',hex(va),size)
    manifest = read(TOPIC / 'function_review.json')
    assert manifest['disk_sha256'] == SHA
    assert {r['va'] for r in manifest['functions']} == set(functions)
    old = read(TOPIC.parent / '字体与文本渲染/函数审阅清单.json')['functions']
    old_addresses = {int(r['va'],16) for r in old}
    new_levels = Counter()
    for row in manifest['functions']:
        f = functions[row['va']]
        assert row['declared_chunks'] == f['declared_chunks']
        assert row['declared_bytes'] == sum(int(c['end_va'],16)-int(c['start_va'],16) for c in f['declared_chunks'])
        name, pointer = row['evidence'].split('#/functions/')
        assert read(TOPIC / name)['functions'][int(pointer)]['va'] == row['va']
        if row['newly_analyzed']:
            new_levels[row['status']] += 1
        else:
            assert int(row['va'],16) in old_addresses and row['reused_topic'] == '../字体与文本渲染/函数审阅清单.json'
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8-sig').splitlines())
    spec = importlib.util.spec_from_file_location('singleton_model_independent', TOPIC / 'model_lifetime.py')
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    initialization_cases = release_cases = gate_cases = 0
    for present in product((False,True),repeat=4):
        slots = [10+i if yes else 0 for i,yes in enumerate(present)]
        for success in product((False,True),repeat=4):
            first = next((i for i,x in enumerate(success) if not x),4)
            count = min(first+1,4)
            actual, ok, replaced = model.initialize(slots,success,100)
            assert actual == [100+i if i<count else slots[i] for i in range(4)]
            assert replaced == [slots[i] for i in range(count) if slots[i]]
            assert ok == all(success)
            initialization_cases += 1
        for flag in list(range(-256,257))+[-2147483648,2147483647]:
            actual, freed, deleted = model.destroy(slots,flag)
            assert actual == [0]*4 and freed == [p for p in slots if p]
            assert deleted == bool(flag & 1)
            release_cases += 1
        borrowed = bytearray(1)
        manager = slots+[borrowed]
        for value in range(256):
            borrowed[0] = value
            assert model.gate_read(manager) == value and manager[4] is borrowed
            gate_cases += 1
    allocated = []
    def allocator():
        allocated.append(1)
        return 99
    assert model.lazy_get(7,allocator) == 7 and not allocated
    assert model.lazy_get(0,lambda:0) == 0
    assert model.lazy_get(0,allocator) == 99 and allocated == [1]
    assert model.lazy_get(99,allocator) == 99 and allocated == [1]
    covered = set()
    for va,size in ranges:
        covered.update(range(va,va+size))
    return dict(pe_sha256=SHA, mode='live' if db is not None else 'local', functions=len(functions),
                instructions=instructions, declared_chunks=chunks, nonmain_chunks=tails,
                calls=calls, function_references=references, thunks=len(thunks),
                comparisons=comparisons, unique_ranges=len(ranges), union_bytes=len(covered),
                new_status=dict(new_levels), navigation_records=len(expected_nav),
                navigation_call_edges=len(call_nav),
                switch_route_checks=route_checks, initialization_cases=initialization_cases,
                release_cases=release_cases, borrowed_gate_cases=gate_cases, lazy_cases=4,
                shutdown_reused_bytes=248, differences=0,
                limitation='静态完整声明块与串行模型；Config+5写入者、SEH作用域、原分配器及GDI未执行。')


def export_assembly():
    lines = ['// 独审阅读副本：完整声明块汇编、已有退出片段；不构成额外函数覆盖。']
    for filename in SOURCES:
        for f in read(HERE / filename)['functions']:
            lines.extend(['//', '// '+f['va']+' '+f['name']+' | '+filename])
            for c in f['declared_chunks']:
                lines.append('// 块 '+c['start_va']+'..'+c['end_va']+' main='+str(c['is_main']))
            lines.extend('// '+r['va']+' '+r['text'] for r in f['assembly'])
    f = next(f for f in read(TOPIC.parent / '事件文字记录器/证据/shutdown.json')['functions'] if f['va']=='0x624080')
    lines.extend(['//', '// 退出复用片段 624A3D..624B35'])
    lines.extend('// '+r['va']+' '+r['text'] for r in f['assembly'] if 0x624a3d <= int(r['va'],16)<0x624b35)
    (HERE / 'independent_assembly.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_local.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    export_assembly()
    print(json.dumps(result,ensure_ascii=False))
