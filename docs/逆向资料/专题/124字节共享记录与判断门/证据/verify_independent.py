"""独立从当前PE核字节、指令边界、引用和清单，不导入作者验证器。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x6B7D60, 0x6B7DC0, 0x6B7DF0, 0x6B7E70, 0x6B7F10, 0x6B7F90,
         0x734460, 0x6A5960, 0x6A39A0, 0x6A3ED0}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pointer(data, path):
    for token in path.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        data = data[int(token)] if isinstance(data, list) else data[token]
    return data


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    saved, source_files, all_sites = {}, {}, {}

    def disk(va, size):
        rows = [(rva, offset) for _, rva, length, offset in sections
                if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(rows) == 1, hex(va)
        rva, offset = rows[0]
        raw = image[offset + va - base - rva:offset + va - base - rva + size]
        assert len(raw) == size
        return raw

    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        size = row['size']
        raw = disk(va, size)
        assert raw.hex() == row['disk_hex'] == row['idb_hex'], hex(va)
        assert row['matching'] is True
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        saved[(va, size)] = hashlib.sha256(raw).hexdigest()
        return raw

    def recursive(node):
        if isinstance(node, dict):
            if 'idb_hex' in node and 'size' in node and ('va' in node or 'start_va' in node):
                audit(node)
            if 'bytes' in node and 'va' in node and isinstance(node['bytes'], str):
                raw = bytes.fromhex(node['bytes'])
                va = int(node['va'], 16)
                assert disk(va, len(raw)) == raw
                ins = list(cs.disasm(raw, va))
                assert len(ins) == 1 and ins[0].size == len(raw)
                all_sites[va] = ins[0]
            for value in node.values():
                recursive(value)
        elif isinstance(node, list):
            for value in node:
                recursive(value)

    def decode(row):
        va = int(row.get('start_va', row.get('va')), 16)
        raw = audit(row)
        instructions, cursor = list(cs.disasm(raw, va)), va
        for item in instructions:
            assert item.address == cursor
            cursor += item.size
            all_sites[item.address] = item
        assert cursor == va + len(raw)
        return instructions

    def source(ref, origin):
        path = (origin / ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        digest = ref.get('sha256', ref.get('source_sha256'))
        assert sha(path) == digest, str(path)
        source_files[str(path.relative_to(DOCS)).replace('\\', '/')] = digest
        data = json.loads(path.read_bytes())
        return pointer(data, ref['pointer']) if 'pointer' in ref else data

    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    dep = json.loads((HERE / 'dependency_raw.json').read_bytes())
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    reused = json.loads((HERE / 'reused_raw.json').read_bytes())
    navigation = json.loads((HERE / 'source_navigation.json').read_bytes())
    assert raw['disk_sha256'] == dep['disk_sha256'] == formal['disk_sha256'] == EXPECTED
    assert sha(TOPIC.parent / '四类型辅助请求与队列/证据/export_preparation_core.py') == raw['exporter_sha256']
    assert {int(x['seed_va'], 16) for x in raw['seeds']} == FRESH - {0x6A39A0, 0x6A3ED0} | {0x6B7CE0}
    assert {int(x['seed_va'], 16) for x in raw['reused_seeds']} == {0x6B7CE0}
    for node in (raw, dep, reused, navigation):
        recursive(node)
    for ref in raw['reuse_sources']:
        source(ref, DOCS)
    current = {f['seed_va']: f['chunk_byte_ranges'] for f in raw['current_chunk_audits']}
    fresh_sites, ranges, functions = {}, [], []
    for f in raw['functions']:
        assert current[f['seed_va']] == f['chunk_byte_ranges']
        decoded = [i for chunk in f['chunk_byte_ranges'] for i in decode(chunk)]
        assert [i.address for i in decoded] == [int(x['site_va'], 16) for x in f['assembly']]
        assert all(x['is_code'] for x in f['assembly'])
        for i in decoded:
            assert i.address not in fresh_sites
            fresh_sites[i.address] = i
        ranges.extend((int(c['start_va'], 16), c['size']) for c in f['chunk_byte_ranges'])
        functions.append(dict(va=f['seed_va'], bytes=sum(c['size'] for c in f['chunk_byte_ranges']),
                              instructions=len(decoded)))
    for f in dep['functions']:
        assert f['byte_ranges'] == f['chunk_byte_ranges'] and f['bytes_match_disk'] is True
        assert f['declared_chunks'] == [dict(start_va=c['va'], end_va=hex(int(c['va'], 16) + c['size']),
                                             is_main=c['va'] == f['va']) for c in f['chunk_byte_ranges']]
        decoded = [i for chunk in f['chunk_byte_ranges'] for i in decode(chunk)]
        assert [i.address for i in decoded] == [int(x['va'], 16) for x in f['assembly']]
        for i in decoded:
            assert i.address not in fresh_sites
            fresh_sites[i.address] = i
        ranges.extend((int(c['va'], 16), c['size']) for c in f['chunk_byte_ranges'])
        functions.append(dict(va=f['va'], bytes=sum(c['size'] for c in f['chunk_byte_ranges']),
                              instructions=len(decoded)))
    assert {int(f['va'], 16) for f in functions} == FRESH
    assert sum(size for _, size in ranges) == 2520 and len(fresh_sites) == 737
    for a, b in zip(sorted(ranges), sorted(ranges)[1:]):
        assert a[0] + a[1] <= b[0]
    assert len(formal['functions']) == len(raw['functions']) == 8
    assert formal['source_sha256'] == sha(HERE / 'bounded_raw.json')
    for n, (f, g) in enumerate(zip(raw['functions'], formal['functions'])):
        assert g['source'] == dict(path='证据/bounded_raw.json', sha256=formal['source_sha256'],
                                   json_pointer='/functions/' + str(n))
        assert g['va'] == f['seed_va'] and g['end_va'] == f['end_va']
        assert all(g[k] == f[k] for k in ('name', 'pseudocode', 'decompile_error'))
        assert g['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code']) for i in f['assembly']]
        assert g['chunk_byte_ranges'] == [dict(va=c['start_va'], **{k:v for k,v in c.items() if k != 'start_va'})
                                          for c in f['chunk_byte_ranges']]
        assert g['declared_chunks'] == [dict(start_va=c['start_va'],
                                             end_va=hex(int(c['start_va'], 16) + c['size']),
                                             is_main=c['start_va'] == f['seed_va']) for c in f['chunk_byte_ranges']]
    bridges = {}
    for row in raw['verified_direct_bridges'] + dep['thunks']:
        va = int(row.get('start_va', row.get('va')), 16)
        block = audit(row)
        target = int(row.get('target_va', row.get('target')), 16)
        assert block[0] == 0xE9 and len(block) == 5
        assert va + 5 + struct.unpack_from('<i', block, 1)[0] == target
        assert va not in bridges or bridges[va] == target
        bridges[va] = target
    assert len(bridges) == 28
    calls = raw['calls'] + [c for f in dep['functions'] for c in f['calls']]
    for call in calls:
        site = int(call.get('site_va', call.get('site')), 16)
        i = all_sites[site]
        assert i.mnemonic in ('call', 'jmp') and i.operands[0].type == CS_OP_IMM
        target = i.operands[0].imm & 0xFFFFFFFF
        assert target == int(call.get('target_va', call.get('target')), 16)
        for thunk in call.get('bridges', call.get('thunks', [])):
            assert int(thunk, 16) == target
            target = bridges[target]
        assert target == int(call.get('implementation_va', call.get('implementation')), 16)
    assert not raw['strings'] and not raw['data_references'] and not raw['data_windows']
    windows = [x['owner_window'] for rows in raw['incoming'].values() for x in rows if 'owner_window' in x]
    window_items = 0
    for window in windows:
        assert len(window['assembly']) <= 11
        sites = []
        for row in window['assembly']:
            i, = decode(row['bytes'])
            assert i.address == int(row['site_va'], 16)
            sites.append(i.address)
            window_items += 1
        assert sites == sorted(set(sites)) and int(window['site_va'], 16) in sites
    assert len(reused['records']) == 9
    for rec in reused['records']:
        assert source(rec['source'], HERE) == rec['original_record']
        old = rec['original_record']
        chunks = old.get('chunk_byte_ranges', [])
        if chunks:
            ins = [i for c in chunks for i in decode(c)]
            assert [i.address for i in ins] == [int(x['va'], 16) for x in old['assembly']]
    assert len(navigation['records']) == 2
    for rec in navigation['records']:
        original = source(rec['source'], HERE)
        assert rec['original_byte_ranges'] == original['chunk_byte_ranges']
        decoded = [i for c in rec['original_byte_ranges'] for i in decode(c)]
        for a in rec['anchors']:
            assert source(dict(rec['source'], pointer=a['pointer']), HERE) == a['value']
            assert int(a['value']['va'], 16) in {i.address for i in decoded}
    constructor_bridge = disk(0x610B7A, 5)
    assert constructor_bridge[0] == 0xE9
    assert 0x610B7F + struct.unpack_from('<i', constructor_bridge, 1)[0] == 0x69DF50
    assert all_sites[0x6282C9].operands[0].imm == 0x610B7A
    assert all_sites[0x6282A9].mnemonic == 'push' and all_sites[0x6282A9].operands[0].imm == 0xABC
    assert all_sites[0x6282EA].operands[0].type == CS_OP_MEM
    assert all_sites[0x6282EA].operands[0].mem.disp == 0xA76728
    historical = source(dict(path='../../游戏分派桥接/证据/property_and_6021_handlers.json',
                             sha256='9861f1e478a0ccb56863d5b766b813c03cb641da93fd7e726c5a59220d971a50',
                             pointer='/functions/18'), HERE)
    assert historical['va'] == '0x6ac070'
    historical_sites = {a['va']: a for a in historical['assembly']}
    for va in ('0x6ac082', '0x6ac08a', '0x6ac094', '0x6ac09e', '0x6ac0a6'):
        a = historical_sites[va]
        block = bytes.fromhex(a['bytes'])
        assert block == disk(int(va, 16), len(block))
        i, = list(cs.disasm(block, int(va, 16)))
        all_sites[i.address] = i
    review = json.loads((TOPIC / 'function_review.json').read_bytes())
    assert review['disk_sha256'] == EXPECTED
    records = {f['va']: f for f in formal['functions'] + dep['functions']}
    assert len(review['functions']) == len(records) == 10
    anchors = 0
    for row in review['functions']:
        assert row['status'] == '局部语义已审阅' and row['conclusion'] and row['unknown']
        ref, = row['source_records']
        record = source(ref, TOPIC)
        assert record == records[row['va']]
        assert row['declared_chunks'] == record['declared_chunks']
        assert row['original_byte_ranges'] == record['chunk_byte_ranges']
        heads = {i['va']: i for i in record['assembly']}
        assert len(heads) == len(row['anchors'])
        for a in row['anchors']:
            assert a['path'] == ref['path'] and a['pointer'].startswith(ref['pointer'] + '/assembly/')
            assert source(dict(ref, pointer=a['pointer']), TOPIC) == a['value']
            assert heads[a['site_va']]['text'] == a['value']
            assert int(a['site_va'], 16) in fresh_sites
            anchors += 1
    assert anchors == 737
    assert review['reused'] == [dict(va=r['va'], source=r['source'], status='已有原证复用；新完成数0')
                                for r in reused['records']]
    semantic = {
        0x6B7D77: ('cmp', 'dword ptr [ebp + 8], 0'),
        0x6B7D7B: ('jl', '0x6b7d94'), 0x6B7D83: ('cmp', 'ecx, dword ptr [eax + 0x5dc]'),
        0x6B7D89: ('jge', '0x6b7d94'), 0x6B7DD1: ('imul', 'eax, eax, 0x7c'),
        0x6B7DD7: ('add', 'eax, dword ptr [ecx + 0x5d8]'),
        0x6B7E29: ('cmp', 'dword ptr [ecx + edx + 0x78], 1'),
        0x6B7EBD: ('cmp', 'ecx, dword ptr [esi + eax + 0x3c]'),
        0x6B7EC1: ('jl', '0x6b7ecc'),
        0x6B7F49: ('cmp', 'dword ptr [ecx + edx + 0x60], 0'),
        0x6B7F4E: ('jle', '0x6b7f59'),
        0x6B7FC9: ('mov', 'edx, dword ptr [ecx + edx + 4]'),
        0x6B7FCD: ('mov', 'eax, dword ptr [edx + 0x20]'),
        0x6B7FD0: ('and', 'eax, 1'),
        0x7344EC: ('mov', 'edx, dword ptr [ecx]'),
        0x73458A: ('mov', 'edx, dword ptr [ecx + 0x48]'),
        0x6A5A25: ('cmp', 'ecx, dword ptr [eax + 0x5dc]'),
        0x6A5A2B: ('jge', '0x6a5d58'),
        0x6A5D70: ('cmp', 'ecx, dword ptr [eax + 0x5dc]'),
        0x6A5D76: ('jge', '0x6a5e09'),
        0x6A5D3B: ('mov', 'dword ptr [edx + eax*4], ecx'),
        0x6A5DEC: ('mov', 'dword ptr [edx + eax*4], ecx'),
        0x6A39C2: ('fild', 'dword ptr [ebp + 8]'),
        0x6A39C8: ('fld', 'qword ptr [eax + 0x58]'),
        0x6A39CB: ('fcomp', 'qword ptr [ebp - 0xc]'),
        0x6A39D0: ('test', 'ah, 1'), 0x6A39D3: ('jne', '0x6a39de'),
        0x6A3EF3: ('mov', 'ecx, dword ptr [eax]'),
        0x6A3EF8: ('mov', 'dword ptr [ebp - 0xc], 1'),
        0x6A3F15: ('mov', 'dword ptr [ebp - 0x10], 0'),
        0x6A3F31: ('push', '3'),
        0x69E48B: ('mov', 'dword ptr [edx + 0x5d8], 0'),
        0x6B7D19: ('cmp', 'dword ptr [ecx + edx + 4], 0'),
        0x6A6CF6: ('mov', 'dword ptr [edx + eax + 0x78], 0'),
        0x6A6D10: ('cmp', 'dword ptr [ebp - 8], 4'),
        0x6A6D14: ('jge', '0x6a6d2f'),
        0x6A6D28: ('mov', 'byte ptr [ecx + eax + 0x74], 0'),
        0x629EB3: ('cmp', 'dword ptr [eax + 0x5e0], -1'),
        0x629DD5: ('cmp', 'dword ptr [ebp + 8], 0'),
        0x629DF5: ('cmp', 'dword ptr [ebp + 8], 1'),
        0x629E15: ('cmp', 'dword ptr [ebp + 8], 4'),
        0x63E1A5: ('cmp', 'dword ptr [ebp + 8], 3'),
        0x64F0A1: ('mov', 'ecx, dword ptr [eax + 0x4f0]'),
        0x64F0AA: ('mov', 'eax, dword ptr [edx + 0x4d4]'),
        0x64F0B0: ('mov', 'eax, dword ptr [eax + ecx*4]'),
        0x73453B: ('mov', 'edx, dword ptr [ecx]'),
        0x7345DA: ('mov', 'edx, dword ptr [ecx]'),
        0x734615: ('mov', 'eax, dword ptr [edx]'),
        0x734513: ('push', '0x223'), 0x734562: ('push', '0x224'),
        0x7345B2: ('push', '0x226'), 0x73463C: ('push', '0x2fa'),
        0x7345F0: ('push', '0x6a'), 0x734601: ('push', 'ecx'),
        0x734661: ('push', 'edx'),
        0x6A5BC4: ('jne', '0x6a5d53'), 0x6A5BDB: ('jne', '0x6a5d53'),
        0x6A5DC2: ('jne', '0x6a5dd7'), 0x6A5DD5: ('je', '0x6a5e04'),
        0x6AC082: ('movsx', 'ecx, word ptr [eax + 2]'),
        0x6AC094: ('jne', '0x6ac09b'),
        0x6AC09E: ('movsx', 'ecx, word ptr [eax + 2]'),
    }
    for va, pair in semantic.items():
        i = all_sites[va]
        assert (i.mnemonic, i.op_str) == pair, (hex(va), i.mnemonic, i.op_str, pair)
    list_instructions = [i for va, i in fresh_sites.items() if 0x6A5960 <= va < 0x6A5E17]
    zero_counts = {o.mem.disp for i in list_instructions if i.mnemonic == 'mov' and len(i.operands) == 2
                   for o in i.operands[:1] if o.type == CS_OP_MEM and o.size == 4
                   and i.operands[1].type == CS_OP_IMM and i.operands[1].imm == 0
                   and 0x610 <= o.mem.disp <= 0x638}
    assert zero_counts == set(range(0x610, 0x63C, 4))
    docs = sorted(TOPIC.glob('*.txt')) + [HERE / '独立审阅.txt']
    for path in docs:
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    result = dict(schema='richonline-independent-record124-1', status='PASS', disk_sha256=EXPECTED,
                  functions=functions, fresh_functions=10, bytes=2520, instructions=737,
                  manifest_anchors=anchors, reused_records=9, source_navigation=2,
                  unique_bridges=len(bridges), calls=len(calls), navigation_window_items=window_items,
                  unique_saved_ranges=len(saved), source_files=source_files,
                  semantic_anchors=[dict(va=hex(va), mnemonic=p[0], operands=p[1]) for va,p in semantic.items()],
                  bound_files={str(p.relative_to(TOPIC)).replace('\\', '/'):sha(p)
                               for p in docs + [TOPIC / 'function_review.json'] + sorted(HERE.glob('*.py'))
                               + [HERE / n for n in ('bounded_raw.json', 'formal_functions.json',
                                  'dependency_raw.json', 'reused_raw.json', 'source_navigation.json')]},
                  boundary='静态局部独审；旧证和对象来源导航新增0；不证明生产、容量、释放或动态UI/网络闭环')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status='PASS', functions=10, bytes=2520, instructions=737, anchors=anchors, bridges=len(bridges))


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
