"""独立核当前PE及完整保存证据；不导入作者采证器或验证器。"""
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
FRESH = {0x6A4DC0, 0x6A4E70, 0x6A51A0, 0x6AB280, 0x6A6E00}
OLD = {0x6AAD70, 0x6ADEC0, 0x6A54F0}


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
    saved, sources, sites = {}, {}, {}

    def disk(va, size):
        choices = [(rva, offset) for _, rva, length, offset in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(choices) == 1, hex(va)
        rva, offset = choices[0]
        block = image[offset + va - base - rva:offset + va - base - rva + size]
        assert len(block) == size
        return block

    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        block = disk(va, row['size'])
        assert block.hex() == row['disk_hex'] == row['idb_hex'], hex(va)
        assert row['matching'] is True
        digest = hashlib.sha256(block).hexdigest()
        if 'sha256' in row:
            assert digest == row['sha256']
        saved[(va, len(block))] = digest
        return block

    def decode(row):
        va = int(row.get('start_va', row.get('va')), 16)
        block = audit(row)
        items = list(cs.disasm(block, va))
        cursor = va
        for item in items:
            assert item.address == cursor
            cursor += item.size
            sites[item.address] = item
        assert cursor == va + len(block), hex(va)
        return items

    def recursive(node):
        if isinstance(node, dict):
            if 'idb_hex' in node and 'size' in node and ('va' in node or 'start_va' in node):
                audit(node)
            if isinstance(node.get('bytes'), str) and 'va' in node:
                block = bytes.fromhex(node['bytes'])
                va = int(node['va'], 16)
                assert disk(va, len(block)) == block
                item, = list(cs.disasm(block, va))
                assert item.size == len(block)
                sites[va] = item
            for value in node.values():
                recursive(value)
        elif isinstance(node, list):
            for value in node:
                recursive(value)

    def source(ref, origin):
        path = (origin / ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        digest = ref.get('sha256', ref.get('source_sha256'))
        assert sha(path) == digest, str(path)
        sources[str(path.relative_to(DOCS)).replace('\\', '/')] = digest
        data = json.loads(path.read_bytes())
        return pointer(data, ref.get('pointer', ref.get('json_pointer', ''))) if any(
            key in ref for key in ('pointer', 'json_pointer')) else data

    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    current = json.loads((HERE / 'reused_6AAD70_current.json').read_bytes())
    assert raw['disk_sha256'] == current['disk_sha256'] == EXPECTED
    assert sha(TOPIC.parent / '四类型辅助请求与队列/证据/export_preparation_core.py') == raw['exporter_sha256']
    assert {int(row['seed_va'], 16) for row in raw['seeds']} == FRESH | OLD
    assert {int(row['seed_va'], 16) for row in raw['reused_seeds']} == OLD
    for node in (raw, current):
        recursive(node)
    for ref in raw['reuse_sources']:
        source(ref, DOCS)
    old_dec = json.loads((DOCS / '专题/大厅玩家记录与装备字段/证据/record_lifecycle.json').read_bytes())
    old_cmp = json.loads((DOCS / '专题/角色1416字段来源/证据/functions.json').read_bytes())
    reused = [current['functions'][0], next(f for f in old_dec['functions'] if f['va'] == '0x6adec0'),
              old_cmp['functions'][18]]
    assert {int(f['va'], 16) for f in reused} == OLD
    audits = {r['seed_va']: r['chunk_byte_ranges'] for r in raw['current_chunk_audits']}
    functions, fresh_sites, ranges = [], {}, []
    for f in raw['functions'] + reused:
        va = f.get('seed_va', f.get('va'))
        chunks = f['chunk_byte_ranges']
        expected = [dict(c, start_va=c['va']) if 'va' in c else c for c in chunks]
        for a, b in zip(audits[va], expected):
            assert int(a['start_va'], 16) == int(b['start_va'], 16) and a['size'] == b['size']
            assert a['disk_hex'] == b['disk_hex']
        assert len(audits[va]) == len(chunks)
        decoded = [i for c in chunks for i in decode(c)]
        assert [i.address for i in decoded] == [int(a.get('site_va', a.get('va')), 16) for a in f['assembly']]
        assert all(a.get('is_code', True) for a in f['assembly'])
        fresh = int(va, 16) in FRESH
        if fresh:
            for i in decoded:
                assert i.address not in fresh_sites
                fresh_sites[i.address] = i
            ranges.extend((int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks)
        functions.append(dict(va=va, fresh=fresh, bytes=sum(c['size'] for c in chunks), instructions=len(decoded)))
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    assert sum(size for _, size in ranges) == 1471 and len(fresh_sites) == 453
    for a, b in zip(sorted(ranges), sorted(ranges)[1:]):
        assert a[0] + a[1] <= b[0]
    bridges = {}
    for row in raw['verified_direct_bridges'] + current['thunks']:
        va = int(row.get('start_va', row.get('va')), 16)
        block = audit(row)
        target = int(row.get('target_va', row.get('target')), 16)
        assert block[0] == 0xE9 and len(block) == 5
        assert va + 5 + struct.unpack_from('<i', block, 1)[0] == target
        assert va not in bridges or bridges[va] == target
        bridges[va] = target
    assert len(bridges) == 40
    for call in raw['calls']:
        item = sites[int(call['site_va'], 16)]
        assert item.mnemonic in ('call', 'jmp') and item.operands[0].type == CS_OP_IMM
        target = item.operands[0].imm & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert target == int(bridge, 16)
            target = bridges[target]
        assert target == int(call['implementation_va'], 16)
    assert len(raw['calls']) == 105
    for ref in raw['data_references']:
        item = sites[int(ref['site_va'], 16)]
        values = [(op.imm & 0xFFFFFFFF) for op in item.operands if op.type == CS_OP_IMM]
        values += [(op.mem.disp & 0xFFFFFFFF) for op in item.operands if op.type == CS_OP_MEM]
        assert int(ref['target_va'], 16) in values
    assert len(raw['data_references']) == 19 and not raw['strings'] and not raw['data_windows']
    windows = raw['explicit_owner_windows'] + [r['owner_window'] for rows in raw['incoming'].values()
                                               for r in rows if 'owner_window' in r]
    heads = 0
    for window in windows:
        assert len(window['assembly']) <= 11
        addresses = []
        for row in window['assembly']:
            item, = decode(row['bytes'])
            assert item.address == int(row['site_va'], 16)
            addresses.append(item.address)
            heads += 1
        assert addresses == sorted(set(addresses)) and int(window['site_va'], 16) in addresses
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    reuse = json.loads((HERE / 'reused_raw.json').read_bytes())
    review = json.loads((TOPIC / 'function_review.json').read_bytes())
    assert formal['disk_sha256'] == review['disk_sha256'] == EXPECTED
    assert formal['source_sha256'] == sha(HERE / 'bounded_raw.json')
    assert len(formal['functions']) == len(raw['functions']) == 5
    for n, (f, g) in enumerate(zip(raw['functions'], formal['functions'])):
        assert g['source'] == dict(path='证据/bounded_raw.json', sha256=formal['source_sha256'],
                                   json_pointer='/functions/' + str(n))
        assert g['va'] == f['seed_va'] and g['end_va'] == f['end_va']
        assert all(g[k] == f[k] for k in ('name', 'pseudocode', 'decompile_error'))
        assert g['assembly'] == [dict(va=a['site_va'], text=a['text'], is_code=a['is_code']) for a in f['assembly']]
        assert g['chunk_byte_ranges'] == [dict(va=b['start_va'], **{k:v for k,v in b.items() if k != 'start_va'})
                                          for b in f['chunk_byte_ranges']]
        assert g['declared_chunks'] == [dict(start_va=b['start_va'], end_va=hex(int(b['start_va'], 16) + b['size']),
                                             is_main=b['start_va'] == f['seed_va']) for b in f['chunk_byte_ranges']]
    assert len(reuse['records']) == 16
    for row in reuse['records']:
        original = source(row['source'], HERE)
        assert original == row['original_record']
        recursive(original)
        if original.get('chunk_byte_ranges'):
            decoded = [i for b in original['chunk_byte_ranges'] for i in decode(b)]
            assert [i.address for i in decoded] == [int(a['va'], 16) for a in original['assembly']]
        elif row['va'] == '0x627450':
            block = bytes.fromhex(original['bytes'])
            va, end = int(original['address'], 16), int(original['end'], 16)
            assert disk(va, len(block)) == block and va + len(block) == end
            decoded = list(cs.disasm(block, va))
            assert sum(i.size for i in decoded) == len(block)
            assert [i.address for i in decoded] == [int(a[0], 16) for a in original['assembly'] if va <= int(a[0], 16) < end]
            sites.update({i.address:i for i in decoded})
        elif row['va'] == '0x6aad70':
            assert original['assembly'] and all(isinstance(a, str) for a in original['assembly'])
            assert not any(k in original for k in ('declared_chunks', 'chunk_byte_ranges', 'byte_ranges'))
    anchors = 0
    assert len(review['functions']) == 5 and len(review['reused_reviews']) == 3
    for row in review['functions'] + review['reused_reviews']:
        assert row['status'] == '局部语义已审阅' and row['conclusion'] and row['unknown']
        assert row['fresh_evidence'] == (int(row['va'], 16) in FRESH)
        ref, = row['source_records']
        record = source(ref, TOPIC)
        assert row['declared_chunks'] == record['declared_chunks']
        assert row['original_byte_ranges'] == record['chunk_byte_ranges']
        assert len(row['anchors']) == len(record['assembly'])
        for a, head in zip(row['anchors'], record['assembly']):
            assert a['path'] == ref['path'] and a['pointer'].startswith(ref['pointer'] + '/assembly/')
            assert source(dict(ref, pointer=a['pointer']), TOPIC) == a['value'] == head['text']
            assert a['site_va'] == head['va'] and int(a['site_va'], 16) in sites
            anchors += 1
    semantic = {
        0x6A4DE6: ('mov', 'dword ptr [edx + eax + 4], 0'),
        0x6A4DFD: ('mov', 'dword ptr [edx + eax + 0x60], 0'),
        0x6A4E14: ('mov', 'dword ptr [edx + eax + 0x78], 0'),
        0x6A4E32: ('jae', '0x6a4e67'),
        0x6A4E46: ('mov', 'dword ptr [ecx + eax*4 + 0x64], 0xffffffff'),
        0x6A4E60: ('mov', 'byte ptr [ecx + eax + 0x74], 0'),
        0x6A4EFB: ('cmp', 'dword ptr [eax + 0x7c], 0'),
        0x6A4F31: ('mov', 'ecx, 0x16'),
        0x6A4F36: ('rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
        0x6A5018: ('jle', '0x6a502d'),
        0x6A506C: ('jge', '0x6a509b'),
        0x6A50DA: ('jge', '0x6a5120'),
        0x6A5136: ('and', 'edx, 0x800'),
        0x6A513C: ('neg', 'edx'),
        0x6A513E: ('sbb', 'edx, edx'),
        0x6A5140: ('neg', 'edx'),
        0x6A5222: ('mov', 'esi, dword ptr [edx + 0x7c]'),
        0x6A5238: ('mov', 'ecx, 0x16'),
        0x6A523D: ('rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
        0x6AB2A4: ('movsx', 'ecx, word ptr [eax + 2]'),
        0x6AB2C2: ('jne', '0x6ab302'),
        0x6A6E65: ('jge', '0x6a6e90'),
        0x6A6E6D: ('mov', 'edx, dword ptr [ecx + eax*4 + 0x64]'),
        0x6A6E82: ('mov', 'ecx, dword ptr [eax + 0x2c]'),
        0x6AAD97: ('movsx', 'ecx, word ptr [eax + 2]'),
        0x6AAE01: ('mov', 'dword ptr [edx + 0x5e0], ecx'),
        0x6AAE0A: ('mov', 'byte ptr [eax + 0x4f4], 0'),
        0x6ADEE3: ('and', 'ecx, 0xfff'),
        0x6ADF27: ('movsx', 'eax, word ptr [edx + 2]'),
        0x6ADF1B: ('mov', 'byte ptr [ecx + 0x4f4], 1'),
        0x6ADFB8: ('mov', 'dword ptr [edx + ecx*4], eax'),
        0x6A574D: ('mov', 'ecx, dword ptr [edx + 0x534]'),
        0x6A58BB: ('cmp', 'dword ptr [ebp - 0x5ec], 0x10'),
        0x6A58CD: ('movzx', 'eax, byte ptr [edx]'),
        0x6A58D9: ('movzx', 'edx, byte ptr [ecx]'),
        0x64F211: ('add', 'eax, 0x64'),
        0x69369A: ('mov', 'eax, dword ptr [ecx + edx*4]'),
        0x82B191: ('movsx', 'eax, word ptr [ebp + 0xe]'),
        0x82B22B: ('movsx', 'eax, word ptr [ebp + 0xe]'),
        0x82B26C: ('movsx', 'eax, word ptr [ebp + 0xe]'),
        0x64CDE3: ('je', '0x64ce18'),
        0x64CE28: ('movsx', 'edx, byte ptr [0xa67342]'),
        0x64CE36: ('mov', 'cl, byte ptr [0xa67343]'),
        0x64CE3C: ('mov', 'byte ptr [eax], cl'),
        0x627480: ('cmp', 'dword ptr [0xa766b4], 0'),
        0x6274D0: ('mov', 'eax, dword ptr [0xa766b4]'),
        0x63E1A5: ('cmp', 'dword ptr [ebp + 8], 3'),
    }
    for va, expected in semantic.items():
        item = sites[va]
        assert (item.mnemonic, item.op_str) == expected, (hex(va), item.mnemonic, item.op_str, expected)
    for f in raw['functions'][:3]:
        assert not any(sites[int(a['site_va'], 16)].mnemonic == 'cld' for a in f['assembly'])
    docs = sorted(TOPIC.glob('*.txt')) + [HERE / '独立审阅.txt']
    for path in docs:
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    result = dict(schema='richonline-independent-record124-writers-1', status='PASS',
                  disk_sha256=EXPECTED, functions=functions, fresh_functions=5, fresh_bytes=1471,
                  fresh_instructions=453, reused_functions=3, current_old_supplement=1,
                  unique_bridges=len(bridges), calls=len(raw['calls']), data_references=19,
                  navigation_window_items=heads, unique_saved_ranges=len(saved), source_files=sources,
                  manifest_anchors=anchors, old_reuse_records=16,
                  semantic_anchors=[dict(va=hex(va), mnemonic=p[0], operands=p[1]) for va,p in semantic.items()],
                  bound_files={str(p.relative_to(TOPIC)).replace('\\', '/'): sha(p) for p in docs +
                               [TOPIC/'function_review.json'] + sorted(HERE.glob('*.py')) +
                               [HERE/n for n in ('bounded_raw.json', 'reused_6AAD70_current.json',
                                                'formal_functions.json', 'reused_raw.json')]},
                  boundary='静态局部终审；旧入口当前补证不计新入口；导航不计完整owner；不证明生产容量释放或动态闭环')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status=result['status'], fresh=5, bytes=1471, instructions=453, bridges=40)


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
