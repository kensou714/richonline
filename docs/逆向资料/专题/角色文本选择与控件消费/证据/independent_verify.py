"""第二十六批角色选择与控件消费独审；只读当前PE及冻结原证。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'd3f6cc36649f163aab76931e1fa8b62573be4027e6f57f7a5cdc06764df053a6'
FRESH = {0x6f4db0, 0x7014a0}
REUSED = {0x756460, 0x762e10}
FINAL_SHA = {
    '00_有限采证实施计划.txt': 'c1a61fbf9ea31f415b2463dd2f6ec6062dc020b2ebe867227c8d0d599231692f',
    '01_候选纠偏与三根对象.txt': 'a819ad01953f2b85ecab4f006fcff95fc40cc702431fb9118a3cc2c83f405785',
    '02_类别门与首个角色标记.txt': 'e797cff914cd7b674f653593238c71a91132d066c17730b96d0b9c8c3efff955',
    '03_图像索引与控件状态写入.txt': '21a9ecb5c5518f33d5238c203905073c5b7f68e92e203e04dae6a50f010df7c4',
    '04_两个消费者与参数窗口.txt': 'd5a22f9537a965ecaeebe5247652bc5d1c9f84fc7d244e36260ea23f5aa143c6',
    '05_覆盖分级与扩展边界.txt': 'f39fe76482cebbf20c3d158318547c881f5f3b85797ab40de344759f5aead9c3',
    '函数审阅清单.json': '594e2f43ce190fabed14715a6d70e21f5508fa0a3bf9306941fe139b3c891afc',
    '独立审阅.txt': 'b8241b6644afcadb0a4544c6d49194979a55b541de0e5dfb7f020ad4444d4fb8',
    '独立语义复核.txt': '5519cf3498c2fe79cc221b772f540068822c779184ba94cb1d1116572e233b90',
    '证据/adapt_sources.py': 'cbd96cf8881f38de0356ded52715587a7561cd9b1a0e2cc8f9802183f3f6adcb',
    '证据/bounded_raw.json': 'd3f6cc36649f163aab76931e1fa8b62573be4027e6f57f7a5cdc06764df053a6',
    '证据/build_review.py': 'a2fcd40b9a520c0ab8f56aa06898245f801524bf2fbd317c255be5a48b1f9f83',
    '证据/export_bounded.py': '8914ffff3f74e3540a333cf25726a1b2564fc097e9766b592c4ac0d685d7d00b',
    '证据/export_switch_table.py': '4dd1dd96f20403de9a95e9d19278ffa7f30efc6314d53d7cea3cf811cbb4ddcd',
    '证据/formal_functions.json': '365300c20dce7d90fd25a652677bec3e143f5f2f526a5ab087417f01d034577f',
    '证据/reused_functions.json': '905c67634ccdcaf66d4c9aff87b6399a23df9bed3c3241be68a3be88ff437cb4',
    '证据/review_assembly.txt': 'adea97bbef4d2da0924cc852e19ca6f3bf05ea3a37885ee2056a7c488357fca5',
    '证据/switch_table/bounded_raw.json': '25276eb641a8410d9e838037e24da54dfd5ab813254261625f221924b059bfcc',
    '证据/validate_current.py': '2467952b7d95ffb622067fa67992e7075705a4fe85bc82ba6eb3fee0b9cb4adf',
    '证据/validation.json': '1706e7068f65581002601b46c9f61113037ab6a26e376091a6ba3510c282a381',
}
DEPENDENCIES = (
    ('业务提示与期限映射/证据/followups.json', 1, 0x627c20),
    ('业务提示与期限映射/证据/followups.json', 3, 0x6dba40),
    ('TeachMode对象与消费者/证据/teachmode_raw.json', 18, 0x6276a0),
    ('TeachMode对象与消费者/证据/teachmode_raw.json', 19, 0x627760),
    ('TeachMode对象与消费者/证据/teachmode_raw.json', 87, 0x6fa7f0),
    ('Avatar配置与角色图片/证据/supplement_raw.json', 2, 0x646590),
    ('角色与精灵动画/证据/角色精灵_依赖原证.json', 1, 0x646610),
    ('控件图像状态记录/证据/functions_raw.json', 1, 0x8e1c70),
)
ANCHORS = {
    0x6f4dcb: 'call 0x602890', 0x6f4dda: 'call 0x6033bc',
    0x6f4ddf: 'cmp eax, 2', 0x6f4de2: 'je 0x6f4df5',
    0x6f4deb: 'call 0x6033bc', 0x6f4df0: 'cmp eax, 7',
    0x6f4df3: 'jne 0x6f4e52', 0x6f4e1c: 'jge 0x6f4e52',
    0x6f4e21: 'push ecx', 0x6f4e25: 'push edx',
    0x6f4e26: 'mov ecx, dword ptr [ebp - 4]',
    0x6f4e29: 'call 0x61059e', 0x6f4e2e: 'movzx eax, al',
    0x6f4e33: 'jne 0x6f4e37', 0x6f4e37: 'push -1',
    0x6f4e3c: 'add ecx, 0x28', 0x6f4e40: 'push 0x2f',
    0x6f4e42: 'push 0xa', 0x6f4e44: 'call 0x60554a',
    0x6f4e4b: 'call 0x60f3b5', 0x6f4e50: 'jmp 0x6f4e55',
    0x6f4e52: 'or eax, 0xffffffff', 0x6f4e62: 'ret',
    0x7014b1: 'imul eax, eax, 0x468',
    0x7014ba: 'mov edx, dword ptr [ecx]',
    0x7014bc: 'mov eax, dword ptr [edx + eax + 0xc]',
    0x7014c3: 'ret 4',
    0x756498: 'mov eax, dword ptr [edx]',
    0x75649a: 'mov dword ptr [ecx + 0x48], eax',
    0x7564a3: 'mov eax, dword ptr [edx + 4]',
    0x7564a6: 'mov dword ptr [ecx + 0x4c], eax',
    0x75663a: 'mov eax, dword ptr [edx + 0x4c]',
    0x75663e: 'call 0x60bfdf',
    0x756646: 'push eax', 0x756649: 'push 7',
    0x756658: 'call 0x60bb48', 0x75666c: 'ret 4',
    0x762e3a: 'movzx ecx, byte ptr [eax + 0x64]',
    0x762e40: 'je 0x76308f', 0x762e52: 'movzx edx, al',
    0x762e57: 'je 0x76308f', 0x762e60: 'mov byte ptr [eax + 0x64], 0',
    0x762ea4: 'mov edx, dword ptr [ecx + 0x5c]',
    0x762eaa: 'mov ecx, dword ptr [eax + 0x60]',
    0x762ead: 'mov edx, dword ptr [edx + ecx*4 + 4]',
    0x762f9c: 'movsx edx, byte ptr [edx + ecx + 0x50]',
    0x762fcc: 'call 0x60bfdf', 0x762fd4: 'push eax',
    0x762fd7: 'push 0xc3', 0x762fe9: 'call 0x60bb48',
    0x76314d: 'xor eax, eax', 0x76315d: 'ret 4',
    0x627ca0: 'mov eax, dword ptr [0xa766e0]', 0x627cbc: 'ret',
    0x62771d: 'mov eax, dword ptr [0xa766d0]', 0x627739: 'ret',
    0x6277e0: 'mov eax, dword ptr [0xa766b0]', 0x6277fc: 'ret',
    0x6465a1: 'mov eax, dword ptr [eax]',
    0x646621: 'imul eax, eax, 0x468',
    0x64662c: 'mov eax, dword ptr [edx + eax + 0x14]',
    0x646633: 'mov al, byte ptr [eax + ecx]', 0x646639: 'ret 8',
    0x6dba67: 'cmp dword ptr [ebp - 0x10], 0xb',
    0x6dba6b: 'ja 0x6dbda1', 0x6dba74: 'jmp dword ptr [ecx*4 + 0x6dbdb4]',
    0x6dbac9: 'cmp ecx, dword ptr [eax + 0x3abfc]',
    0x6dbacf: 'jge 0x6dbafc', 0x6dbad5: 'jl 0x6dbafc',
    0x6dbadb: 'jge 0x6dbafc', 0x6dbae0: 'imul edx, edx, 0x4b0',
    0x6dbae9: 'add edx, dword ptr [eax + 0x3ac00]',
    0x6dbaf2: 'imul ecx, ecx, 0xc', 0x6dbaf5: 'mov edx, dword ptr [edx + ecx + 4]',
    0x6dbdb1: 'ret 0x10',
    0x6fa802: 'push 0', 0x6fa807: 'add ecx, 0xa4',
    0x6fa811: 'call 0x60da8d', 0x6fa823: 'ret 4',
    0x8e1c85: 'lea ebx, [ecx + eax*8 + 0x18]',
    0x8e1c91: 'cmp eax, -1', 0x8e1c9c: 'mov eax, dword ptr [edx + 0x2c]',
    0x8e1ca5: 'call eax', 0x8e1caa: 'mov dword ptr [ebx], ebp',
    0x8e1cac: 'mov al, byte ptr [edi + 0x181]',
    0x8e1cb6: 'mov al, byte ptr [edi + 0x180]',
    0x8e1cd5: 'call 0x6033ee', 0x8e1cde: 'ret 0xc',
}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(image) == PE_SHA
    nt = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt + 24)[0] == 0x10b
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, nt + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions, bridges, sources, ranges, assembly = {}, {}, {}, set(), []

    def read(va, size):
        offsets = [off + va - base - rva for _, rva, length, off in sections
                   if rva <= va - base and va - base + size <= rva + length]
        assert len(offsets) == 1
        return image[offsets[0]:offsets[0] + size]

    def load(path):
        payload = path.read_bytes()
        sources[str(path.relative_to(ROOT))] = digest(payload)
        return json.loads(payload)

    def pointer(value, path):
        for part in path.strip('/').split('/'):
            part = part.replace('~1', '/').replace('~0', '~')
            value = value[int(part)] if isinstance(value, list) else value[part]
        return value

    def audit(chunk):
        va = int(chunk.get('start_va', chunk.get('va')), 16)
        b = read(va, chunk['size'])
        assert b.hex() == chunk['disk_hex'] == chunk.get('idb_hex', chunk.get('ida_hex'))
        assert chunk.get('matching', chunk.get('equal')) is True
        assert 'sha256' not in chunk or digest(b) == chunk['sha256']
        ranges.add((va, len(b)))
        return va, b

    def code(chunk):
        va, b = audit(chunk)
        decoded = list(decoder.disasm(b, va))
        assert sum(i.size for i in decoded) == len(b)
        for i in decoded:
            assert instructions.setdefault(i.address, i).bytes == i.bytes
        return decoded

    def scan(value):
        if isinstance(value, dict):
            if {'size', 'disk_hex'} <= value.keys() and value['disk_hex'] is not None:
                audit(value)
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    raw = load(HERE / 'bounded_raw.json')
    assert digest((HERE / 'bounded_raw.json').read_bytes()) == RAW_SHA
    assert raw['disk_sha256'] == PE_SHA and raw['schema'] == 'richonline-bounded-preparation-1'
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    assert {int(f['seed_va'], 16) for f in raw['reused_seeds']} == REUSED
    scan(raw)
    assert raw['strings'] == [] and raw['data_windows'] == []
    for ref in raw['reuse_sources']:
        path = DOCS / ref['path']
        assert digest(path.read_bytes()) == ref['source_sha256']
        sources[str(path.relative_to(ROOT))] = ref['source_sha256']
    old = load(DOCS / '专题/业务提示与期限映射/证据/callers.json')
    functions = {int(f['seed_va'], 16): f for f in raw['functions']}
    for va, index in [(0x756460, 16), (0x762e10, 19)]:
        f = old['functions'][index]
        assert int(f['va'], 16) == va
        functions[va] = f
    current = {int(f['seed_va'], 16): f['chunk_byte_ranges'] for f in raw['current_chunk_audits']}
    assert set(current) == set(functions) == FRESH | REUSED
    rows = []
    for va, f in functions.items():
        chunks = f.get('chunk_byte_ranges', f.get('byte_ranges'))
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in current[va]]
        body = [i for c in chunks for i in code(c)]
        assert len(body) == len(f['assembly'])
        assert {i.address for i in body} == {int(a.get('site_va', a.get('va')), 16) for a in f['assembly']}
        calls = {i.address: int(i.op_str, 16) for i in body if i.mnemonic == 'call' and i.op_str.startswith('0x')}
        reported = [c for c in raw['calls'] if int(c['seed_va'], 16) == va]
        assert set(calls) == {int(c['site_va'], 16) for c in reported}
        for c in reported:
            target = calls[int(c['site_va'], 16)]
            assert target == int(c['target_va'], 16)
            for address in c['bridges']:
                assert target == int(address, 16)
                b = read(target, 5)
                assert b[0] == 0xe9
                destination = target + 5 + struct.unpack_from('<i', b, 1)[0]
                assert bridges.setdefault(target, destination) == destination
                target = destination
            assert target == int(c['implementation_va'], 16)
        rows.append(dict(seed_va=hex(va), reused=va in REUSED, byte_count=sum(c['size'] for c in chunks),
                         chunks=len(chunks), instruction_count=len(body), direct_calls=len(calls)))
        assembly.extend(['// 主体 ' + hex(va)] + ['// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    for c in raw['verified_direct_bridges']:
        ins = code(c)
        assert len(ins) == 1 and ins[0].mnemonic == 'jmp'
        assert int(ins[0].op_str, 16) == int(c['target_va'], 16)
        assert bridges.setdefault(ins[0].address, int(c['target_va'], 16)) == int(c['target_va'], 16)
    assert len(bridges) == len(raw['verified_direct_bridges'])
    windows = raw['explicit_owner_windows'] + [e['owner_window'] for edges in raw['incoming'].values() for e in edges if 'owner_window' in e]
    unique_windows = set()
    for w in windows:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        body = []
        for row in w['assembly']:
            ins = code(row['bytes'])
            assert len(ins) == 1 and ins[0].address == int(row['site_va'], 16)
            body.extend(ins)
        assert int(w['site_va'], 16) in {i.address for i in body}
        assert all(a.address + a.size == b.address for a, b in zip(body, body[1:]))
        unique_windows.add((w['owner_va'], w['site_va'], hex(body[0].address), hex(body[-1].address + body[-1].size)))
        assembly.extend(['// 窗口 ' + w['site_va']] + ['// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    dependency_rows = []
    for name, index, va in DEPENDENCIES:
        f = load(DOCS / '专题' / name)['functions'][index]
        assert int(f.get('va', f.get('address')), 16) == va
        chunks = f.get('chunk_byte_ranges', f.get('chunks', f.get('byte_ranges')))
        body = []
        for c in chunks:
            if 'bytes_hex' in c:
                start, end = int(c['start'], 16), int(c['end'], 16)
                b = read(start, end - start)
                assert b.hex() == c['bytes_hex'] and digest(b) == c['sha256'].lower()
                c = dict(va=hex(start), size=len(b), disk_hex=b.hex(), idb_hex=b.hex(), matching=True,
                         sha256=digest(b))
            body.extend(code(c))
        declared = f.get('assembly', f.get('instructions'))
        assert len(body) == len(declared)
        assert {i.address for i in body} == {int(r.get('va', r.get('ea')), 16) for r in declared}
        dependency_rows.append(dict(owner_va=hex(va), source=name, json_pointer='/functions/' + str(index),
                                    byte_count=sum(i.size for i in body), instruction_count=len(body)))
        assembly.extend(['// 有限依赖 ' + hex(va)] + ['// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    table_path = HERE / 'switch_table/bounded_raw.json'
    assert digest(table_path.read_bytes()) == '25276eb641a8410d9e838037e24da54dfd5ab813254261625f221924b059bfcc'
    table_raw = load(table_path)
    assert table_raw['disk_sha256'] == PE_SHA and table_raw['seeds'] == table_raw['functions'] == []
    assert len(table_raw['data_windows']) == 1
    table_va, table_bytes = audit(table_raw['data_windows'][0])
    assert table_va == 0x6dbdb4 and len(table_bytes) == 48
    switch_destinations = struct.unpack('<12I', table_bytes)
    assert switch_destinations[10] == 0x6dbabd and all(va in instructions for va in switch_destinations)
    adapted_rows = []
    adapted_by_va = {}
    for filename, expected_vas in [('formal_functions.json', FRESH),
                                   ('reused_functions.json', REUSED | {v for _, _, v in DEPENDENCIES})]:
        adapted = load(HERE / filename)
        assert adapted['disk_sha256'] == PE_SHA
        assert {int(f['va'], 16) for f in adapted['functions']} == expected_vas
        for row in adapted['functions']:
            path = DOCS / row['source_path']
            payload = path.read_bytes()
            assert digest(payload) == row['source_sha256']
            original = pointer(load(path), row['source_pointer'])
            expected = dict(original)
            va = original.get('seed_va', original.get('va', original.get('address')))
            chunks = original.get('chunk_byte_ranges', original.get('chunks', original.get('byte_ranges')))
            declared_assembly = original.get('assembly', original.get('instructions'))
            expected.update(va=va, source_path=row['source_path'], source_pointer=row['source_pointer'],
                source_sha256=digest(payload), adaptation_scope=row['adaptation_scope'],
                source_field_pointers={k: row['source_pointer'] + '/' + k for k in original},
                normalized_chunks=[dict(start_va=c.get('start_va', c.get('va', c.get('address'))),
                    **{k: v for k, v in c.items() if k not in ('start_va', 'va', 'address')}) for c in chunks],
                normalized_assembly=[dict(site_va=a.get('site_va', a.get('va', a.get('address'))),
                    text=a['text'], is_code=a.get('is_code', True), original=a) for a in declared_assembly])
            if 'declared_chunks' not in expected:
                expected['declared_chunks'] = [dict(start_va=c['start_va'],
                    end_va=hex(int(c['start_va'], 16) + c['size']), is_main=c['start_va'] == va)
                    for c in expected['normalized_chunks']]
            if 'byte_ranges' not in expected:
                expected['byte_ranges'] = chunks
            assert row == expected
            body = [i for c in row['normalized_chunks'] for i in code(c)]
            assert len(body) == len(row['normalized_assembly'])
            assert {i.address for i in body} == {int(a['site_va'], 16) for a in row['normalized_assembly']}
            adapted_rows.append(dict(owner_va=va, source=row['source_path'], json_pointer=row['source_pointer']))
            adapted_by_va[int(va, 16)] = row
    helper = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
    assert load(HERE / 'formal_functions.json')['adapter_helper_sha256'] == digest(helper.read_bytes())
    sources[str(helper.relative_to(ROOT))] = digest(helper.read_bytes())
    historical_bridges = []
    for name, expected_sha, index, va, destination in [
        ('TeachMode对象与消费者/证据/bridge_raw.json',
         '2eb16206077a4ab8a8bda6a156eb258340b3a0e2dde8bc353e8b0fd8fa2134c2', 160, 0x60da8d, 0x8e1c70),
        ('控件图像状态记录/证据/navigation.json',
         'bab759c529d90bc714224d1cbf584ac8e57c3b629a64a81860dcd1bd7a41322a', 10, 0x6033ee, 0x8e2200),
    ]:
        path = DOCS / '专题' / name
        assert digest(path.read_bytes()) == expected_sha
        row = load(path)['bridges'][index]
        assert int(row['va'], 16) == va and row['size'] == 5
        payload = read(va, 5)
        assert payload.hex() == row['idb_hex']
        if 'disk_hex' in row:
            assert row['disk_hex'] == payload.hex() and row['equal'] is True
        assert payload[0] == 0xe9
        assert va + 5 + struct.unpack_from('<i', payload, 1)[0] == int(row['target'], 16) == destination
        historical_bridges.append(dict(site_va=hex(va), target_va=hex(destination),
            bytes_hex=payload.hex(), source=name, json_pointer='/bridges/' + str(index), source_sha256=expected_sha))
    ledger = load(HERE.parent / '函数审阅清单.json')
    assert ledger['disk_sha256'] == PE_SHA
    assert {int(f['va'], 16) for f in ledger['functions']} == FRESH | REUSED
    assert {int(f['va'], 16) for f in ledger['historical_contracts']} == {v for _, _, v in DEPENDENCIES}
    author_anchor_count = 0
    for row in ledger['functions'] + ledger['historical_contracts']:
        va = int(row['va'], 16)
        assert row['status'] == ('完整分析' if va in FRESH else '部分分析' if va in REUSED else '复用局部契约')
        ref = row['evidence_ref']
        source = pointer(load(HERE / ref['file']), ref['pointer'])
        assert source == adapted_by_va[va]
        assert row['source_sha256'] == source['source_sha256']
        assert row['declared_chunks'] == source['declared_chunks']
        assert row['instruction_count'] == len(source['normalized_assembly'])
        for anchor in row['semantic_anchors']:
            ins = instructions[int(anchor['va'], 16)]
            assert all(token in ins.mnemonic + ' ' + ins.op_str for token in anchor['tokens'])
            author_anchor_count += 1
    assert ledger['summary'] == dict(reviewed_functions=4, complete=2, partial=2,
        reviewed_instructions=527, historical_contracts=8, historical_contract_instructions=484,
        owner_windows=2, direct_bridges=32)
    assert len(ledger['owner_windows']) == 2
    for row in ledger['owner_windows']:
        original = pointer(raw, row['evidence_ref']['pointer'])
        assert row['owner_va'] == original['owner_va'] and row['site_va'] == original['site_va']
        assert row['start_va'] == original['assembly'][0]['site_va']
        last = original['assembly'][-1]
        assert int(row['end_va'], 16) == int(last['site_va'], 16) + last['bytes']['size']
    # 模拟中央显式记录入口，避免独审数据被误算为额外完成函数。
    import runpy
    walk = runpy.run_path(str(DOCS / '全量分析/merge_reviews.py'))['walk']
    explicit_records = []
    for path in HERE.parent.rglob('*.json'):
        for row, ptr in walk(json.loads(path.read_text('utf-8-sig'))):
            address = row.get('va', row.get('address', row.get('ea', row.get('地址'))))
            status = row.get('status', row.get('review_status', row.get('状态')))
            conclusion = row.get('conclusion', row.get('结论'))
            if address is not None and isinstance(status, str) and isinstance(conclusion, str):
                explicit_records.append((path.relative_to(HERE.parent).as_posix(), ptr, address, status))
    assert len(explicit_records) == 12
    assert all(row[0] == '函数审阅清单.json' for row in explicit_records)
    semantic = []
    for va, expected in ANCHORS.items():
        i = instructions[va]
        actual = (i.mnemonic + ' ' + i.op_str).rstrip()
        assert actual == expected, (hex(va), expected, actual)
        semantic.append(dict(site_va=hex(va), text=actual, bytes_hex=i.bytes.hex()))
    final = {}
    for name, expected in FINAL_SHA.items():
        actual = digest((HERE.parent / name).read_bytes())
        assert actual == expected, (name, '终稿改变，须重新独审')
        final[name] = actual
    for path in HERE.parent.rglob('*.txt'):
        assert all((not line.strip() or line.startswith('//')) and '\t' not in line
                   and line == line.rstrip() for line in path.read_text('utf-8').splitlines())
    result = dict(status='PASS' if FINAL_SHA else '原证预核通过；完整依赖语义和作者终稿待核', pe_sha256=PE_SHA,
        raw_sha256=RAW_SHA, functions=rows, sources=sources, original_window_count=len(windows),
        unique_windows=sorted(unique_windows), unique_bridges=len(bridges), unique_byte_ranges=len(ranges),
        semantic_anchors=semantic, reviewed_final_sha256=final,
        finite_dependencies=dependency_rows,
        exact_adaptations=adapted_rows,
        historical_bridges=historical_bridges, author_semantic_anchor_count=author_anchor_count,
        explicit_record_count=len(explicit_records),
        resource_switch=dict(table_va=hex(table_va), destinations=[hex(v) for v in switch_destinations],
                             case10_site_va='0x6dbddc', case10_target_va='0x6dbabd'),
        boundary='两新函数完整局部契约、两旧消费者部分路径、八helper局部复用分别核验；没有客户端动态验证')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(line.rstrip() for line in assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = verify()
    print(result['status'], len(result['functions']), result['unique_bridges'])
