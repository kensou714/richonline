"""角色档案专题独立PE/Capstone复核；不调用IDA和作者验证器。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x7f2c20, 0x7f2c40, 0x7f2c90, 0x629750, 0x6a25a0, 0x7f35f0, 0x7f3630}
REUSED = {0x6276a0, 0x6b7930, 0x646590}
FINAL_SHA = {
    '00_有限采证实施计划.txt': 'd4748d357286290eb3409c8899c4a31a70b94f6012ccb2efa997da05bd1ee98b',
    '01_对象与记录布局.txt': 'ee14d81e3bcfbb4025011cc546b29ad6fe7f5b32c97f53ae6b562f6c94dc1d7a',
    '02_装载与索引边界.txt': '59842153c1e14905d2df5cfb856055e1d79ecf44fe2e22aec53ce8042f499e16',
    '03_字段消费与资源查询.txt': '449874cf2c97fe0516a5bb4b577b847ba098dc957784035996ed654a7a3f20ce',
    '04_证据与复核边界.txt': 'b9316ec943e5314c53d1bdd58de12793aa55c34705277388ae57e30023d24fd2',
    '05_当前资源概览.txt': 'de0360e8caaa636f0ee93ec8286bcb5cf57afc033619dadf8ed01436e1facff9',
    '06_当前资源文本对照.txt': '15b975316031328ca1965d17099c5cf58247512bc2e7a8699b47f9a0499615da',
    '函数审阅清单.json': '87eb66ac680873a4e3a42ef7036846d47eb51a4d4e3eebcbb0926886cedfb12a',
    '验证结果.json': '9ded0a237825ff35fbabee3821c70a5d89ee7667fa38f90b0c1969e48e1b5e6d',
    '证据/bounded_raw.json': '857d4958176ff522951d3599c12198a96928b23b7a3811f723ec03133591fd69',
    '证据/constructor_callback_raw.json': 'd39f08cab6741a3c494dbdc8637348b6765c3be93f0e04813fee9d381df3d425',
    '证据/formal_functions.json': '8f7dd9e269f8484a2dfe3dd70dd3b197ef416383e84ab522452f3c54bd99ec51',
    '证据/reused_audit.json': 'dcbad9a72feda9b2904d9e2dd22e22be19e8dbf9ba61f37983ab494e39ae38a9',
    '证据/bounded_audit.json': 'c195f48f007a81b7c6247a030b8b0eb689e146dffb43d2bdaa9bf59d92740b3a',
    '证据/verify_bounded.py': '579bf1dbbb0d4d740c78df5096e370a1e37db456171a593e615749e591be3c1a',
    '证据/resource_audit.py': 'fc04a11bb912bddb9bfac33072dbf4acc1cfa3c303d18df91b3101231051a43e',
    '证据/resource_audit.json': '75267af1f79b1cd78a096680f735cd0014c96df61cd99a4257e21fcb015dea4e',
}
ANCHORS = {
    0x7f2c31: 'mov dword ptr [eax + 4], 0',
    0x7f2c78: 'mov dword ptr [ecx + 4], 0',
    0x7f2d6f: 'mov dword ptr [ecx], 0',
    0x7f2dca: 'jle 0x7f2dd4',
    0x7f2dd2: 'mov dword ptr [eax], ecx',
    0x7f2ddb: 'add eax, 1',
    0x7f2e03: 'imul ecx, ecx, 0xc84',
    0x7f2e25: 'push 0x6022cd',
    0x7f2e73: 'mov dword ptr [eax + 4], ecx',
    0x7f2ed8: 'imul edx, edx, 0xc84',
    0x7f2ee7: 'mov byte ptr [ecx + edx + 0xc80], al',
    0x7f2f33: 'mov dword ptr [ecx + edx], eax',
    0x7f2f46: 'push 0x10',
    0x7f2fea: 'mov byte ptr [edx + eax + 0xc81], 0',
    0x7f301d: 'mov byte ptr [ecx + edx + 0xc81], 1',
    0x7f306a: 'mov dword ptr [edx + ecx + 0x14], eax',
    0x7f30aa: 'jne 0x7f30ae',
    0x7f30ac: 'jmp 0x7f30f5',
    0x7f30e6: 'mov dword ptr [ecx + edx*4 + 0x18], eax',
    0x7f3475: 'push 0xc8',
    0x7f34ac: 'push 0x320',
    0x7f2bee: 'push 0xc84',
    0x7f2bf3: 'push 0',
    0x7f2c04: 'mov byte ptr [ecx + 0xc80], 0xff',
    0x6465a1: 'mov eax, dword ptr [eax]',
    0x6b794d: 'movsx eax, byte ptr [edx + eax + 0xc81]',
    0x629769: 'and eax, 1',
    0x6a25ba: 'mov ecx, dword ptr [eax + 0x28]',
    0x7f3600: 'push 9',
    0x7f3606: 'push 8',
    0x7f3640: 'push 0xa',
    0x7f3646: 'push 8',
    0x622d57: 'sub eax, 1',
    0x622d5d: 'js 0x622d79',
    0x622d64: 'call dword ptr [ebp + 0x14]',
    0x622d71: 'add ecx, dword ptr [ebp + 0xc]',
    0x693691: 'mov ecx, dword ptr [eax + 0x4d4]',
    0x69369a: 'mov eax, dword ptr [ecx + edx*4]',
    0x6dbd36: 'cmp dword ptr [ebp + 0xc], 0',
    0x6dbd3a: 'jl 0x6dbd75',
    0x6dbd42: 'cmp ecx, dword ptr [eax + 0x3abec]',
    0x6dbd48: 'jge 0x6dbd75',
    0x6dbd4a: 'cmp dword ptr [ebp + 0x10], 0',
    0x6dbd50: 'cmp dword ptr [ebp + 0x10], 0x64',
    0x6dbd59: 'imul edx, edx, 0x4b0',
    0x6dbd62: 'add edx, dword ptr [eax + 0x3abf0]',
    0x6dbd6b: 'imul ecx, ecx, 0xc',
    0x6dbd6e: 'mov edx, dword ptr [edx + ecx + 4]',
    0x819686: 'mov edx, dword ptr [ecx + 0x8c]',
    0x81968c: 'mov dword ptr [eax + 0x90], edx',
    0x819739: 'jne 0x819740',
    0x81973b: 'jmp 0x8198c6',
    0x8198c6: 'xor eax, eax',
    0x819926: 'cmp edx, 0x80',
    0x819977: 'cmp eax, 0xa',
    0x819988: 'mov byte ptr [edx], 0',
    0x8199a7: 'mov byte ptr [ecx], 0xa',
    0x8199cf: 'mov byte ptr [edx], cl',
    0x8199f4: 'cmp edx, dword ptr [ebp + 0xc]',
    0x8199f7: 'jle 0x819a10',
    0x81a0b0: 'mov dword ptr [edx + 0x94], ecx',
    0x81a0c2: 'mov dword ptr [eax + 0x90], edx',
    0x81a0d4: 'mov dword ptr [eax + 0x8c], edx',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def review():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(image) == SHA
    nt = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt + 24)[0] == 0x10b
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, nt + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    sources, instructions, ranges, bridges, assembly = {}, {}, {}, {}, []

    def read(va, size):
        positions = [off + va - base - rva for _, rva, raw, off in sections
                     if rva <= va - base and va - base + size <= rva + raw]
        assert len(positions) == 1 and positions[0] + size <= len(image)
        return image[positions[0]:positions[0] + size]

    def load(path):
        content = path.read_bytes()
        sources[str(path.relative_to(ROOT))] = digest(content)
        return json.loads(content)

    def check(row):
        va = int(row.get('start_va', row.get('va')), 16)
        content = read(va, row['size'])
        assert row.get('matching', row.get('equal')) is True
        assert content.hex() == row['idb_hex'] == row['disk_hex']
        assert 'sha256' not in row or digest(content) == row['sha256']
        ranges[va, len(content)] = dict(start_va=hex(va), size=len(content), sha256=digest(content))
        return va, content

    def code(row):
        va, content = check(row)
        decoded = list(decoder.disasm(content, va))
        assert sum(i.size for i in decoded) == len(content)
        for ins in decoded:
            assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        return decoded

    def bridge(va, target):
        content = read(va, 5)
        assert content[0] == 0xe9 and va + 5 + struct.unpack_from('<i', content, 1)[0] == target
        assert bridges.setdefault(va, target) == target

    raw = load(HERE / 'bounded_raw.json')
    assert raw['disk_sha256'] == SHA and raw['topic'] == HERE.parent.name
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert digest((DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == raw['exporter_sha256']
    assert {int(r['seed_va'], 16) for r in raw['functions']} == FRESH
    assert {int(r['seed_va'], 16) for r in raw['reused_seeds']} == REUSED
    audits = {int(r['seed_va'], 16): r['chunk_byte_ranges'] for r in raw['current_chunk_audits']}
    assert set(audits) == FRESH | REUSED
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert digest(path.read_bytes()) == source['source_sha256']
        sources[str(path.relative_to(ROOT))] = source['source_sha256']
    functions = {int(r['seed_va'], 16): r for r in raw['functions']}
    for filename, addresses in [('TeachMode对象与消费者/证据/teachmode_raw.json', {0x6276a0, 0x6b7930}),
                                ('Avatar配置与角色图片/证据/supplement_raw.json', {0x646590})]:
        old = load(DOCS / '专题' / filename)
        for f in old['functions']:
            if int(f['va'], 16) in addresses:
                functions[int(f['va'], 16)] = f
    assert set(functions) == FRESH | REUSED
    function_rows = []
    for va, function in functions.items():
        chunks = function.get('chunk_byte_ranges', function.get('chunks'))
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in audits[va]]
        for c in chunks:
            check(c)
        decoded = [i for chunk in audits[va] for i in code(chunk)]
        old_assembly = function.get('assembly', function.get('instructions'))
        assert {i.address for i in decoded} == {int(r.get('site_va', r.get('va')), 16) for r in old_assembly}
        assert len(decoded) == len(old_assembly)
        calls = {i.address for i in decoded if i.mnemonic == 'call' and i.op_str.startswith('0x')}
        reported = [c for c in raw['calls'] if int(c['seed_va'], 16) == va]
        assert calls == {int(c['site_va'], 16) for c in reported}
        for call in reported:
            target = int(call['target_va'], 16)
            assert instructions[int(call['site_va'], 16)].op_str == hex(target)
            for thunk in call['bridges']:
                assert target == int(thunk, 16)
                destination = target + 5 + struct.unpack_from('<i', read(target, 5), 1)[0]
                bridge(target, destination)
                target = destination
            assert target == int(call['implementation_va'], 16)
        function_rows.append(dict(seed_va=hex(va), reused=va in REUSED, chunks=len(chunks),
                                  instruction_count=len(decoded), direct_calls=len(calls)))
        assembly.extend(['// 主体 ' + hex(va)] + ['// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    for row in raw['verified_direct_bridges']:
        decoded = code(row)
        assert len(decoded) == 1 and decoded[0].mnemonic == 'jmp'
        bridge(decoded[0].address, int(row['target_va'], 16))
    assert len(bridges) == len(raw['verified_direct_bridges']) == 40
    windows = list(raw['explicit_owner_windows']) + [e['owner_window'] for edges in raw['incoming'].values() for e in edges if 'owner_window' in e]
    unique_windows = {}
    for window in windows:
        if window['owner_va'] is None:
            assert not window['assembly']
            continue
        decoded = []
        for row in window['assembly']:
            current = code(row['bytes'])
            assert len(current) == 1 and current[0].address == int(row['site_va'], 16)
            decoded.extend(current)
        assert int(window['site_va'], 16) in {i.address for i in decoded}
        assert all(a.address + a.size == b.address for a, b in zip(decoded, decoded[1:]))
        key = (window['owner_va'], window['site_va'], decoded[0].address, decoded[-1].address + decoded[-1].size)
        unique_windows[key] = dict(owner_va=key[0], site=key[1], start=hex(key[2]), end=hex(key[3]))
        assembly.extend(['// 调用窗口 ' + window['site_va']] + ['// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    data_rows = []
    for row in raw['data_windows']:
        va, content = check(row)
        if va == 0xa766d0:
            assert content == bytes(4)
        elif va == 0xa69330:
            assert content.hex() == '4ee640bb'
        else:
            assert content[-1:] == b'\0' and b'\0' not in content[:-1]
            data_rows.append(dict(site_va=hex(va), text=content[:-1].decode('ascii'), bytes_hex=content.hex()))
    for row in raw['strings']:
        check(row['byte_audit'])
        payload, width = bytes.fromhex(row['payload_hex']), row['unit_width']
        assert width in (1, 2) and len(payload) % width == 0 and row['nul_hex'] == bytes(width).hex()
        assert row['byte_audit']['idb_hex'] == (payload + bytes(width)).hex()
    dependency = load(HERE / 'constructor_callback_raw.json')
    assert dependency['disk_sha256'] == SHA and len(dependency['functions']) == 1
    callback = dependency['functions'][0]
    assert callback['va'] == '0x7f2be0'
    decoded = [i for c in callback['chunk_byte_ranges'] for i in code(c)]
    assert {i.address for i in decoded} == {int(r['va'], 16) for r in callback['assembly']}
    assert len(decoded) == len(callback['assembly'])
    assert callback['declared_chunks'] == [dict(start_va='0x7f2be0', end_va='0x7f2c1c', is_main=True)]
    for row in dependency['thunks']:
        code(row)
        bridge(int(row['va'], 16), int(row['target'], 16))
    bridge(0x6022cd, 0x7f2be0)
    path_source = load(DOCS / '专题/事件文字记录器/证据/data_audit.json')
    def nested_rows(node):
        if isinstance(node, dict):
            yield node
            for value in node.values():
                yield from nested_rows(value)
        elif isinstance(node, list):
            for value in node:
                yield from nested_rows(value)
    path_row = next(r for r in nested_rows(path_source) if r.get('va') == '0xa22164' and 'disk_hex' in r)
    assert check(path_row)[1] == b'Data\\Role.kpd\0'
    assert instructions[0x623bf2].op_str == '0xa22164'
    assert instructions[0x623bf7].op_str == '0x60e0b4'
    assert instructions[0x623bfe].op_str == '0x606724'
    assert bridges[0x60e0b4] == 0x6276a0 and bridges[0x606724] == 0x7f2c90
    assembly.extend(['// 元素构造回调'] + ['// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    reused_audit = load(HERE / 'reused_audit.json')
    assert reused_audit['disk_sha256'] == SHA
    reuse_rows = []
    for ref in reused_audit['references']:
        path = DOCS / ref['source']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert digest(path.read_bytes()) == ref['source_sha256']
        f = load(path)
        for part in ref['json_pointer'].split('/')[1:]:
            f = f[int(part)] if isinstance(f, list) else f[part]
        assert f['va'] == ref['owner_va']
        chunks = f.get('chunk_byte_ranges', f.get('byte_ranges', f.get('disk_ranges', f.get('chunks'))))
        body = []
        for c in chunks:
            va = int(c.get('start_va', c.get('va')), 16)
            payload = read(va, c['size'])
            assert payload.hex() == c['disk_hex']
            assert 'sha256' not in c or digest(payload) == c['sha256']
            assert 'idb_hex' not in c or c['idb_hex'] == payload.hex()
            assert 'ida_hex' not in c or c['ida_hex'] == payload.hex()
            current = list(decoder.disasm(payload, va))
            assert sum(i.size for i in current) == len(payload)
            body.extend(current)
            for ins in current:
                assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in ref['chunks']]
        for c in ref['chunks']:
            assert int(c['end_va'], 16) == int(c['start_va'], 16) + c['size']
            assert digest(read(int(c['start_va'], 16), c['size'])) == c['sha256']
        old_assembly = f.get('assembly', f.get('instructions'))
        assert {i.address for i in body} == {int(r.get('site_va', r.get('va')), 16) for r in old_assembly}
        assert len(body) == len(old_assembly)
        declared = f.get('declared_chunks')
        if declared is not None:
            assert {(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks} == {
                (int(c['start_va'], 16), int(c['end_va'], 16) - int(c['start_va'], 16)) for c in declared}
        reuse_rows.append(dict(owner_va=f['va'], chunks=len(chunks), instruction_count=len(body),
                              scope='完整字节独立复解码；语义仅角色档案依赖，不新增审阅入口'))
        if int(f['va'], 16) in {0x622d50, 0x693680, 0x6dba40, 0x819470, 0x819660, 0x8198e0, 0x81a090, 0x91f7e0}:
            assembly.extend(['// 依赖限定语义 ' + f['va']] + [
                '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    assert len(reuse_rows) == 26
    assert reused_audit['path'] == dict(source='专题/事件文字记录器/证据/data_audit.json',
        source_sha256=digest((DOCS / '专题/事件文字记录器/证据/data_audit.json').read_bytes()),
        json_pointer='/records/88', address='0xa22164', size=14, text='Data\\Role.kpd', caller_site='0x623bf2')
    callback_audit = reused_audit['callback']
    assert callback_audit['source'] == 'constructor_callback_raw.json'
    assert callback_audit['source_sha256'] == digest((HERE / callback_audit['source']).read_bytes())
    assert callback_audit['json_pointer'] == '/functions/0'
    assert callback_audit['argument_source_pointer'] == '/data_references/7' and callback_audit['argument_site'] == '0x7f2e25'
    assert raw['data_references'][7]['site_va'] == '0x7f2e25'
    for c in callback_audit['chunks']:
        assert digest(read(int(c['start_va'], 16), c['size'])) == c['sha256']
    cb_bridge = callback_audit['bridge_current_pe']
    assert cb_bridge['disk_hex'] == read(0x6022cd, 5).hex() and cb_bridge['sha256'] == digest(read(0x6022cd, 5))
    assert cb_bridge['target'] == '0x7f2be0'
    raw_sha = digest((HERE / 'bounded_raw.json').read_bytes())
    expected_functions = []
    for index, f in enumerate(raw['functions']):
        byte_ranges = [dict(c, va=c['start_va']) for c in f['chunk_byte_ranges']]
        expected_functions.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'],
            status='仅导出；审阅另见分级清单', assembly=[dict(r, va=r['site_va']) for r in f['assembly']],
            pseudocode=f['pseudocode'], decompile_error=f['decompile_error'], byte_ranges=byte_ranges,
            bytes_match_disk=True, declared_chunks=[dict(start_va=c['start_va'],
                end_va=hex(int(c['start_va'], 16) + c['size']), is_main=c['start_va'] == f['seed_va']) for c in byte_ranges],
            source='证据/bounded_raw.json', source_sha256=raw_sha, json_pointer='/functions/' + str(index)))
    formal = load(HERE / 'formal_functions.json')
    assert formal == dict(schema='richonline-formal-functions-1', disk_sha256=SHA, source_sha256=raw_sha,
        functions=expected_functions, scope='机械适配保留全部汇编/原类型伪码/声明块；不自动认证语义',
        thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']])
    manifest = load(HERE.parent / '函数审阅清单.json')
    assert manifest['disk_sha256'] == SHA and manifest['raw_source_sha256'] == raw_sha
    assert len(manifest['functions']) == 11
    assert {int(f['va'], 16) for f in manifest['functions']} == FRESH | REUSED | {0x7f2be0}
    assert sum(f['status'] == '静态契约已审阅' for f in manifest['functions']) == 10
    assert [f['va'] for f in manifest['functions'] if f['status'] == '局部路径已核'] == ['0x7f2c90']
    assert len(manifest['windows']) == len(unique_windows) == 54
    for current, exported in zip(manifest['windows'], unique_windows.values()):
        assert {k: current[k] for k in ['owner_va', 'site', 'start', 'end']} == exported
        assert {'va', 'status', 'conclusion'}.isdisjoint(current)
    merger = runpy.run_path(str(DOCS / '全量分析/merge_reviews.py'), run_name='independent_readonly')
    recognized = []
    for path in HERE.parent.rglob('*.json'):
        if path.name == 'independent_validation.json':
            continue
        for node, pointer in merger['walk'](json.loads(path.read_bytes())):
            address = node.get('va', node.get('address', node.get('ea', node.get('地址'))))
            status = node.get('status', node.get('review_status', node.get('状态')))
            conclusion = node.get('conclusion', node.get('结论'))
            if address is not None and isinstance(status, str) and isinstance(conclusion, str):
                recognized.append((str(path.relative_to(HERE.parent)), pointer, address))
    assert len(recognized) == 11 and all(r[0] == '函数审阅清单.json' for r in recognized)
    semantic_rows = []
    for site, expected in ANCHORS.items():
        instruction = instructions[site]
        actual = (instruction.mnemonic + ' ' + instruction.op_str).rstrip()
        assert actual == expected, (hex(site), actual, expected)
        semantic_rows.append(dict(site_va=hex(site), text=actual, bytes_hex=instruction.bytes.hex()))
    resource = (ROOT / 'Data/Role.kpd').read_bytes()
    assert digest(resource) == 'd40e2ba5eea1f6bd162fbbc33f5891a89031de787a587212b334a5dcb33b50d2'
    key = resource[0]
    raw_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in resource[1:9]))
    assert len(resource) == 9 + packed_size and 0 < raw_size < 1048576
    plain = lzokay.decompress(bytes((b - key) & 255 for b in resource[9:]), raw_size)
    assert len(plain) == raw_size and digest(plain) == 'cfff4a6e8d8a03532152562a8b09a816e9fc797b751505edcf429e01b1158df7'
    text = plain.decode('cp950')
    assert text.encode('cp950') == plain
    section_rows, active, offset = [], None, 0
    for number, raw_line in enumerate(plain.splitlines(keepends=True), 1):
        line = raw_line.rstrip(b'\r\n')
        if line.startswith(b'['):
            assert line.endswith(b']')
            active = dict(name=line[1:-1].decode('ascii'), source_line=number,
                          source_offset=offset, raw_line_hex=line.hex(), entries=[])
            section_rows.append(active)
        elif active is not None and line.strip() and not line.lstrip().startswith(b'//'):
            name, value = line.split(b'=', 1)
            value = value.lstrip(b' \t')
            active['entries'].append(dict(key=name.strip().decode('ascii'), value_hex=value.hex(),
                value=value.decode('cp950'), source_line=number, source_offset=offset,
                raw_line_hex=line.hex(), value_offset=offset + len(line) - len(value)))
        offset += len(raw_line)
    roles = [s for s in section_rows if s['name'] == 'ROLE']
    assert len(roles) == 9
    assert [next(int(e['value']) for e in s['entries'] if e['key'] == 'indx') for s in roles] == list(range(9))
    assert (key, raw_size, packed_size, plain.count(b'\r'), plain.count(b'\n'), plain.count(b'\0')) == (93, 6397, 3774, 0, 366, 0)
    text_fields = [('name', 4, 16)] + [(name, 0x98 + 0x80 * index, 128) for index, name in enumerate([
        'enName', 'xingZuo', 'birthday', 'bloodType', 'age', 'shengXiao', 'height', 'weight',
        'work', 'interest', 'pet', 'favor', 'dislike', 'idol', 'language', 'tag'])] + [
        ('trait', 0x898, 200), ('introduce', 0x960, 800)]
    def parser_output(value):
        source, output, index = value + b'\n', bytearray(), 0
        while source[index] != 10:
            if source[index] >= 128:
                assert index + 1 < len(value)
                output.extend(source[index:index + 2])
                index += 2
            elif source[index:index + 2] == b'`n':
                output.append(10)
                index += 2
            else:
                output.append(source[index])
                index += 1
        return bytes(output)
    role_checks = []
    for role in roles:
        entries = {e['key']: bytes.fromhex(e['value_hex']) for e in role['entries']}
        assert len(entries) == len(role['entries'])
        text_lengths = []
        for name, field_offset, capacity in text_fields:
            value = parser_output(entries[name])
            assert len(value) + 1 <= capacity
            text_lengths.append(dict(key=name, field_offset=hex(field_offset), capacity=capacity,
                output_bytes=len(value), nul_included_bytes=len(value) + 1))
        suit = []
        while 'suit' + str(len(suit)) in entries:
            suit.append(int(entries['suit' + str(len(suit))]))
        assert len(suit) <= 32
        ignored = sorted(k for k in entries if k.startswith('suit') and int(k[4:]) >= len(suit))
        role_checks.append(dict(index=int(entries['indx']), mood=int(entries['mood']),
            sex=entries['sex'].decode('ascii'), sex_byte=0 if entries['sex'] == b'girl' else 1,
            land_flag=int(entries['landFlag']), consumed_suit_ids=suit, ignored_suit_keys=ignored,
            text_lengths=text_lengths))
    assert [len(r['consumed_suit_ids']) for r in role_checks] == [17, 17, 16, 18, 17, 13, 10, 5, 17]
    assert role_checks[7]['ignored_suit_keys'] == ['suit10', 'suit11', 'suit12', 'suit13', 'suit14', 'suit15', 'suit16', 'suit7', 'suit8', 'suit9']
    resource_audit = load(HERE / 'resource_audit.json')
    assert resource_audit['status'] == 'PASS' and resource_audit['source'] == 'Data/Role.kpd'
    assert resource_audit['source_sha256'] == digest(resource) and resource_audit['plain_sha256'] == digest(plain)
    assert resource_audit['sections'] == section_rows
    assert (resource_audit['key'], resource_audit['raw_size'], resource_audit['packed_size']) == (key, raw_size, packed_size)
    assert (resource_audit['cr'], resource_audit['lf'], resource_audit['nul']) == (0, 366, 0)
    assert resource_audit['role_section_count'] == resource_audit['array_count'] == 9
    assert resource_audit['array_bytes'] == 9 * 0xc84
    assert all(not resource_audit[k] for k in ['duplicate_indices', 'negative_indices', 'missing_indices'])
    expected_rendered = []
    for section, ours, theirs in zip(roles, role_checks, resource_audit['roles']):
        for k in ['index', 'mood', 'sex', 'land_flag']:
            assert ours[k] == theirs[k]
        es = {e['key']: bytes.fromhex(e['value_hex']) for e in section['entries']}
        assert theirs['name'] == es['name'].decode('cp950')
        assert theirs['suit_values'] == ours['consumed_suit_ids']
        assert theirs['consumed_suit_keys'] == ['suit' + str(i) for i in range(len(ours['consumed_suit_ids']))]
        assert set(theirs['ignored_suit_keys']) == set(ours['ignored_suit_keys'])
        assert len(theirs['text_capacities']) == len(text_fields) == 19
        for (name, offset, capacity), audit in zip(text_fields, theirs['text_capacities']):
            value = parser_output(es[name])
            assert audit == dict(key=name, offset=hex(offset), capacity=capacity, copied_hex=value.hex(),
                                 copied_bytes=len(value), with_nul=len(value) + 1)
        for entry in section['entries']:
            suffix = '  （该loader未消费）' if entry['key'] in theirs['ignored_suit_keys'] else ''
            expected_rendered.append('// ' + entry['key'] + ' = ' + entry['value'].rstrip() + suffix)
    rendered = (HERE.parent / '06_当前资源文本对照.txt').read_text('utf-8').splitlines()
    assert [line for line in rendered if line.startswith('// ') and ' = ' in line] == expected_rendered
    for p in HERE.parent.rglob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in p.read_text('utf-8').splitlines()), str(p)
    final_bindings = {}
    for relative, expected in FINAL_SHA.items():
        actual = digest((HERE.parent / relative).read_bytes())
        assert actual == expected, (relative, '终稿改变，须重新独审')
        final_bindings[relative] = actual
    result = dict(status='PASS' if FINAL_SHA else '原证字节预核通过；作者终稿待审', pe_sha256=SHA,
        functions=function_rows, callback=dict(site_va='0x7f2be0', instruction_count=len(decoded)),
        original_window_records=len(windows), unique_windows=list(unique_windows.values()),
        unique_bridges=len(bridges), semantic_anchors=semantic_rows, string_windows=data_rows,
        reused_dependencies=reuse_rows, formal_equivalent=True, central_compatible_reviews=recognized,
        resource=dict(path='Data/Role.kpd', navigation_only=False, path_callsite='0x623bf2', source_sha256=digest(resource), plain_sha256=digest(plain),
            key=key, raw_size=raw_size, packed_size=packed_size, encoding='CP950严格往返；不证明运行期代码页',
            sections=section_rows, allocation_count=9, role_checks=role_checks),
        sources=sources, unique_ranges=list(ranges.values()), reviewed_final_sha256=final_bindings,
        boundary='完整声明块字节独立复核；依赖语义限定于角色路径；窗口不计owner完整语义；未运行游戏')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], len(result['functions']), result['unique_bridges'])
