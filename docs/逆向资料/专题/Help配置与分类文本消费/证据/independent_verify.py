"""Help专题独立PE/Capstone/资源核验；不调用IDA或作者验证器。"""
import hashlib
import json
import struct
import runpy
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x69c740, 0x69c790, 0x69c880, 0x69c930, 0x69cbb0, 0x69ce30, 0x69d190, 0x69d510, 0x629480}
REUSED = {0x628a80}
FINAL_SHA = {
    '00_有限采证实施计划.txt': '47aab2672550b52741c3658f3bee797e8e30c0a1a7dcbac89c24eec877a43b31',
    '01_阅读入口与对象布局.txt': '8c5a24836ed4bd81eb11a7ac2caf02680aa805c7d70857d112109f0884005d8b',
    '02_分类装载与配置约束.txt': 'c2515caa11e751f684a7d3ddff544492ea80afc4be47af233bbea009186f52bd',
    '03_文本借用与清理责任.txt': '52b978d8f709ba6f70fb9065640b5d1bf9737d5e624a3518822b4f4ca523c8e2',
    '04_证据复核与合作边界.txt': 'dffb586939c7902a328c49ec1fbf5ffa0cfacfb14f891cf9172084395979f238',
    '05_当前资源与文本修改入口.txt': '8584ae98ff02ceb9a7884c9108831e1a0ff234b5ff5756593d28b6b688d5fd01',
    '06_当前资源文本对照.txt': '7ca1cdaf7829403f5b99f610e285267684451a5c40e221f0fe08342bcae88ff7',
    '函数审阅清单.json': '77f00b52c61645fd5a5e0bbc1a1735d8f0e7ead1f4dc0248e1dde671749a563b',
    '验证结果.json': '689031cc53761e0666cba0be679c3de1d57d6db8d905db48e677e52ce628a4ac',
    '证据/bounded_raw.json': '74e0f33df8bebc21f17663591f626525ca5734703e483968b726e34379f4ec05',
    '证据/dependency_raw.json': '446eb023e73662fb49b4945c2aa5b554b8fa872a7efb6ae83b826919ec0804cd',
    '证据/formal_functions.json': 'a401744cf3efd8760017c27b89de86256862e835ddc3c3eba80e941d09f2648d',
    '证据/reused_audit.json': 'c743ea3c50a7be6012670eccaad1d26fb8733302e70a956cb375131d5d31b3f8',
    '证据/bounded_audit.json': '4b309b6e8c8fefe39ebd20011fc795ec12ffb5cb59e50c06b32d3e9fdb232a69',
    '证据/resource_audit.json': '9b3740c8da95150420470398c30dbb5f689d0140e3bc59c936e85194afb7f655',
    '证据/resource_audit.py': 'c4c5546c601e5f50176f2d096e07f4600534374f468942406972303b40adb00c',
    '证据/verify_bounded.py': 'e092da5e5bc5c0908e47c772165f6426a4983e875b0b116c30cf97b0b1975481',
    '证据/export_bounded.py': '9947823f0ef0afc8461eecf2b2ca190cd43b4866018f9917c10262f26cff19a2',
}
ANCHORS = {
    0x69c751: 'mov dword ptr [eax + 0x84], 0',
    0x69c75e: 'mov dword ptr [ecx + 0x90], 0',
    0x69c76b: 'mov dword ptr [edx + 0x9c], 0',
    0x69c778: 'mov dword ptr [eax + 0xa8], 0',
    0x69c7d4: 'mov dword ptr [ecx + 0x84], 0',
    0x69c805: 'mov dword ptr [eax + 0x90], 0',
    0x69c836: 'mov dword ptr [edx + 0x9c], 0',
    0x69c867: 'mov dword ptr [ecx + 0xa8], 0',
    0x69c8a2: 'mov dword ptr [ecx + 0x80], 0',
    0x69c8af: 'mov byte ptr [edx + 0x88], 0',
    0x69c8fe: 'mov dword ptr [eax + 0xb0], 0',
    0x69c90b: 'mov byte ptr [ecx + 0xb8], 0',
    0x69c912: 'mov eax, 1',
    0x69ca57: 'shl edx, 9',
    0x69cad0: 'call 0x60fde2',
    0x69cf57: 'imul edx, edx, 0x244',
    0x69d2b7: 'imul edx, edx, 0x244',
    0x69d36c: 'cmp dword ptr [ebp - 0x38], -1',
    0x69d62b: 'imul ecx, ecx, 0xc',
    0x69d646: 'mov dword ptr [edx + 0xb4], eax',
    0x69d708: 'mov dword ptr [edx + ecx + 4], eax',
    0x69d72b: 'mov dword ptr [edx + ecx + 8], eax',
    0x629499: 'and eax, 1',
    0x6294ba: 'ret 4',
    0x693381: 'imul eax, eax, 0x468',
    0x69338c: 'lea eax, [edx + eax + 0x294]',
    0x69ded1: 'imul eax, eax, 0x468',
    0x69dedc: 'lea eax, [edx + eax + 0x2d4]',
    0x69d8e9: 'shl eax, 9',
    0x69d8ef: 'add eax, dword ptr [ecx + 0x84]',
    0x69d929: 'shl eax, 9',
    0x69d92f: 'add eax, dword ptr [ecx + 0x90]',
    0x69d969: 'imul eax, eax, 0x244',
    0x69d972: 'add eax, dword ptr [ecx + 0x9c]',
    0x69d9a9: 'imul eax, eax, 0x244',
    0x69d9b2: 'add eax, dword ptr [ecx + 0xa8]',
    0x69d9e9: 'imul eax, eax, 0xc',
    0x69d9ef: 'add eax, dword ptr [ecx + 0xb4]',
    0x81968c: 'mov dword ptr [eax + 0x90], edx',
    0x819736: 'cmp ecx, 0x5b',
    0x819926: 'cmp edx, 0x80',
    0x819977: 'cmp eax, 0xa',
    0x819993: 'cmp ecx, 0x60',
    0x81999f: 'cmp eax, 0x6e',
    0x8199a7: 'mov byte ptr [ecx], 0xa',
    0x8199f4: 'cmp edx, dword ptr [ebp + 0xc]',
    0x64f013: 'cmp dword ptr [eax + 0x18964], 1',
    0x819154: 'lea edx, [ecx + eax + 0x7fc8]',
    0x81a0a7: 'mov ecx, dword ptr [eax + 4]',
    0x81a0b0: 'mov dword ptr [edx + 0x94], ecx',
    0x81a0c2: 'mov dword ptr [eax + 0x90], edx',
    0x81a0d4: 'mov dword ptr [eax + 0x8c], edx',
    0x91f7e7: 'call 0x604cfd',
    0x91bd87: 'call 0x601274',
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
    exporter = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    assert digest(exporter.read_bytes()) == raw['exporter_sha256']
    assert {int(r['seed_va'], 16) for r in raw['functions']} == FRESH
    assert {int(r['seed_va'], 16) for r in raw['reused_seeds']} == REUSED
    assert {int(r['seed_va'], 16) for r in raw['seeds']} == FRESH | REUSED
    audits = {int(r['seed_va'], 16): r['chunk_byte_ranges'] for r in raw['current_chunk_audits']}
    assert set(audits) == FRESH | REUSED
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert digest(path.read_bytes()) == source['source_sha256']
        sources[str(path.relative_to(ROOT))] = source['source_sha256']
    teach = load(DOCS / '专题/TeachMode对象与消费者/证据/teachmode_raw.json')
    functions = {int(r['seed_va'], 16): r for r in raw['functions']}
    functions[0x628a80] = next(f for f in teach['functions'] if f['va'] == '0x628a80')
    function_rows = []
    for va, function in functions.items():
        chunks = function.get('chunk_byte_ranges', function.get('chunks'))
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in audits[va]]
        if va in FRESH:
            assert chunks == audits[va]
        else:
            for c in chunks:
                check(c)
        decoded = [i for chunk in audits[va] for i in code(chunk)]
        source_assembly = function.get('assembly', function.get('instructions'))
        assert {i.address for i in decoded} == {
            int(r.get('site_va', r.get('va')), 16) for r in source_assembly}
        assert len(decoded) == len(source_assembly)
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
        assembly.extend(['// 主体 ' + hex(va)] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    for row in raw['verified_direct_bridges']:
        decoded = code(row)
        assert len(decoded) == 1 and decoded[0].mnemonic == 'jmp'
        bridge(decoded[0].address, int(row['target_va'], 16))
    assert len(bridges) == len(raw['verified_direct_bridges']) == 41
    windows = list(raw['explicit_owner_windows']) + [e['owner_window']
        for edges in raw['incoming'].values() for e in edges if 'owner_window' in e]
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
        key = (window['owner_va'], decoded[0].address, decoded[-1].address + decoded[-1].size)
        unique_windows[key] = dict(owner_va=key[0], start=hex(key[1]), end=hex(key[2]))
    assert len(windows) == 24
    data_rows = []
    for row in raw['data_windows']:
        va, content = check(row)
        if va == 0xa766f8:
            assert content == bytes(4)
            continue
        assert content[-1:] == b'\0' and b'\0' not in content[:-1]
        data_rows.append(dict(site_va=hex(va), text=content[:-1].decode('ascii'), bytes_hex=content.hex()))
    assert len(data_rows) == 22
    for row in raw['strings']:
        check(row['byte_audit'])
        payload, width = bytes.fromhex(row['payload_hex']), row['unit_width']
        assert width in (1, 2) and len(payload) % width == 0 and row['nul_hex'] == bytes(width).hex()
        assert row['byte_audit']['idb_hex'] == (payload + bytes(width)).hex()
    small_sources = [(DOCS / '专题/TeachMode对象与消费者/证据/teachmode_raw.json', 0x693370),
                     (DOCS / '专题/40D0系列事件/证据/ui_helpers.json', 0x69dec0)]
    for path, va in small_sources:
        source = load(path)
        function = next(f for f in source['functions'] if int(f['va'], 16) == va)
        chunks = function.get('byte_ranges', function.get('chunks'))
        decoded = [i for c in chunks for i in code(c)]
        source_assembly = function.get('assembly', function.get('instructions'))
        assert {i.address for i in decoded} == {int(r['va'], 16) for r in source_assembly}
        assembly.extend(['// 复用借用指针访问器 ' + hex(va)] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    dependency = load(HERE / 'dependency_raw.json')
    getters = {0x69d8d0, 0x69d910, 0x69d950, 0x69d990, 0x69d9d0}
    assert dependency['disk_sha256'] == SHA
    assert {int(f['va'], 16) for f in dependency['functions']} == getters
    for f in dependency['functions']:
        decoded = [i for c in f['chunk_byte_ranges'] for i in code(c)]
        assert {i.address for i in decoded} == {int(r['va'], 16) for r in f['assembly']}
        assert len(decoded) == len(f['assembly'])
        assert {(c.get('start_va', c.get('va')), hex(int(c.get('start_va', c.get('va')), 16) + c['size'])) for c in f['chunk_byte_ranges']} == {
            (c['start_va'], c['end_va']) for c in f['declared_chunks']}
        assembly.extend(['// 完整读取器 ' + f['va']] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    for row in dependency['thunks']:
        decoded = code(row)
        assert len(decoded) == 1 and decoded[0].mnemonic == 'jmp'
        bridge(int(row['va'], 16), int(row['target'], 16))
    for va, loader in zip(sorted(getters), [0x69c930, 0x69cbb0, 0x69ce30, 0x69d190, 0x69d510]):
        site = va + 17
        assert instructions[site].mnemonic == 'call'
        assert bridges[int(instructions[site].op_str, 16)] == loader
    reused_audit = load(HERE / 'reused_audit.json')
    assert len(reused_audit['supplemental']) == 5
    for index, (f, audit) in enumerate(zip(dependency['functions'], reused_audit['supplemental'])):
        assert audit['seed_va'] == f['va'] and audit['source'] == 'dependency_raw.json'
        assert audit['source_sha256'] == digest((HERE / audit['source']).read_bytes())
        assert audit['json_pointer'] == '/functions/' + str(index)
        assert [(int(c['start_va'], 16), c['size']) for c in audit['chunks']] == [
            (int(c.get('start_va', c.get('va')), 16), c['size']) for c in f['chunk_byte_ranges']]
        assert all(digest(read(int(c['start_va'], 16), c['size'])) == c['sha256'] for c in audit['chunks'])
    reuse_rows = []
    for ref in reused_audit['references']:
        path = DOCS / ref['source']
        assert digest(path.read_bytes()) == ref['source_sha256']
        f = load(path)
        for part in ref['json_pointer'].split('/')[1:]:
            f = f[int(part)] if isinstance(f, list) else f[part]
        assert f['va'] == ref['owner_va']
        chunks = f.get('chunk_byte_ranges', f.get('byte_ranges', f.get('disk_ranges', f.get('chunks'))))
        decoded = []
        for c in chunks:
            va = int(c.get('start_va', c.get('va')), 16)
            payload = read(va, c['size'])
            assert payload.hex() == c['disk_hex']
            assert 'sha256' not in c or digest(payload) == c['sha256']
            assert 'idb_hex' not in c or c['idb_hex'] == payload.hex()
            assert 'ida_hex' not in c or c['ida_hex'] == payload.hex()
            body = list(decoder.disasm(payload, va))
            assert sum(i.size for i in body) == len(payload)
            decoded.extend(body)
            for i in body:
                assert instructions.setdefault(i.address, i).bytes == i.bytes
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in ref['chunks']]
        for c in ref['chunks']:
            assert digest(read(int(c['start_va'], 16), c['size'])) == c['sha256']
        source_assembly = f.get('assembly', f.get('instructions'))
        assert {i.address for i in decoded} == {int(r.get('site_va', r.get('va')), 16) for r in source_assembly}
        assert len(decoded) == len(source_assembly)
        reuse_rows.append(dict(owner_va=f['va'], chunks=len(chunks), instruction_count=len(decoded),
                              scope='完整字节独立复解码；语义仅Help依赖契约，不新增审阅入口'))
        if int(f['va'], 16) in {0x819470, 0x819660, 0x8198e0, 0x81a090, 0x91f7e0, 0x91bd80, 0x64f000, 0x8190b0}:
            assembly.extend(['// 依赖限定语义 ' + f['va']] + [
                '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    formal = load(HERE / 'formal_functions.json')
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
    assert formal == dict(schema='richonline-formal-functions-1', disk_sha256=SHA, source_sha256=raw_sha,
        functions=expected_functions, scope='机械字段适配；完整汇编、伪码和声明块保留；非自动语义认证',
        thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']])
    manifest = load(HERE.parent / '函数审阅清单.json')
    assert manifest['disk_sha256'] == SHA and manifest['raw_source_sha256'] == raw_sha
    assert len(manifest['functions']) == 15
    assert {int(f['va'], 16) for f in manifest['functions']} == FRESH | REUSED | getters
    assert sum(f['status'] == '静态契约已审阅' for f in manifest['functions']) == 10
    assert sum(f['status'] == '局部路径已核' for f in manifest['functions']) == 5
    assert len(manifest['windows']) == 24
    for current, exported in zip(manifest['windows'], windows):
        assert current['owner_va'] == exported['owner_va'] and current['site'] == exported['site_va']
        assert current['start'] == exported['assembly'][0]['site_va']
        last = exported['assembly'][-1]['bytes']
        assert int(current['end'], 16) == int(last['start_va'], 16) + last['size']
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
    assert len(recognized) == 15 and all(r[0] == '函数审阅清单.json' for r in recognized)
    semantic_rows = []
    for site, expected in ANCHORS.items():
        instruction = instructions[site]
        actual = (instruction.mnemonic + ' ' + instruction.op_str).rstrip()
        assert actual == expected, (hex(site), actual, expected)
        semantic_rows.append(dict(site_va=hex(site), text=actual, bytes_hex=instruction.bytes.hex()))
    resource = (ROOT / 'Data/Help.kpd').read_bytes()
    assert digest(resource) == '1145a25a22698581623bc587666f5847e9d9a11588f11a5cfc1fbdccd1b78b39'
    key = resource[0]
    raw_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in resource[1:9]))
    assert len(resource) == 9 + packed_size and 0 < raw_size < 1048576
    plain = lzokay.decompress(bytes((b - key) & 255 for b in resource[9:]), raw_size)
    assert len(plain) == raw_size
    assert digest(plain) == 'ab61d7ddd6a796278ce6f93584177241c35a1712c116ca38881beca00f387d68'
    text = plain.decode('cp950')
    assert text.encode('cp950') == plain
    section_rows, active = [], None
    for number, line in enumerate(plain.splitlines(), 1):
        if line.startswith(b'['):
            assert line.endswith(b']')
            active = dict(name=line[1:-1].decode('ascii'), line=number, entries=[])
            section_rows.append(active)
        elif active is not None and line.strip() and not line.lstrip().startswith(b'//'):
            name, value = line.split(b'=', 1)
            active['entries'].append(dict(key=name.strip().decode('ascii'),
                value_hex=value.lstrip(b' \t').hex(), source_line=number))
    resource_audit = load(HERE / 'resource_audit.json')
    assert resource_audit['source_sha256'] == digest(resource) and resource_audit['plain_sha256'] == digest(plain)
    assert len(section_rows) == len(resource_audit['sections']) == 125
    for ours, theirs in zip(section_rows, resource_audit['sections']):
        assert ours['name'] == theirs['name'] and ours['line'] == theirs['source_line']
        assert ours['entries'] == [{k: e[k] for k in ['key', 'value_hex', 'source_line']} for e in theirs['entries']]
        for entry in theirs['entries']:
            value = bytes.fromhex(entry['value_hex'])
            assert value.decode('cp950') == entry['value']
            assert plain[entry['value_offset']:entry['value_offset'] + len(value)] == value
    assert (key, raw_size, packed_size, plain.count(b'\r'), plain.count(b'\n'), plain.count(b'\0')) == (42, 10048, 5292, 0, 569, 0)
    def value_bytes(value):
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
    def values(section):
        result = {}
        for e in section['entries']:
            assert e['key'] not in result
            result[e['key']] = bytes.fromhex(e['value_hex'])
        return result
    category_checks = []
    for name, count in [('OP', 13), ('RULE', 5)]:
        es = values(next(s for s in section_rows if s['name'] == name))
        assert int(es['num']) == count and set(es) == {'num'} | {'item' + str(i) for i in range(count)}
        actual_values = [value_bytes(es['item' + str(i)]) for i in range(count)]
        assert max(map(len, actual_values)) + 1 <= 512
        category_checks.append(dict(category=name, count=count, max_output_bytes=max(map(len, actual_values)), capacity=512))
    for name, prefix, count in [('EVENT', 'event', 26), ('NPC', 'npc', 20)]:
        assert int(values(next(s for s in section_rows if s['name'] == name))['num']) == count
        selected = [s for s in section_rows if s['name'].startswith(prefix)]
        assert [s['name'] for s in selected] == [prefix + str(i) for i in range(count)]
        rows = [values(s) for s in selected]
        assert all(set(r) == {'id', 'name', 'desc'} for r in rows)
        assert all(len(value_bytes(r['name'])) + 1 <= 64 and len(value_bytes(r['desc'])) + 1 <= 512 for r in rows)
        category_checks.append(dict(category=name, count=count, ids=[int(r['id']) for r in rows],
            max_output_name_bytes=max(len(value_bytes(r['name'])) for r in rows),
            max_output_desc_bytes=max(len(value_bytes(r['desc'])) for r in rows)))
    props = [values(s) for s in section_rows if s['name'] == 'prop']
    expected_ids = list(range(500, 509)) + list(range(1031, 1080)) + [1084] + list(range(1116, 1126)) + [1181, 1182, 1183, 1127, 1130, 1131]
    assert len(props) == 75 and all(set(r) == {'id', 'name'} for r in props)
    assert [int(r['id']) for r in props] == expected_ids
    category_checks.append(dict(category='prop', count=75, ids=expected_ids, resource_name_ignored=True))
    for ours, theirs in zip(category_checks, resource_audit['categories']):
        assert ours['category'] == theirs['category'] and ours['count'] == theirs['count']
        assert 'ids' not in ours or ours['ids'] == theirs['ids']
    assert b'`n' not in plain
    rendered = (HERE.parent / '06_当前资源文本对照.txt').read_text('utf-8').splitlines()
    resource_lines = [line for line in rendered if line.startswith('// ') and ' = ' in line]
    assert resource_lines == ['// ' + e['key'] + ' = ' + bytes.fromhex(e['value_hex']).decode('cp950').rstrip()
                              for s in section_rows for e in s['entries']]
    for p in HERE.parent.rglob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in p.read_text('utf-8').splitlines()), str(p)
    final_bindings = {}
    for relative, expected in FINAL_SHA.items():
        actual = digest((HERE.parent / relative).read_bytes())
        assert actual == expected, (relative, '终稿改变，须重新独审')
        final_bindings[relative] = actual
    result = dict(status='PASS' if FINAL_SHA else '字节预核通过；终稿待审', pe_sha256=SHA,
        functions=function_rows, original_window_records=len(windows), unique_windows=list(unique_windows.values()),
        unique_bridges=len(bridges), semantic_anchors=semantic_rows, string_windows=data_rows,
        getters=sorted(hex(x) for x in getters), reused_dependencies=reuse_rows,
        formal_equivalent=True, central_compatible_reviews=recognized,
        resource=dict(path='Data/Help.kpd', source_sha256=digest(resource), plain_sha256=digest(plain),
            key=key, raw_size=raw_size, packed_size=packed_size, cr=plain.count(b'\r'), lf=plain.count(b'\n'),
            nul=plain.count(b'\0'), encoding='CP950严格往返；不证明运行期代码页', sections=section_rows,
            category_checks=category_checks),
        sources=sources, unique_ranges=list(ranges.values()), reviewed_final_sha256=final_bindings,
        boundary='窗口不计owner完整语义；未运行游戏')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], len(result['functions']), result['unique_bridges'])
