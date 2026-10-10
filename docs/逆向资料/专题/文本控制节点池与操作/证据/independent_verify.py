"""独立磁盘核验；不导入作者脚本、不连接IDA、不登记语义完成。"""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = {0x6e52d0, 0x6fabe0, 0x6facf0, 0x6fad40, 0x8e02f0, 0x8eaa30, 0x8eaaf0}
ANCHORS = {
    0x6fad01: 'mov byte ptr [eax + 8], 0',
    0x6fad08: 'mov dword ptr [ecx], 0',
    0x6fad11: 'mov dword ptr [edx + 4], 0',
    0x6fad1b: 'mov dword ptr [eax + 0xc], 0',
    0x6fad4e: 'cmp dword ptr [0xacc3c4], 0',
    0x6fad55: 'je 0x6fad5b',
    0x6fad57: 'xor eax, eax',
    0x6fad5b: 'mov eax, 1',
    0x6fac15: 'call 0x609ffa',
    0x6fac1c: 'jne 0x6fac5e',
    0x6fac1e: 'mov eax, dword ptr [0xacc3c4]',
    0x6fac2c: 'mov edx, dword ptr [ecx + 0xc]',
    0x6fac2f: 'mov dword ptr [0xacc3c4], edx',
    0x6fac38: 'mov byte ptr [eax + 8], 0',
    0x6fac3f: 'mov dword ptr [ecx], 0',
    0x6fac48: 'mov dword ptr [edx + 4], 0',
    0x6fac52: 'mov dword ptr [eax + 0xc], 0',
    0x6fac5e: 'push 0x10',
    0x6fac60: 'call 0x601274',
    0x6fac76: 'je 0x6fac85',
    0x6fac7b: 'call 0x6037a4',
    0x6fac85: 'mov dword ptr [ebp - 0x20], 0',
    0xa13d04: 'call 0x604cfd',
    0xa13d10: 'jmp 0x60657b',
    0x6e5325: 'movzx eax, word ptr [edx]',
    0x6e532a: 'je 0x6e5510',
    0x6e5336: 'cmp edx, 0x80',
    0x6e5351: 'call 0x609587',
    0x6e5370: 'cmp edx, 6',
    0x6e5380: 'cmp ecx, 0x14',
    0x6e5390: 'cmp eax, 0x46',
    0x6e53c0: 'mov dword ptr [edx + 0xc], 0',
    0x6e53cd: 'mov dword ptr [eax], ecx',
    0x6e53d5: 'mov dword ptr [edx + 4], eax',
    0x6e53db: 'mov byte ptr [ecx + 8], 0',
    0x6e53ef: 'mov dword ptr [edx + 0xc], eax',
    0x6e53fe: 'mov dword ptr [edx + 0xc], 0',
    0x6e540b: 'mov dword ptr [eax], ecx',
    0x6e5413: 'mov dword ptr [edx + 4], eax',
    0x6e5419: 'mov byte ptr [ecx + 8], 0',
    0x6e542a: 'mov dword ptr [ebp - 0x14], 2',
    0x6e5431: 'mov dword ptr [ebp - 0x18], 0x18',
    0x6e5455: 'mov dword ptr [ecx + 0xc], 0',
    0x6e5462: 'mov dword ptr [edx], eax',
    0x6e546a: 'mov dword ptr [ecx + 4], edx',
    0x6e5470: 'mov byte ptr [eax + 8], 1',
    0x6e5484: 'mov dword ptr [ecx + 0xc], eax',
    0x6e5493: 'mov dword ptr [ecx + 0xc], 0',
    0x6e54a0: 'mov dword ptr [edx], eax',
    0x6e54a8: 'mov dword ptr [ecx + 4], edx',
    0x6e54ae: 'mov byte ptr [eax + 8], 1',
    0x6e54c2: 'add edx, 4',
    0x6e54d3: 'movzx ecx, word ptr [ebp + 0x14]',
    0x6e54db: 'push 0x2a',
    0x6e5533: 'mov dword ptr [eax + 0xc], 0',
    0x6e5540: 'mov dword ptr [ecx], edx',
    0x6e5548: 'mov dword ptr [eax + 4], ecx',
    0x6e554e: 'mov byte ptr [edx + 8], 0',
    0x6e5562: 'mov dword ptr [ecx + 0xc], eax',
    0x6e5571: 'mov dword ptr [ecx + 0xc], 0',
    0x6e557e: 'mov dword ptr [edx], eax',
    0x6e5586: 'mov dword ptr [ecx + 4], edx',
    0x6e558c: 'mov byte ptr [eax + 8], 0',
    0x6e5590: 'mov eax, dword ptr [ebp - 8]',
    0x6e53af: 'call 0x607872',
    0x6e53e7: 'call 0x607872',
    0x6e5444: 'call 0x607872',
    0x6e547c: 'call 0x607872',
    0x6e5522: 'call 0x607872',
    0x6e555a: 'call 0x607872',
    0x8e0306: 'mov dword ptr [esi + 0x5118], 0',
    0x8e0323: 'mov dword ptr [esi + 0x5120], 0',
    0x8e033e: 'call 0x607872',
    0x8e0344: 'call 0x604cfd',
    0x8e034c: 'jmp 0x8e0333',
    0x8e034e: 'mov dword ptr [0xacc3c4], 0',
    0x8eaa4a: 'mov ebp, dword ptr [esp + 0x14]',
    0x8eaa57: 'mov eax, dword ptr [esp + 0x20]',
    0x8eaa5b: 'mov ecx, dword ptr [esp + 0x1c]',
    0x8eaa63: 'call dword ptr [ebx + 0x40]',
    0x8eaa66: 'add esp, 0x10',
    0x8eaa6f: 'mov esi, dword ptr [ecx + 4]',
    0x8eaa72: 'mov ecx, dword ptr [ecx + 0xc]',
    0x8eaa7d: 'jne 0x8eaaa1',
    0x8eaa91: 'mov dword ptr [ecx], esi',
    0x8eaa99: 'mov dword ptr [0xacc3c4], esi',
    0x8eaaa7: 'ret 0x10',
    0x8eaaf8: 'mov ebp, dword ptr [esp + 0x42c]',
    0x8eab14: 'mov ebx, dword ptr [esp + 0x434]',
    0x8eab1f: 'mov eax, dword ptr [esp + 0x43c]',
    0x8eab26: 'mov ecx, dword ptr [esp + 0x438]',
    0x8eab2d: 'mov edx, dword ptr [0xacc3c8]',
    0x8eab37: 'call dword ptr [edx + 0x40]',
    0x8eab3a: 'add esp, 0x10',
    0x8eab40: 'mov ecx, 0x82',
    0x8eab4b: 'mov word ptr [esp + 0x18], si',
    0x8eab50: 'mov word ptr [esp + 0x224], si',
    0x8eab6a: 'je 0x8eab8c',
    0x8eab79: 'mov ecx, eax',
    0x8eab81: 'shr ecx, 1',
    0x8eab92: 'mov ecx, eax',
    0x8eab96: 'mov edx, ecx',
    0x8eab9a: 'shr ecx, 2',
    0x8eaba5: 'and ecx, 3',
    0x8eabcc: 'cmp ax, 0x20',
    0x8eabd2: 'mov word ptr [esi], ax',
    0x8eac17: 'mov word ptr [esi], 0',
    0x8eac2d: 'mov eax, dword ptr [esp + 0x438]',
    0x8eac37: 'jne 0x8eac5b',
    0x8eac48: 'mov ebx, dword ptr [ebx + 0xc]',
    0x8eac4b: 'mov dword ptr [eax], edx',
    0x8eac53: 'mov dword ptr [0xacc3c4], edx',
    0x8eac64: 'ret 0x10',
    0x6e2f0e: 'push 0x609537',
    0x6e2f13: 'mov ecx, dword ptr [0xacc3c8]',
    0x6e2f19: 'call 0x610797',
    0x8e8720: 'mov eax, dword ptr [esp + 4]',
    0x8e8724: 'test eax, eax',
    0x8e8726: 'je 0x8e872b',
    0x8e8728: 'mov dword ptr [ecx + 0x40], eax',
    0x8e872b: 'ret 4',
}
FINAL_SHA = {
    '00_有限采证实施计划.txt': '3317949cce3b443167d05a7883c7f7c4df16ab6ab7b75491c803a6a2f9f0c803',
    '01_准备问题与复用边界.txt': 'ada0faaeb2b4c2b15d42a3563b6b5405d5e7f133e53474eff68ce7c207842ad4',
    '02_节点布局与生产.txt': '37c03f6dc08d49db495b476c39b8f0d5cbf7f9f80bf9a2a501966acbf6789bd9',
    '03_调用契约与回收.txt': 'd975b8a6955e13b76e86296c36991e0df1a66b6b30b62ac146d764e6814708f5',
    '04_文本消费与协作边界.txt': 'f4d7263ac54a3542c4b338d695699c0c4c6aba6ea8bbd88b3d94de75c027bd30',
    '函数审阅清单.json': '2d2eb93960f28d83b520b2c2a0a913043e33918fc52c5d9c84cbf54cdfb6059c',
    '验证结果.json': '1ecd8b9992b0d27a64afdd9a6758a9ca66591cf06ae7f392d6331bf5cb94628a',
    '证据/verify_bounded.py': '936dc696b8072929e0f9a1f094bd9a4cd6f3008bc18c0154fe3f891d74874324',
    '证据/verify_reused_owners.py': 'dee573e63b5f664e0ce8655da3a9091dd04a81d7fe9ba1bef02ab4f625a2f0e9',
    '证据/formal_functions.json': 'caa2dac42663abf7b51682372ca2b61a4216f47efae1dfd6aac3e68bba8bd10c',
    '证据/bounded_audit.json': '357ae9a1f56e1adf4dae0c1a42ebad82f66112495c1eb34c32a11b80f9b96aae',
    '证据/reused_owner_audit.json': 'aa2aed4fe74e299a65377fdfcc86ef9492fe87034602231de2c137ea080948a2',
    '证据/bounded_raw.json': '657757f1af01608ca84be60202b62b279761bf72e550a58df9fc8f74ff41c0bd',
    '证据/export_bounded.py': '42827ed7aeed62ada6f040fd2dda8a4c7a874fbf82d528f95a12f0342044a6e7',
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
    sections = [struct.unpack_from('<4I', image, table + 40 * n + 8)
                for n in range(struct.unpack_from('<H', image, nt + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    all_instructions, ranges, bridges, snapshots, assembly = {}, {}, {}, {}, []

    def read(va, size):
        offsets = [off + va - base - rva for _, rva, raw, off in sections
                   if rva <= va - base and va - base + size <= rva + raw]
        assert len(offsets) == 1 and offsets[0] + size <= len(image), (hex(va), size)
        return image[offsets[0]:offsets[0] + size]

    def load(path):
        content = path.read_bytes()
        snapshots[str(path.relative_to(ROOT))] = digest(content)
        return json.loads(content)

    def check(row):
        va = int(row.get('start_va', row.get('va')), 16)
        size = row['size']
        content = read(va, size)
        assert row['matching'] is True and content.hex() == row['idb_hex'] == row['disk_hex']
        assert 'sha256' not in row or digest(content) == row['sha256']
        ranges[va, size] = dict(start_va=hex(va), size=size, sha256=digest(content))
        return va, content

    def code(row):
        va, content = check(row)
        decoded = list(decoder.disasm(content, va))
        assert sum(ins.size for ins in decoded) == len(content), hex(va)
        for ins in decoded:
            assert all_instructions.setdefault(ins.address, ins).bytes == ins.bytes
        return decoded

    def bridge(va, target):
        encoded = read(va, 5)
        assert encoded[0] == 0xe9
        assert va + 5 + struct.unpack_from('<i', encoded, 1)[0] == target
        assert bridges.setdefault(va, target) == target

    raw = load(HERE / 'bounded_raw.json')
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['topic'] == '文本控制节点池与操作' and raw['disk_sha256'] == SHA
    exporter = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    assert digest(exporter.read_bytes()) == raw['exporter_sha256']
    snapshots[str(exporter.relative_to(ROOT))] = raw['exporter_sha256']
    assert {int(row['seed_va'], 16) for row in raw['seeds']} == SEEDS
    assert raw['reused_seeds'] == []
    audits = {int(row['seed_va'], 16): row for row in raw['current_chunk_audits']}
    functions = {int(row['seed_va'], 16): row for row in raw['functions']}
    assert len(audits) == len(functions) == 7 and set(audits) == set(functions) == SEEDS
    function_rows = []
    for va, function in functions.items():
        chunks = function['chunk_byte_ranges']
        assert chunks == audits[va]['chunk_byte_ranges']
        assert chunks[0]['start_va'] == hex(va)
        assert int(chunks[0]['start_va'], 16) + chunks[0]['size'] == int(function['end_va'], 16)
        decoded = [ins for chunk in chunks for ins in code(chunk)]
        sites = {ins.address for ins in decoded}
        exported_sites = {int(row['site_va'], 16) for row in function['assembly']}
        assert len(sites) == len(decoded) == len(function['assembly']) and sites == exported_sites
        assert all(row['is_code'] is True for row in function['assembly'])
        calls = {ins.address for ins in decoded if ins.mnemonic == 'call' and ins.op_str.startswith('0x')}
        reported_calls = [row for row in raw['calls'] if int(row['seed_va'], 16) == va]
        assert calls == {int(row['site_va'], 16) for row in reported_calls}
        for call in reported_calls:
            site, target = int(call['site_va'], 16), int(call['target_va'], 16)
            assert all_instructions[site].op_str == hex(target)
            for thunk in call['bridges']:
                assert target == int(thunk, 16)
                encoded = read(target, 5)
                destination = target + 5 + struct.unpack_from('<i', encoded, 1)[0]
                bridge(target, destination)
                target = destination
            assert target == int(call['implementation_va'], 16)
        function_rows.append(dict(seed_va=hex(va), chunks=len(chunks), instruction_count=len(decoded),
                                  direct_call_count=len(calls)))
        assembly.extend(['// 新导主体 ' + hex(va)] + [
            '// ' + hex(ins.address) + ' ' + ins.bytes.hex() + ' ' + ins.mnemonic + ' ' + ins.op_str
            for ins in decoded])
    for thunk in raw['verified_direct_bridges']:
        decoded = code(thunk)
        assert len(decoded) == 1 and decoded[0].mnemonic == 'jmp' and decoded[0].size == 5
        bridge(decoded[0].address, int(thunk['target_va'], 16))
    declared_bridges = {int(row['start_va'], 16) for row in raw['verified_direct_bridges']}
    assert set(bridges).issubset(declared_bridges)
    windows = list(raw['explicit_owner_windows']) + [row['owner_window']
        for edges in raw['incoming'].values() for row in edges if 'owner_window' in row]
    unique_windows = {}
    for window in windows:
        if window['owner_va'] is None:
            assert window['assembly'] == []
            continue
        decoded = []
        for row in window['assembly']:
            instructions = code(row['bytes'])
            assert len(instructions) == 1 and instructions[0].address == int(row['site_va'], 16)
            decoded.extend(instructions)
        assert decoded and int(window['site_va'], 16) in {ins.address for ins in decoded}
        assert all(a.address + a.size == b.address for a, b in zip(decoded, decoded[1:]))
        key = (window['owner_va'], decoded[0].address, decoded[-1].address + decoded[-1].size)
        unique_windows[key] = dict(owner=key[0], start_va=hex(key[1]), end_va=hex(key[2]))
    sources = {}
    for row in raw['reuse_sources']:
        path = DOCS / row['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        sources[row['path']] = load(path)
        assert digest(path.read_bytes()) == row['source_sha256']
    lifecycle = sources['专题/提示文本生命周期/证据/lifecycle.json']
    setter_path = DOCS / '专题/提示文本生命周期/证据/registration_setters.json'
    assert digest(setter_path.read_bytes()) == 'a2cdf1566ac6443d8c178d9e65ed63ef30f56487c6a28bf55c7d88bb129a4c60'
    setters = load(setter_path)
    assert setters['disk_sha256'] == SHA
    owner_rows = []
    for va, source, scope in ((0x8e1620, lifecycle, '文本节点消费'),
                              (0x8ea2b0, lifecycle, '空闲池释放'),
                              (0x6e2e60, lifecycle, '仅+40槽注册现场'),
                              (0x8e8720, setters, '仅+40条件setter')):
        function = next(row for row in source['functions'] if int(row['va'], 16) == va)
        chunks = function.get('chunk_byte_ranges', function['byte_ranges'])
        decoded = [ins for chunk in chunks for ins in code(chunk)]
        assert {ins.address for ins in decoded} == {int(row['va'], 16) for row in function['assembly']}
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']}
        assert declared == {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks}
        owner_rows.append(dict(owner=hex(va), instruction_count=len(decoded),
                               scope='复用本体字节；语义仅限' + scope))
        assembly.extend(['// 复用owner局部语义 ' + hex(va)] + [
            '// ' + hex(ins.address) + ' ' + ins.bytes.hex() + ' ' + ins.mnemonic + ' ' + ins.op_str
            for ins in decoded])
    for va, target in ((0x610797, 0x8e8720), (0x609537, 0x6e52d0)):
        bridge(va, target)
        ins = list(decoder.disasm(read(va, 5), va))
        assert len(ins) == 1 and ins[0].mnemonic == 'jmp'
        assembly.append('// 复用注册桥 ' + hex(va) + ' -> ' + hex(target))
    for row in raw['strings']:
        check(row['byte_audit'])
        width, payload = row['unit_width'], bytes.fromhex(row['payload_hex'])
        assert width in (1, 2) and len(payload) % width == 0
        assert row['nul_hex'] == bytes(width).hex()
        assert row['byte_audit']['idb_hex'] == (payload + bytes(width)).hex()
        assert all(payload[i:i + width] != bytes(width) for i in range(0, len(payload), width))
    virtual = raw['data_windows']
    assert len(virtual) == 1
    row = virtual[0]
    va, size = int(row['start_va'], 16), row['size']
    assert va == 0xacc3c4 and size == 4 and row['matching'] is None and row['disk_hex'] is None
    assert not any(rva <= va - base and va - base + size <= rva + raw_size
                   for _, rva, raw_size, _ in sections)
    assert sum(rva <= va - base and va - base + size <= rva + vsize
               for vsize, rva, _, _ in sections) == 1
    if row['idb_hex'] is not None:
        assert len(bytes.fromhex(row['idb_hex'])) == size
        assert digest(bytes.fromhex(row['idb_hex'])) == row['sha256']
    semantic_rows = []
    for site, expected in ANCHORS.items():
        ins = all_instructions[site]
        actual = (ins.mnemonic + ' ' + ins.op_str).rstrip()
        assert actual == expected, (hex(site), actual, expected)
        semantic_rows.append(dict(site_va=hex(site), text=actual, bytes_hex=ins.bytes.hex()))
    formal = load(HERE / 'formal_functions.json')
    expected_functions = []
    raw_sha = digest((HERE / 'bounded_raw.json').read_bytes())
    for index, function in enumerate(raw['functions']):
        chunks = function['chunk_byte_ranges']
        expected_functions.append(dict(
            va=function['seed_va'], end_va=function['end_va'], name=function['name'],
            status='仅导出；审阅见分级清单',
            assembly=[dict(row, va=row['site_va']) for row in function['assembly']],
            pseudocode=function['pseudocode'], decompile_error=function['decompile_error'],
            declared_chunks=[dict(start_va=c['start_va'], end_va=hex(int(c['start_va'], 16) + c['size']),
                                  is_main=c['start_va'] == function['seed_va']) for c in chunks],
            byte_ranges=[dict(c, va=c['start_va']) for c in chunks], bytes_match_disk=True,
            source='证据/bounded_raw.json', source_sha256=raw_sha, json_pointer=f'/functions/{index}'))
    assert formal == dict(schema='richonline-formal-functions-1', disk_sha256=SHA,
        source='bounded_raw.json', source_sha256=raw_sha,
        scope='仅机械适配；字段值与原证等价；语义级别另见函数审阅清单', functions=expected_functions,
        thunks=[dict(row, va=row['start_va'], target=row['target_va']) for row in raw['verified_direct_bridges']])
    manifest = load(HERE.parent / '函数审阅清单.json')
    assert manifest['disk_sha256'] == SHA and manifest['raw_source_sha256'] == raw_sha
    rows = manifest['functions']
    assert len(rows) == 9 and len({r['va'] for r in rows}) == 9
    expected_levels = {0x6e52d0: '局部路径已核', 0x6fabe0: '静态契约已审阅',
        0x6facf0: '静态契约已审阅', 0x6fad40: '静态契约已审阅', 0x8e02f0: '静态契约已审阅',
        0x8eaa30: '局部路径已核', 0x8eaaf0: '局部路径已核', 0x8e1620: '复用局部路径',
        0x8ea2b0: '复用局部路径'}
    assert {int(r['va'], 16): r['status'] for r in rows} == expected_levels
    assert len(manifest['windows']) == len(windows) == 22
    assert {(w['owner_va'], w['start'], w['end']) for w in manifest['windows']} == {
        (w['owner'], w['start_va'], w['end_va']) for w in unique_windows.values()}
    assert all(w['window_status'] == '仅有限窗口核验' for w in manifest['windows'])
    assert all(w['window_conclusion'] == '调用点参数与后续局部操作已核；不能覆盖owner整函数'
               and w['evidence'] == '证据/bounded_raw.json' for w in manifest['windows'])
    raw_window_rows = [dict(owner_va=w['owner_va'], start=w['assembly'][0]['site_va'],
                            end=hex(int(w['assembly'][-1]['site_va'], 16)
                                    + w['assembly'][-1]['bytes']['size']), site=w['site_va'])
                       for w in windows]
    assert [dict(owner_va=w['owner_va'], start=w['start'], end=w['end'], site=w['site'])
            for w in manifest['windows']] == raw_window_rows
    assert all({'va', 'address', 'ea', '地址', 'status', 'review_status', '状态',
                'conclusion', '结论', 'owner'}.isdisjoint(w) for w in manifest['windows'])
    # 只调用中央遍历器；不运行会写台账的 main。
    merger_path = DOCS / '全量分析/merge_reviews.py'
    spec = importlib.util.spec_from_file_location('readonly_review_merger', merger_path)
    merger = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(merger)
    def recognized_reviews(data):
        found = []
        for node, pointer in merger.walk(data):
            address = node.get('va', node.get('address', node.get('ea', node.get('地址'))))
            status = node.get('status', node.get('review_status', node.get('状态')))
            conclusion = node.get('conclusion', node.get('结论'))
            bounds = merger.explicit_range(node, status) if address is None else None
            if bounds is not None:
                address = bounds[0]
            if address is not None and isinstance(status, str) and isinstance(conclusion, str):
                found.append((pointer, address))
        return found
    central_rows = recognized_reviews(manifest)
    assert central_rows == [(f'/functions/{i}', r['va']) for i, r in enumerate(rows)]
    central_topic_counts = {}
    for path in sorted(HERE.parent.rglob('*.json')):
        found = recognized_reviews(json.loads(path.read_text('utf-8-sig')))
        assert all(not pointer.startswith('/windows/') for pointer, _ in found)
        central_topic_counts[path.relative_to(HERE.parent).as_posix()] = len(found)
    author_result = load(HERE.parent / '验证结果.json')
    assert author_result['status'] == 'PASS' and author_result['disk_sha256'] == SHA
    assert author_result['raw_source_sha256'] == raw_sha
    assert author_result['fresh_functions'] == 7 and author_result['current_chunks'] == 8
    assert author_result['finite_windows'] == 22 and author_result['verified_e9_bridges'] == 14
    author_audit = load(HERE / 'bounded_audit.json')
    assert author_audit['disk_sha256'] == SHA and author_audit['fresh_functions'] == 7
    assert author_audit['current_chunks'] == 8 and author_audit['verified_e9_bridges'] == 14
    binding = author_audit['binding_reuse']
    assert {int(r['owner_va'], 16) for r in binding['reused_paths']} == {0x6e2e60, 0x8e8720}
    assert {int(r['va'], 16): int(r['target'], 16) for r in binding['bridges']} == {
        0x610797: 0x8e8720, 0x609537: 0x6e52d0}
    final_bindings = {}
    for relative, expected in FINAL_SHA.items():
        path = HERE.parent / relative
        assert path.resolve().is_relative_to(HERE.parent.resolve())
        actual = digest(path.read_bytes())
        assert actual == expected, (relative, '终稿已改变，需要重新人工审阅')
        final_bindings[relative] = actual
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//')
                   for line in path.read_text('utf-8').splitlines())
    status = 'PASS' if FINAL_SHA else '字节与语义锚预核通过，终稿待审'
    result = dict(status=status, pe_sha256=SHA,
                  functions=function_rows, reused_owners=owner_rows,
                  semantic_anchors=semantic_rows,
                  formal_adapter_equivalent=True, reviewed_final_sha256=final_bindings,
                  central_manifest_review_records=len(central_rows),
                  finite_windows_excluded_from_central_reviews=True,
                  central_readonly_topic_counts=central_topic_counts,
                  review_levels={'静态契约已审阅': 4, '局部路径已核': 3, '复用局部路径': 2},
                  exported_window_records=len(windows), unique_window_count=len(unique_windows),
                  unique_bridge_count=len(bridges), finite_windows=list(unique_windows.values()),
                  sources=snapshots, unique_ranges=list(ranges.values()),
                  boundary='静态虚拟池头不当运行状态；owner全块字节不当全语义；未运行游戏')
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], len(result['functions']), result['unique_bridge_count'])
