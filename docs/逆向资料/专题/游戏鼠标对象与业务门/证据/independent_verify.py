"""独立解析当前PE并重解码；不调用IDA，不导入作者验证器。"""
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
FRESH = {0x6baac0, 0x6516e0, 0x651960, 0x653850}
REUSED = {0x6278f0, 0x6bad80, 0x691cc0}
FINAL_SHA = {
    '00_有限采证实施计划.txt': '5c2a47f28b8b6c2bd15ec912b7f4a3f94d1b46bf6fdf93073eefd8d5d79d1465',
    '01_阅读入口与证据范围.txt': 'd5dc139052c5b397c17ca1abc3ecc26750d8067a8796682cb7d4c824b37d70ae',
    '02_对象字段与输入门.txt': '6af71cf83d8f181abd3a35c1cd157fc5cccc30afc1332f6aa1d584588b8a7c5a',
    '03_三个业务入口的分支.txt': '0e43d34682b11d8c15ec7be94c53e341bff73d20fdb104b6875c3e2b8b3d1095',
    '04_证据复核与合作边界.txt': '72687aa6056f68576129c65b985ad9792ec61dd4544c0be2b42221f6fbb320c8',
    '函数审阅清单.json': 'cbbf6f961dae32e7d8b0cead5476fc85819c822ebe46ab955895be59ebdbf8c6',
    '证据/bounded_audit.json': '6669b82709443b019666841b805481715f0cc400f817a38c43ff864456c59de8',
    '证据/bounded_raw.json': '64c2ab780f3cbc1636e256e1d76a6d0abdf21ab7b8b9ff0a1ac33a251fd815b9',
    '证据/destructor_raw.json': 'dd96aa4eb198276e82e2bd23eb52dcc683de8c0d70d8b894a432d4e2aac8f54a',
    '证据/exit_dependency_raw.json': 'a8cced5fe7a8436365ddfa07b97fc5794c2e9d20566e194c2e8af63e7302c8d8',
    '证据/exit_owner_context.json': 'd648b0a9ec5ed0b8461003bbf1e3c988f3e854d4aee94009bbbfb523e2b09eba',
    '证据/export_bounded.py': 'f9d4c84e8f0a5edbb000fec9cb3d633f7c7cf77e089c33ca4bee30fe1725f78a',
    '证据/formal_functions.json': 'df436086451ce26afabeddb33d0bc576f9953285428eb70b6498b49587ecf5e6',
    '证据/reused_audit.json': 'b75022c1300d3d48fd08713b0a539c54935e0461fd2014f2f420bb62c39d4960',
    '证据/verify_bounded.py': '4f5029cbafb6c39a6e3ac4a31f558c386be183d75cab06d1fbc97627c5b504e7',
    '验证结果.json': 'be23d234256e73f1fff553c0681e0f621ae9f2ebf443a81021336329152bc879',
}
ANCHORS = {
    0x6baace: 'push 0x190',
    0x6baad3: 'push 0',
    0x6baad8: 'add eax, 0xc',
    0x6baadc: 'call 0x60ffdb',
    0x627920: 'cmp dword ptr [0xa766c0], 0',
    0x627929: 'push 0x1ac',
    0x627940: 'cmp dword ptr [ebp - 0x14], 0',
    0x627949: 'call 0x60046e',
    0x62796a: 'mov dword ptr [0xa766c0], ecx',
    0x627970: 'mov eax, dword ptr [0xa766c0]',
    0x691cd1: 'mov al, byte ptr [eax]',
    0x6bad98: 'mov eax, dword ptr [eax + 0x19c]',
    0x6bad9e: 'cmp eax, dword ptr [edx + ecx*4 + 0xc]',
    0x6bada2: 'je 0x6bade3',
    0x6badb1: 'mov dword ptr [ecx + 0x19c], edx',
    0x6badc4: 'mov dword ptr [eax + 0x1a0], ecx',
    0x6badd6: 'call dword ptr [0xad3f88]',
    0x6badf1: 'ret 4',
    0x7a47c1: 'mov cl, byte ptr [ebp + 8]',
    0x7a47c4: 'mov byte ptr [eax], cl',
    0x6249ea: 'cmp dword ptr [0xa766c0], 0',
    0x6249f3: 'mov ecx, dword ptr [0xa766c0]',
    0x624a14: 'push 1',
    0x624a1c: 'call 0x60def7',
    0x624a33: 'mov dword ptr [0xa766c0], 0',
    0x651700: 'push 0x26',
    0x651721: 'mov eax, 3',
    0x651817: 'push 0',
    0x651820: 'call 0x60ba94',
    0x65183f: 'call 0x60dd35',
    0x651849: 'je 0x65188b',
    0x651861: 'mov word ptr [ebp - 0x12], ax',
    0x651868: 'mov byte ptr [ebp - 0x10], al',
    0x65186e: 'mov byte ptr [ebp - 0xf], cl',
    0x651875: 'mov word ptr [ebp - 0xe], dx',
    0x651879: 'push 8',
    0x65187f: 'call 0x610977',
    0x651887: 'xor eax, eax',
    0x65188b: 'mov eax, 2',
    0x65197b: 'push 3',
    0x65199c: 'mov eax, 3',
    0x6519ee: 'lea eax, [ebp - 0xc]',
    0x6519fb: 'call 0x60fb44',
    0x651ab0: 'mov ecx, dword ptr [eax + 0xe28]',
    0x651ae0: 'mov ecx, dword ptr [ecx + eax*4 + 0xe00]',
    0x651aff: 'push 1',
    0x651b08: 'call 0x60ba94',
    0x651b27: 'call 0x60dd35',
    0x651b31: 'je 0x651b73',
    0x651b49: 'mov word ptr [ebp - 0x22], ax',
    0x651b50: 'mov byte ptr [ebp - 0x20], cl',
    0x651b56: 'mov byte ptr [ebp - 0x1f], dl',
    0x651b5d: 'mov word ptr [ebp - 0x1e], ax',
    0x651b61: 'push 8',
    0x651b67: 'call 0x610977',
    0x651b73: 'mov eax, 2',
    0x65388b: 'push 0x12',
    0x6538c9: 'mov eax, 3',
    0x6538e2: 'jne 0x6539e6',
    0x653919: 'cmp dword ptr [ebp - 0x20], 1',
    0x653958: 'call 0x60dd35',
    0x653962: 'je 0x6539af',
    0x65397a: 'mov word ptr [ebp - 0x36], ax',
    0x653981: 'mov byte ptr [ebp - 0x34], al',
    0x653987: 'mov byte ptr [ebp - 0x33], cl',
    0x65398d: 'mov byte ptr [ebp - 0x32], dl',
    0x653990: 'push 8',
    0x653996: 'call 0x610977',
    0x6539b5: 'jle 0x6539e4',
    0x6539f5: 'cmp dword ptr [ebp - 0x28], -1',
    0x653a11: 'mov word ptr [ebp - 0x46], ax',
    0x653a18: 'mov byte ptr [ebp - 0x44], cl',
    0x653a1e: 'mov byte ptr [ebp - 0x43], dl',
    0x653a24: 'mov byte ptr [ebp - 0x42], al',
    0x653a27: 'push 8',
    0x653a2d: 'call 0x610977',
    0x653a43: 'mov eax, 2',
    0x6298a1: 'call 0x604627',
    0x6298a9: 'and eax, 1',
    0x6298ac: 'je 0x6298ba',
    0x6298b2: 'call 0x604cfd',
    0x6298ba: 'mov eax, dword ptr [ebp - 4]',
    0x6298ca: 'ret 4',
    0x6bab18: 'mov dword ptr [ebp - 8], 0',
    0x6bab2a: 'cmp dword ptr [ebp - 8], 0x64',
    0x6bab2e: 'jae 0x6bab59',
    0x6bab36: 'cmp dword ptr [edx + ecx*4 + 0xc], 0',
    0x6bab3b: 'je 0x6bab57',
    0x6bab45: 'mov edx, dword ptr [ecx + eax*4 + 0xc]',
    0x6bab4a: 'call dword ptr [0xad3acc]',
    0x6bab57: 'jmp 0x6bab21',
    0x7a2b71: 'call 0x604bb8',
    0x7a2b7b: 'je 0x7a2bc9',
    0x7a2b7d: 'cmp dword ptr [0xacc3c8], 0',
    0x7a2b9c: 'call 0x60041e',
    0x7a2ba6: 'je 0x7a2bc9',
    0x7a2ba8: 'push 0',
    0x7a2bb1: 'call 0x5ff523',
    0x7a2bc4: 'jmp 0x7a2e1b',
    0x7a2bc9: 'call 0x604bb8',
    0x7a2bd3: 'je 0x7a2be3',
    0x7a2bd5: 'push 1',
    0x7a2bde: 'call 0x5ff523',
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
    instructions, ranges, bridges, sources, assembly = {}, {}, {}, {}, []

    def read(va, size):
        positions = [off + va - base - rva for _, rva, raw, off in sections
                     if rva <= va - base and va - base + size <= rva + raw]
        assert len(positions) == 1
        assert positions[0] + size <= len(image)
        return image[positions[0]:positions[0] + size]

    def load(path):
        content = path.read_bytes()
        sources[str(path.relative_to(ROOT))] = digest(content)
        return json.loads(content)

    def code_at(va, size):
        content = read(va, size)
        decoded = list(decoder.disasm(content, va))
        assert sum(ins.size for ins in decoded) == size
        ranges[va, size] = dict(start_va=hex(va), size=size, sha256=digest(content))
        for ins in decoded:
            assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        return decoded

    def check(row):
        va = int(row.get('start_va', row.get('va')), 16)
        content = read(va, row['size'])
        assert row['matching'] is True and content.hex() == row['idb_hex'] == row['disk_hex']
        assert 'sha256' not in row or digest(content) == row['sha256']
        return code_at(va, row['size'])

    def bridge(va, target):
        content = read(va, 5)
        assert content[0] == 0xe9
        assert va + 5 + struct.unpack_from('<i', content, 1)[0] == target
        assert bridges.setdefault(va, target) == target

    raw = load(HERE / 'bounded_raw.json')
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['topic'] == '游戏鼠标对象与业务门' and raw['disk_sha256'] == SHA
    exporter = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    assert digest(exporter.read_bytes()) == raw['exporter_sha256']
    sources[str(exporter.relative_to(ROOT))] = raw['exporter_sha256']
    assert {int(row['seed_va'], 16) for row in raw['seeds']} == FRESH | REUSED
    assert {int(row['seed_va'], 16) for row in raw['functions']} == FRESH
    assert {int(row['seed_va'], 16) for row in raw['reused_seeds']} == REUSED
    audits = {int(row['seed_va'], 16): row['chunk_byte_ranges'] for row in raw['current_chunk_audits']}
    assert set(audits) == FRESH | REUSED
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert digest(path.read_bytes()) == source['source_sha256']
        sources[str(path.relative_to(ROOT))] = source['source_sha256']
    reuse_path = DOCS / '专题/40B0系列事件/证据/request_helpers.json'
    reuse = load(reuse_path)
    assert reuse['disk_sha256'] == SHA
    functions = {int(row['seed_va'], 16): row for row in raw['functions']}
    for row in reuse['functions']:
        va = int(row['va'], 16)
        if va in REUSED:
            functions[va] = row
    function_rows = []
    for va, function in functions.items():
        chunks = function.get('chunk_byte_ranges', function.get('byte_ranges'))
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in audits[va]]
        if va in FRESH:
            assert chunks == audits[va]
        else:
            assert {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']} == {
                (int(c['start_va'], 16), int(c['start_va'], 16) + c['size']) for c in audits[va]}
        decoded = [ins for chunk in audits[va] for ins in check(chunk)]
        assert {ins.address for ins in decoded} == {
            int(row.get('site_va', row.get('va')), 16) for row in function['assembly']}
        assert len(decoded) == len(function['assembly'])
        calls = {ins.address for ins in decoded if ins.mnemonic == 'call' and (
            ins.op_str.startswith('0x') or ins.op_str == 'dword ptr [0xad3f88]')}
        reported = [c for c in raw['calls'] if int(c['seed_va'], 16) == va]
        assert calls == {int(c['site_va'], 16) for c in reported}
        for call in reported:
            target = int(call['target_va'], 16)
            site = int(call['site_va'], 16)
            actual = instructions[site].op_str
            assert actual == hex(target) or target == 0xad3f88 and actual == 'dword ptr [0xad3f88]'
            for thunk in call['bridges']:
                assert target == int(thunk, 16)
                content = read(target, 5)
                destination = target + 5 + struct.unpack_from('<i', content, 1)[0]
                bridge(target, destination)
                target = destination
            assert target == int(call['implementation_va'], 16)
        function_rows.append(dict(seed_va=hex(va), reused=va in REUSED,
                                  chunks=len(chunks), instruction_count=len(decoded),
                                  direct_or_iat_calls=len(calls)))
        assembly.extend(['// 主体 ' + hex(va)] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    for row in raw['verified_direct_bridges']:
        decoded = check(row)
        assert len(decoded) == 1 and decoded[0].mnemonic == 'jmp'
        bridge(decoded[0].address, int(row['target_va'], 16))
    assert len(bridges) == len(raw['verified_direct_bridges']) == 48
    windows = list(raw['explicit_owner_windows']) + [row['owner_window']
        for edges in raw['incoming'].values() for row in edges if 'owner_window' in row]
    unique_windows = {}
    for window in windows:
        if window['owner_va'] is None:
            assert not window['assembly']
            continue
        decoded = []
        for row in window['assembly']:
            current = check(row['bytes'])
            assert len(current) == 1 and current[0].address == int(row['site_va'], 16)
            decoded.extend(current)
        assert int(window['site_va'], 16) in {i.address for i in decoded}
        assert all(a.address + a.size == b.address for a, b in zip(decoded, decoded[1:]))
        key = (window['owner_va'], decoded[0].address, decoded[-1].address + decoded[-1].size)
        unique_windows[key] = dict(owner_va=key[0], start=hex(key[1]), end=hex(key[2]))
    assert len(windows) == 206
    assert len(raw['data_windows']) == 1
    data = raw['data_windows'][0]
    assert data['start_va'] == '0xa766c0' and data['size'] == 4
    assert read(0xa766c0, 4) == bytes(4) and data['idb_hex'] == data['disk_hex'] == '00000000'
    assert data['matching'] is True and data['sha256'] == digest(bytes(4))
    input_data = load(DOCS / '专题/输入与快捷键/ida_input_raw.json')
    gate = input_data['functions']['0x7a47b0']
    gate_code = []
    for row in gate['ranges']:
        va, end = int(row['start'], 16), int(row['end'], 16)
        assert read(va, end - va).hex() == row['idb_bytes_hex']
        gate_code.extend(code_at(va, end - va))
    assert {i.address for i in gate_code} == {int(r['ea'], 16) for r in gate['instructions']}
    input_owner = input_data['functions']['0x7a29e0']
    for row in input_owner['ranges']:
        va, end = int(row['start'], 16), int(row['end'], 16)
        assert read(va, end - va).hex() == row['idb_bytes_hex']
    input_window = code_at(0x7a2b71, 0x7a2be3 - 0x7a2b71)
    assert {i.address for i in input_window} == {int(r['ea'], 16) for r in input_owner['instructions']
        if 0x7a2b71 <= int(r['ea'], 16) < 0x7a2be3}
    bridge(0x5ff523, 0x7a47b0)
    exit_source = load(DOCS / '专题/启动线程与退出/证据/startup_exit_functions.json')
    exit_function = next(f for f in exit_source['functions'] if f['va'] == '0x624080')
    exit_code = code_at(0x6249ea, 0x624a3d - 0x6249ea)
    assert {i.address for i in exit_code} == {int(r['va'], 16) for r in exit_function['assembly']
        if 0x6249ea <= int(r['va'], 16) < 0x624a3d}
    shutdown_source = load(DOCS / '专题/事件文字记录器/证据/shutdown.json')
    assert shutdown_source['disk_sha256'] == SHA
    shutdown = next(f for f in shutdown_source['functions'] if f['va'] == '0x624080')
    shutdown_chunks = shutdown['chunk_byte_ranges']
    assert {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in shutdown['declared_chunks']} == {
        (int(c.get('start_va', c.get('va')), 16),
         int(c.get('start_va', c.get('va')), 16) + c['size']) for c in shutdown_chunks}
    shutdown_decoded = [ins for c in shutdown_chunks for ins in check(c)]
    assert {i.address for i in shutdown_decoded} == {int(r['va'], 16) for r in shutdown['assembly']}
    for label, decoded in (('复用首BYTE setter', gate_code), ('输入局部窗口', input_window),
                           ('退出局部窗口', exit_code)):
        assembly.extend(['// ' + label] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    exit_dependency = load(HERE / 'exit_dependency_raw.json')
    assert exit_dependency['disk_sha256'] == SHA
    assert {f['va'] for f in exit_dependency['functions']} == {'0x60def7', '0x629890'}
    destructor = load(HERE / 'destructor_raw.json')
    assert destructor['disk_sha256'] == SHA
    assert {f['va'] for f in destructor['functions']} == {'0x6bab00'}
    dependency_rows = []
    for function in exit_dependency['functions'] + destructor['functions']:
        chunks = function['chunk_byte_ranges']
        assert {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']} == {
            (int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks}
        decoded = [i for c in chunks for i in check(c)]
        assert {i.address for i in decoded} == {int(r['va'], 16) for r in function['assembly']}
        assert {i.address for i in decoded if i.mnemonic == 'call'} == {
            int(c['site'], 16) for c in function['calls']}
        for call in function['calls']:
            target = int(call['target'], 16)
            actual = instructions[int(call['site'], 16)].op_str
            assert actual == hex(target) or target == 0xad3acc and actual == 'dword ptr [0xad3acc]'
            for thunk in call['thunks']:
                assert target == int(thunk, 16)
                destination = target + 5 + struct.unpack_from('<i', read(target, 5), 1)[0]
                bridge(target, destination)
                target = destination
            assert target == int(call['implementation'], 16)
        dependency_rows.append(dict(seed_va=function['va'], instruction_count=len(decoded)))
        assembly.extend(['// 退出短依赖 ' + function['va']] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in decoded])
    bridge(0x60def7, 0x629890)
    for thunk in exit_dependency['thunks'] + destructor['thunks']:
        check(thunk)
        bridge(int(thunk['va'], 16), int(thunk['target'], 16))
    context = load(HERE / 'exit_owner_context.json')
    assert context['disk_sha256'] == SHA
    assert len(context['windows']) == 3
    for window in context['windows']:
        assert window['owner_va'] == '0x624080'
        decoded = check(window)
        assert int(window['start_va'], 16) + window['size'] == int(window['end_va'], 16)
        assert {i.address for i in decoded} == {int(r['site_va'], 16) for r in window['assembly']}
        for row in window['assembly']:
            check(dict(row['bytes'], start_va=row['site_va']))
    assert [b['block_start_va'] for b in context['controls'][0]['blocks']] == [
        '0x624a14', '0x6249f3', '0x6249ea']
    imports_rva = struct.unpack_from('<I', image, nt + 24 + 104)[0]
    descriptor, imported = base + imports_rva, []
    def ascii_z(va):
        content = bytearray()
        while read(va, 1) != b'\0':
            content += read(va, 1)
            va += 1
        return content.decode('ascii')
    while any(struct.unpack('<5I', read(descriptor, 20))):
        ilt, _, _, dll_rva, iat = struct.unpack('<5I', read(descriptor, 20))
        index = 0
        while (value := struct.unpack('<I', read(base + (ilt or iat) + index * 4, 4))[0]):
            slot = base + iat + index * 4
            if slot in (0xad3f88, 0xad3acc):
                assert not value & 0x80000000
                imported.append(dict(slot_va=hex(slot), dll=ascii_z(base + dll_rva),
                                     symbol=ascii_z(base + value + 2)))
            index += 1
        descriptor += 20
    assert sorted(imported, key=lambda row: row['slot_va']) == [
        dict(slot_va='0xad3acc', dll='GDI32.dll', symbol='DeleteObject'),
        dict(slot_va='0xad3f88', dll='USER32.dll', symbol='SetCursor')]
    semantic_rows = []
    for site, expected in ANCHORS.items():
        instruction = instructions[site]
        actual = (instruction.mnemonic + ' ' + instruction.op_str).rstrip()
        assert actual == expected, (hex(site), actual, expected)
        semantic_rows.append(dict(site_va=hex(site), text=actual, bytes_hex=instruction.bytes.hex()))
    raw_sha = digest((HERE / 'bounded_raw.json').read_bytes())
    formal = load(HERE / 'formal_functions.json')
    expected_functions = []
    for index, function in enumerate(raw['functions']):
        chunks = function['chunk_byte_ranges']
        expected_functions.append(dict(va=function['seed_va'], end_va=function['end_va'],
            name=function['name'], status='仅导出；审阅见分级清单',
            assembly=[dict(row, va=row['site_va']) for row in function['assembly']],
            pseudocode=function['pseudocode'], decompile_error=function['decompile_error'],
            declared_chunks=[dict(start_va=c['start_va'], end_va=hex(int(c['start_va'], 16) + c['size']),
                is_main=c['start_va'] == function['seed_va']) for c in chunks],
            byte_ranges=[dict(c, va=c['start_va']) for c in chunks], bytes_match_disk=True,
            source='证据/bounded_raw.json', source_sha256=raw_sha, json_pointer=f'/functions/{index}'))
    assert formal == dict(schema='richonline-formal-functions-1', disk_sha256=SHA,
        source_sha256=raw_sha, functions=expected_functions,
        thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']],
        scope='纯机械适配；原始汇编、伪码及全部声明字节保留；不是语义认证')
    manifest = load(HERE.parent / '函数审阅清单.json')
    assert manifest['disk_sha256'] == SHA and manifest['raw_source_sha256'] == raw_sha
    assert len(manifest['functions']) == 9
    assert {int(r['va'], 16): r['status'] for r in manifest['functions']} == {
        0x6baac0: '静态契约已审阅', 0x6516e0: '局部路径已核', 0x651960: '局部路径已核',
        0x653850: '局部路径已核', 0x6278f0: '静态契约已审阅', 0x6bad80: '静态契约已审阅',
        0x691cc0: '静态契约已审阅', 0x629890: '静态契约已审阅', 0x6bab00: '静态契约已审阅'}
    expected_windows = []
    for window in windows:
        if window['owner_va'] is None:
            continue
        last = window['assembly'][-1]
        expected_windows.append(dict(owner_va=window['owner_va'], start=window['assembly'][0]['site_va'],
            end=hex(int(last['site_va'], 16) + last['bytes']['size']), site=window['site_va'],
            window_status='仅有限窗口核验', window_conclusion='字节与局部调用点已核；不代表owner完整语义'))
    assert len(expected_windows) == 204
    expected_windows += [dict(owner_va=w['owner_va'], start=w['start_va'], end=w['end_va'],
        window_status='仅退出有限窗口', window_conclusion='两层前驱与释放实参已核，不计624080整函数覆盖')
        for w in context['windows']]
    assert manifest['windows'] == expected_windows
    assert all({'va', 'address', 'ea', '地址', 'status', 'review_status', '状态',
                'conclusion', '结论'}.isdisjoint(w) for w in manifest['windows'])
    merger_path = DOCS / '全量分析/merge_reviews.py'
    spec = importlib.util.spec_from_file_location('readonly_review_merger', merger_path)
    merger = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(merger)
    central_counts = {}
    for path in sorted(HERE.parent.rglob('*.json')):
        found = []
        for node, pointer in merger.walk(json.loads(path.read_text('utf-8-sig'))):
            address = node.get('va', node.get('address', node.get('ea', node.get('地址'))))
            status = node.get('status', node.get('review_status', node.get('状态')))
            conclusion = node.get('conclusion', node.get('结论'))
            bounds = merger.explicit_range(node, status) if address is None else None
            if bounds is not None:
                address = bounds[0]
            if address is not None and isinstance(status, str) and isinstance(conclusion, str):
                found.append((pointer, address))
        if path.name == '函数审阅清单.json':
            assert found == [(f'/functions/{i}', r['va']) for i, r in enumerate(manifest['functions'])]
        else:
            assert not found, (str(path), found)
        central_counts[path.relative_to(HERE.parent).as_posix()] = len(found)
    author = load(HERE.parent / '验证结果.json')
    audit = load(HERE / 'bounded_audit.json')
    assert author == {k: v for k, v in audit.items() if k != 'reuse_sources'}
    assert author['status'] == 'PASS' and author['disk_sha256'] == SHA
    assert author['raw_source_sha256'] == raw_sha
    for key, expected in dict(fresh_functions=4, reused_seeds=3, current_chunks=8,
        verified_e9_bridges=48, finite_windows=204, raw_window_records=206,
        ownerless_window_records=2, supplemental_functions=2, supplemental_thunk_functions=1,
        exit_windows=3).items():
        assert author[key] == expected, key
    assert author['review_levels'] == {'静态契约已审阅': 6, '局部路径已核': 3}
    reused_audit = load(HERE / 'reused_audit.json')
    for row in reused_audit['reused_seeds']:
        source = DOCS / row['source']
        assert digest(source.read_bytes()) == row['source_sha256']
        original = json.loads(source.read_bytes())
        for key in row['json_pointer'].strip('/').split('/'):
            original = original[int(key)] if isinstance(original, list) else original[key]
        assert original['va'] == row['seed_va']
        assert [(r['start_va'], r['size']) for r in row['current_chunks']] == [
            (r['start_va'], r['size']) for r in audits[int(row['seed_va'], 16)]]
        for chunk in row['current_chunks']:
            assert digest(read(int(chunk['start_va'], 16), chunk['size'])) == chunk['sha256']
    assert {r['owner_va'] for r in reused_audit['input_paths']} == {'0x7a29e0', '0x7a47b0'}
    input_sha = digest((DOCS / '专题/输入与快捷键/ida_input_raw.json').read_bytes())
    for row in reused_audit['input_paths']:
        assert row['source_sha256'] == input_sha
        assert row['json_pointer'] == '/functions/' + row['owner_va']
        assert input_data['functions'][row['owner_va']]['ea'] == row['owner_va']
    assert reused_audit['exit_source_sha256'] == digest((DOCS / '专题/事件文字记录器/证据/shutdown.json').read_bytes())
    assert reused_audit['exit_context_source_sha256'] == digest((HERE / 'exit_owner_context.json').read_bytes())
    for row in reused_audit['supplemental']:
        assert digest((HERE / row['source']).read_bytes()) == row['source_sha256']
        original = json.loads((HERE / row['source']).read_bytes())
        for key in row['json_pointer'].strip('/').split('/'):
            original = original[int(key)] if isinstance(original, list) else original[key]
        assert original['va'] == row['seed_va']
        assert [(r['start_va'], r['size']) for r in row['current_chunks']] == [
            (r['va'], r['size']) for r in original['chunk_byte_ranges']]
        for chunk in row['current_chunks']:
            assert digest(read(int(chunk['start_va'], 16), chunk['size'])) == chunk['sha256']
    for chunk in reused_audit['exit_owner_chunks']:
        assert digest(read(int(chunk['start_va'], 16), chunk['size'])) == chunk['sha256']
    final_bindings = {}
    for relative, expected in FINAL_SHA.items():
        path = HERE.parent / relative
        actual = digest(path.read_bytes())
        assert actual == expected, (relative, '终稿改变，需要重新人工复核')
        final_bindings[relative] = actual
    result = dict(status='PASS' if FINAL_SHA else '字节预核通过；终稿待审', pe_sha256=SHA,
        functions=function_rows, finite_window_records=len(windows), unique_windows=list(unique_windows.values()),
        exit_dependencies=dependency_rows, exit_context_windows=len(context['windows']),
        formal_adapter_equivalent=True, central_readonly_topic_counts=central_counts,
        classified_function_records=9, classified_window_records=0,
        valid_raw_windows=204, ownerless_raw_windows=2, manifest_windows=207,
        unique_bridges=len(bridges), semantic_anchors=semantic_rows, imports=imported,
        sources=sources, unique_ranges=list(ranges.values()), reviewed_final_sha256=final_bindings,
        static_global='A766C0当前磁盘4B零初值；不证明运行状态',
        boundary='只审指定主体与路径；退出仅读局部；未运行游戏')
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], len(result['functions']), result['unique_bridges'])
