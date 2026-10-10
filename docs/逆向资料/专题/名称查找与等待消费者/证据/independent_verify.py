"""名称查找专题独立磁盘复核；原证未就绪或终稿未冻结时不输出PASS。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x6b20a0, 0x6b81d0, 0x6ad9f0, 0x73d560}
REUSED = {0x6aebe0}
EXTRA = {0x858e50, 0x858ea0, 0x922830, 0x9228e0, 0x85b800, 0x85b870}
FINAL_SHA = {
    '独立审阅.txt': '1899adf659dd5f66c35db1b7b6a8bed11d120955c836360a33226b9508c46016',
    '独立语义复核.txt': '9ff18fe2212313253abba957b225c19eb421fc8a11de93e405aa095b40bc43fd',
    '00_有限采证实施计划.txt': '321d0e2650ffce351f16f768de444c0526ea332fe57d9bbc227b03e1cb7d19f1',
    '00_阅读入口.txt': '6919dc79fbe9884e86e24a52051b8a3d84c886803db1a7d4b5ff582935b4f9aa',
    '01_名称查找接口与返回边界.txt': '438b041070bb6a9576ee72c4c8357eb4b5d6858fa06caeab5dce2b7001037825',
    '02_两组界面消费者与低字节ABI.txt': '1868714e54dcb2a9c686ae3ee2cfb30c1fccefee5d59c3bf2fac82b4ae325da6',
    '03_邮件与记录消费者对照.txt': '17084132c41ca3fea5f5ff22f2d62edbd5f33051f7433fb0d04c0f6338185340',
    '04_证据分层与后续缺口.txt': '339ff0ce69d129c2019cebea3282ecca3a982ec8d2295785304fade4c68f264d',
    '05_名称容器与比较器补证.txt': 'f74f5c034586943605d5fd5cfed3f1bd34423286f342324b618a05d9399971e8',
    'function_review.json': 'ed821c1f427bac49b48d263bbf7baff55b81b58b714b193c4ea54ae67466f180',
    '证据/author_validation.json': 'f2df17acfad4d51fc9d29cc439d4fc50c4c51517c01805f0593d6978210eb792',
    '证据/bounded_raw.json': '15be75a1ad6266da6a0df0010c3316ec45619f2e78f05ae691ddc50f4a50c1d6',
    '证据/build_artifacts.py': 'b1b19012231956ffbb66eb1e92a19b9d56c550ab31a9265f4580fe1fc011cd6f',
    '证据/container_formal.json': '932a0c858758693631402e92e517f23bb0158a1dad2c78bd0626877e96022ff5',
    '证据/container_template_navigation.json': '35f2b0699f756d865e1abcc5e4e2ad7922e6b73874b23279a27d37043631c96e',
    '证据/export_bounded.py': '81d24d58390fc223f1b326883bf84a6bd43a5e254ac4fe6a1224b851acee3e81',
    '证据/export_container.py': '39a4167af1b34291e6ffa4394af76e6e209651baf2a95efcad26a5883c992cf9',
    '证据/formal_functions.json': 'cd9940a7efd72bd7c10cb1f21f6734bdd490bf98d8f3808b78848ac0b190b193',
    '证据/network_production_navigation.json': '01180775911ca89665fec9064b4fcfba5f6fe1017d2d90f3f24f4e946d8c20c1',
    '证据/reused_raw.json': 'ee58756789775fbdc477e3ce6537fedbc1de5450956bdf9d6c59381581c71d26',
    '证据/source_navigation.json': 'a5116ed511d7954af20ee1c66925bc2cf9a69cdbcb48c93d929ce17337c8f843',
    '证据/supplement_formal.json': 'de0695a485ae5f34f83e3239bfdb8711a42c495079c78f65ad39970d09952551',
    '证据/supplement_raw.json': '5211fcf04136f28f57a91453be58a22d8f01304f98393371726d06a4ef9770bf',
    '证据/validate_author.py': '10ada2ae050e718a24e49a4fd308fcfa2f118a2a7222319d65fd27febb7fbac4',
    '证据/historical_crt_sources.json': 'fd644f887ebb1eb619726868054fd2529deccd0bdfc9cb711a133895e15f0235',
    '证据/container_dependency/bounded_raw.json': '50b81df4ceb2447338eee2df17334ebc7cc75944b9cc725dc30db056d05071cc',
}
PREVIEW_SHA = {
    '00_有限采证实施计划.txt': '321d0e2650ffce351f16f768de444c0526ea332fe57d9bbc227b03e1cb7d19f1',
    '00_阅读入口.txt': '295bf339e057a9f0b3b4acd0d889c570d26f79c83c463786d8ac3a60dcfc2300',
    '01_名称查找接口与返回边界.txt': '2a6a60c64d5c3ed1b4a216b212c30d4f46d2354adb55ec372ae55e8da648d115',
    '02_两组界面消费者与低字节ABI.txt': '1868714e54dcb2a9c686ae3ee2cfb30c1fccefee5d59c3bf2fac82b4ae325da6',
    '03_邮件与记录消费者对照.txt': '17084132c41ca3fea5f5ff22f2d62edbd5f33051f7433fb0d04c0f6338185340',
    '04_证据分层与后续缺口.txt': 'b594e6aa317b5f1d12ebeec6dd46b3ee51f244cb428eb1dae820e091956bdd1e',
    'function_review.json': '5a785c482cb851f6a4b3eea6f39926a1ead1ba24fa4072886e93a1b173f8104f',
    '证据/bounded_raw.json': '15be75a1ad6266da6a0df0010c3316ec45619f2e78f05ae691ddc50f4a50c1d6',
    '证据/formal_functions.json': 'cd9940a7efd72bd7c10cb1f21f6734bdd490bf98d8f3808b78848ac0b190b193',
    '证据/reused_raw.json': 'ee58756789775fbdc477e3ce6537fedbc1de5450956bdf9d6c59381581c71d26',
    '证据/source_navigation.json': 'a5116ed511d7954af20ee1c66925bc2cf9a69cdbcb48c93d929ce17337c8f843',
    '证据/network_production_navigation.json': '01180775911ca89665fec9064b4fcfba5f6fe1017d2d90f3f24f4e946d8c20c1',
    '证据/build_artifacts.py': 'f72e8044f2513ecccd6bad62d72b65548a1220963a63a80ee5d6f58fc91e9ef0',
    '证据/validate_author.py': '5b69de5d4db784ac174ed587a4a7b6607d9f0faad932775abad9a0346f8ae652',
    '证据/author_validation.json': '3000a1e8e7e5d797bcca14e04716115a2820c585cadfdf179f6d396596c46c90',
}
ANCHORS = {
    0x6b20b7: 'mov dword ptr [ebp - 4], ecx',
    0x6b20c3: 'mov eax, dword ptr [ebp + 8]',
    0x6b20d1: 'jne 0x6b20d7',
    0x6b20d3: 'xor eax, eax',
    0x6b20f4: 'cmp edx, dword ptr [ebp - 8]',
    0x6b20f7: 'jge 0x6b2125',
    0x6b2108: 'push 0x20',
    0x6b211c: 'jne 0x6b2123',
    0x6b211e: 'mov eax, dword ptr [ebp - 0x10]',
    0x6b2125: 'xor eax, eax',
    0x6b2134: 'ret 4',
    0x6b81e1: 'add eax, 0x42c',
    0x6b81e9: 'ret',
    0x6ada0a: 'push 0x78',
    0x6ada18: 'movzx eax, al',
    0x6ada1d: 'jne 0x6ada8b',
    0x6ada22: 'movsx edx, word ptr [ecx + 4]',
    0x6ada33: 'call 0x61149e',
    0x6ada3a: 'jne 0x6ada76',
    0x6ada46: 'push 0',
    0x6ada48: 'push 0',
    0x6ada4a: 'push 0x66',
    0x6ada58: 'lea edx, [ebp - 0xc]',
    0x6ada5c: 'push 0x66',
    0x6ada6a: 'push 1',
    0x6ada76: 'push 0xa23acf',
    0x6ada7e: 'movsx ecx, word ptr [eax + 4]',
    0x73d59a: 'mov ecx, dword ptr [eax + 4]',
    0x73d5bf: 'mov dword ptr [ecx + 0x48], eax',
    0x73d5d6: 'push 2',
    0x73d5e8: 'push 1',
    0x73d5f2: 'call dword ptr [edx + 0xc4]',
    0x73d601: 'push 3',
    0x73d61d: 'movzx edx, al',
    0x73d620: 'neg edx',
    0x73d622: 'sbb dl, dl',
    0x73d624: 'inc dl',
    0x73d628: 'push edx',
    0x73d631: 'call dword ptr [edx + 0xc4]',
    0x73d640: 'push 6',
    0x73d663: 'call 0x61149e',
    0x73d668: 'neg eax',
    0x73d66a: 'sbb al, al',
    0x73d66c: 'inc al',
    0x73d670: 'push eax',
    0x73d679: 'call dword ptr [edx + 0xc4]',
    0x6aec44: 'cmp edx, dword ptr [ecx + 0xaa4]',
    0x6aec4a: 'jge 0x6aee15',
    0x6aec62: 'cmp dword ptr [edx + eax + 4], -1',
    0x6aee18: 'imul eax, eax, 0x14c',
    0x6aee27: 'lea eax, [edx + eax + 0x10]',
    0x6aee2f: 'call 0x61149e',
    0x6aee3b: 'je 0x6aee81',
    0x6aee40: 'movzx edx, byte ptr [ecx + 0x21]',
    0x6aee46: 'je 0x6aee81',
    0x6aee5a: 'cmp dword ptr [edx + eax + 0x144], 0',
    0x6aee62: 'jg 0x6aee81',
    0x6aaf7d: 'call 0x61149e',
    0x6ab20c: 'call 0x61149e',
    0x64f0da: 'movzx ecx, al',
    0x64f0df: 'je 0x64f0f5',
    0x64f0e4: 'mov eax, dword ptr [edx + 0x4d4]',
    0x64f0ed: 'mov eax, dword ptr [eax + ecx*4]',
    0x64f0f0: 'add eax, 0x70',
    0x64f104: 'ret 4',
    0x6279f0: 'cmp dword ptr [0xa766c8], 0',
    0x627a40: 'mov eax, dword ptr [0xa766c8]',
    0x627a5c: 'ret',
    0x6e453b: 'imul eax, eax, 0x84',
    0x6e4547: 'cmp dword ptr [edx + eax + 4], 0',
    0x6e4578: 'call dword ptr [eax + 0x50]',
    0x6e4599: 'mov al, byte ptr [ebp - 8]',
    0x6e45aa: 'ret 4',
    0x6e466c: 'cmp dword ptr [edx + eax + 4], 0',
    0x6e4675: 'mov eax, dword ptr [ebp + 0xc]',
    0x6e4678: 'push eax',
    0x6e46a3: 'call dword ptr [eax + 0x10]',
    0x6e46c9: 'ret 8',
    0x8e2c6a: 'xor eax, eax',
    0x6282a0: 'cmp dword ptr [0xa76728], 0',
    0x6282f0: 'mov eax, dword ptr [0xa76728]',
    0x62830c: 'ret',
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
    instructions, sources, bridges, assembly = {}, {}, {}, []

    def read(va, size):
        positions = [off + va - base - rva for _, rva, raw, off in sections
                     if rva <= va - base and va - base + size <= rva + raw]
        assert len(positions) == 1 and positions[0] + size <= len(image)
        return image[positions[0]:positions[0] + size]

    def load(path):
        payload = path.read_bytes()
        sources[str(path.relative_to(ROOT))] = digest(payload)
        return json.loads(payload)

    def pointer(value, path):
        for part in path.strip('/').split('/'):
            value = value[int(part)] if isinstance(value, list) else value[part]
        return value

    def code(chunk):
        va = int(chunk.get('start_va', chunk.get('va')), 16)
        payload = read(va, chunk['size'])
        assert payload.hex() == chunk['disk_hex']
        assert chunk.get('matching', chunk.get('equal')) is True
        assert payload.hex() == chunk.get('idb_hex', chunk.get('ida_hex'))
        assert 'sha256' not in chunk or digest(payload) == chunk['sha256']
        result = list(decoder.disasm(payload, va))
        assert sum(i.size for i in result) == len(payload)
        for ins in result:
            assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        return result

    def bridge(va, target):
        payload = read(va, 5)
        assert payload[0] == 0xe9
        assert va + 5 + struct.unpack_from('<i', payload, 1)[0] == target
        assert bridges.setdefault(va, target) == target

    raw = load(HERE / 'bounded_raw.json')
    assert raw['disk_sha256'] == SHA and raw['topic'] == HERE.parent.name
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert digest((DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == raw['exporter_sha256']
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    assert {int(f['seed_va'], 16) for f in raw['reused_seeds']} == REUSED
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert digest(path.read_bytes()) == source['source_sha256']
        sources[str(path.relative_to(ROOT))] = source['source_sha256']
    historical_network = load(DOCS / '专题/四类型辅助请求与队列/证据/reused_network.json')
    historical_ranges = []
    assert historical_network['disk_sha256'] == SHA
    for source in historical_network['sources']:
        assert digest((DOCS / source['path']).read_bytes()) == source['sha256']
        sources[str((DOCS / source['path']).relative_to(ROOT))] = source['sha256']
    for index, f in enumerate(historical_network['functions']):
        original = load(DOCS / f['source']['path'])
        assert digest((DOCS / f['source']['path']).read_bytes()) == f['source']['sha256']
        found = [(i, r) for i, r in enumerate(original) if r.get('va') == f['seed_va']]
        assert len(found) == 1 and found[0][1] == f['record']
        c = f['current_range_audit']
        payload = read(int(c['start_va'], 16), c['size'])
        assert payload.hex() == c['disk_hex'] and digest(payload) == c['sha256']
        legacy = f['legacy_version_record']
        assert legacy['idb_sha256'] == legacy['disk_sha256'] == c['sha256']
        assert legacy['matches_disk'] is True
        historical_ranges.append(dict(seed_va=f['seed_va'], size=c['size'],
            source=f['source']['path'], pointer='/' + str(found[0][0]),
            boundary='旧单区间字节复核；不提升为本批完整声明块语义审阅'))
    old = load(DOCS / '专题/邮件与礼物分组/证据/functions.json')
    assert old['functions'][9]['va'] == '0x6aebe0'
    functions = {int(f['seed_va'], 16): f for f in raw['functions']}
    functions[0x6aebe0] = old['functions'][9]
    audits = {int(f['seed_va'], 16): f['chunk_byte_ranges'] for f in raw['current_chunk_audits']}
    assert set(functions) == set(audits) == FRESH | REUSED
    function_rows = []
    for va, f in functions.items():
        chunks = f.get('chunk_byte_ranges', f.get('byte_ranges'))
        assert [(int(c.get('start_va', c.get('va')), 16), c['size']) for c in chunks] == [
            (int(c['start_va'], 16), c['size']) for c in audits[va]]
        for c in chunks:
            code(c)
        body = [i for c in audits[va] for i in code(c)]
        assert len(body) == len(f['assembly'])
        assert {i.address for i in body} == {int(r.get('site_va', r.get('va')), 16) for r in f['assembly']}
        calls = {i.address for i in body if i.mnemonic == 'call' and i.op_str.startswith('0x')}
        reported = [c for c in raw['calls'] if int(c['seed_va'], 16) == va]
        assert calls == {int(c['site_va'], 16) for c in reported}
        for c in reported:
            target = int(c['target_va'], 16)
            assert instructions[int(c['site_va'], 16)].op_str == hex(target)
            for address in c['bridges']:
                assert target == int(address, 16)
                destination = target + 5 + struct.unpack_from('<i', read(target, 5), 1)[0]
                bridge(target, destination)
                target = destination
            assert target == int(c['implementation_va'], 16)
        function_rows.append(dict(seed_va=hex(va), reused=va in REUSED, chunks=len(chunks),
                                  instruction_count=len(body), direct_calls=len(calls)))
        assembly.extend(['// 主体 ' + hex(va)] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    for chunk in raw['verified_direct_bridges']:
        decoded = code(chunk)
        assert len(decoded) == 1 and decoded[0].mnemonic == 'jmp'
        bridge(decoded[0].address, int(chunk['target_va'], 16))
    assert len(bridges) == len(raw['verified_direct_bridges'])
    windows = list(raw['explicit_owner_windows']) + [e['owner_window'] for edges in raw['incoming'].values() for e in edges if 'owner_window' in e]
    unique_windows = {}
    for w in windows:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        body = []
        for row in w['assembly']:
            current = code(row['bytes'])
            assert len(current) == 1 and current[0].address == int(row['site_va'], 16)
            body.extend(current)
        assert int(w['site_va'], 16) in {i.address for i in body}
        assert all(a.address + a.size == b.address for a, b in zip(body, body[1:]))
        key = (w['owner_va'], w['site_va'], hex(body[0].address), hex(body[-1].address + body[-1].size))
        unique_windows[key] = dict(zip(['owner_va', 'site', 'start', 'end'], key))
        assembly.extend(['// 窗口 ' + w['site_va']] + [
            '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    for chunk in raw['data_windows']:
        va = int(chunk['start_va'], 16)
        payload = read(va, chunk['size'])
        assert payload.hex() == chunk['idb_hex'] == chunk['disk_hex']
        assert chunk['matching'] is True
        assert digest(payload) == chunk['sha256']
    for string in raw['strings']:
        chunk = string['byte_audit']
        va = int(chunk['start_va'], 16)
        payload = read(va, chunk['size'])
        assert payload.hex() == chunk['idb_hex'] == chunk['disk_hex']
        assert chunk['matching'] is True and digest(payload) == chunk['sha256']
        assert string['unit_width'] in (1, 2)
        assert string['nul_hex'] == bytes(string['unit_width']).hex()
        assert payload.hex() == string['payload_hex'] + string['nul_hex']
    raw_sha = digest((HERE / 'bounded_raw.json').read_bytes())
    formal = load(HERE / 'formal_functions.json')
    expected_functions = []
    for index, f in enumerate(raw['functions']):
        ranges = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'})
                  for c in f['chunk_byte_ranges']]
        expected_functions.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'],
            status='机械适配；语义见function_review.json', pseudocode=f['pseudocode'],
            decompile_error=f['decompile_error'],
            assembly=[dict(va=r['site_va'], text=r['text'], is_code=r['is_code']) for r in f['assembly']],
            declared_chunks=[dict(start_va=c['va'], end_va=hex(int(c['va'], 16) + c['size']),
                                  is_main=c['va'] == f['seed_va']) for c in ranges],
            chunk_byte_ranges=ranges, bytes_match_disk=all(c['matching'] for c in ranges),
            source=dict(path='证据/bounded_raw.json', sha256=raw_sha, json_pointer='/functions/' + str(index))))
    assert formal == dict(schema='richonline-formal-bounded-adaptation-1', disk_sha256=SHA,
        source_sha256=raw_sha, functions=expected_functions,
        scope='四新主体原文/完整声明块无损机械适配；格式转换不增加语义计数')
    reused = load(HERE / 'reused_raw.json')
    assert len(reused['records']) == 8
    assert {int(r['va'], 16) for r in reused['records']} == {
        0x6aebe0, 0x64f0c0, 0x6279c0, 0x6e4520, 0x6e3b40, 0x6e4640, 0x8e2c10, 0x628270}
    reuse_rows = []
    for row in reused['records']:
        ref = row['source']
        path = (HERE / ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve()) and digest(path.read_bytes()) == ref['sha256']
        original = pointer(load(path), ref['pointer'])
        assert original == row['original_record'] and original['va'] == row['va']
        chunks = original.get('chunk_byte_ranges', original.get('byte_ranges'))
        body = [i for c in chunks for i in code(c)]
        assert {i.address for i in body} == {int(r['va'], 16) for r in original['assembly']}
        assert len(body) == len(original['assembly'])
        declared = original.get('declared_chunks')
        if declared:
            assert {(int(c.get('va', c.get('start_va')), 16), c['size']) for c in chunks} == {
                (int(c['start_va'], 16), int(c['end_va'], 16) - int(c['start_va'], 16)) for c in declared}
        reuse_rows.append(dict(owner_va=row['va'], chunks=len(chunks), instruction_count=len(body),
                              source=str(path.relative_to(ROOT)), json_pointer=ref['pointer'], role=row['role']))
        if row['va'] != '0x6aebe0':
            assembly.extend(['// 有限复用 ' + row['va']] + [
                '// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str for i in body])
    assert instructions[0x627a5c].mnemonic == 'ret'
    assert instructions[0x6e3ff7].op_str == '0xc'
    assert instructions[0x6e46c9].op_str == '8'
    navigation = load(HERE / 'source_navigation.json')
    assert navigation['bounded_owner_windows'] == raw['explicit_owner_windows']
    assert navigation['bounded_incoming'] == raw['incoming']
    assert len(navigation['owners']) == 2
    for row, owner, site, index, offset in zip(navigation['owners'], [0x6aaef0, 0x6ab0d0],
                                             [0x6aaf7d, 0x6ab20c], [3, 4], [42, 101]):
        assert int(row['owner_va'], 16) == owner and int(row['site_va'], 16) == site
        assert {'va', 'status', 'conclusion'}.isdisjoint(row)
        ref = row['source']
        path = (HERE / ref['path']).resolve()
        assert digest(path.read_bytes()) == ref['sha256'] and ref['pointer'] == '/functions/' + str(index)
        original = pointer(load(path), ref['pointer'])
        assert original == row['original_record'] and original['assembly'][offset]['va'] == hex(site)
    production = load(HERE / 'network_production_navigation.json')
    assert production['schema'] == 'richonline-exact-network-production-navigation-1'
    ref = production['source']
    path = (HERE / ref['path']).resolve()
    assert path == (DOCS / '专题/四类型辅助请求与队列/证据/reused_network.json').resolve()
    assert ref['pointer'] == '' and digest(path.read_bytes()) == ref['sha256']
    assert production['original_document'] == historical_network
    supplemental = runpy.run_path(str(HERE / 'independent_supplement_verify.py'), run_name='independent_readonly')['verify']()
    history = load(HERE / 'historical_crt_sources.json')
    assert len(history['records']) == 3
    identities = supplemental['old_crt_sources'] + [supplemental['old_crt_reread']]
    for entry, identity, range_key in zip(history['records'], identities, ['chunks', 'chunk_byte_ranges', None]):
        ref = entry['source']
        path = (HERE / ref['path']).resolve()
        assert path == (DOCS / '专题' / identity['path']).resolve()
        assert ref['sha256'] == identity['sha256'] == digest(path.read_bytes())
        assert ref['pointer'] == identity['json_pointer']
        assert entry['original_record'] == pointer(load(path), ref['pointer'])
        assert entry['range_key'] == range_key
    for raw_name, formal_name, status, scope in [
        ('supplement_raw.json', 'supplement_formal.json', '必要依赖无损机械适配；语义见function_review.json',
         '四个必要依赖完整声明块无损适配，保留922873非代码填充'),
        ('container_dependency/bounded_raw.json', 'container_formal.json', '必要容器依赖无损适配；下层模板语义限定',
         '两必要依赖无损适配；85B870不外推取槽公式'),
    ]:
        extra_raw = load(HERE / raw_name)
        raw_digest = digest((HERE / raw_name).read_bytes())
        extra_formal = load(HERE / formal_name)
        expected = []
        for index, f in enumerate(extra_raw['functions']):
            ranges = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'})
                      for c in f['chunk_byte_ranges']]
            expected.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'], status=status,
                pseudocode=f['pseudocode'], decompile_error=f['decompile_error'],
                assembly=[dict(va=r['site_va'], text=r['text'], is_code=r['is_code']) for r in f['assembly']],
                declared_chunks=[dict(start_va=c['va'], end_va=hex(int(c['va'], 16) + c['size']),
                                      is_main=c['va'] == f['seed_va']) for c in ranges],
                chunk_byte_ranges=ranges, bytes_match_disk=all(c['matching'] for c in ranges),
                source=dict(path='证据/' + raw_name, sha256=raw_digest, json_pointer='/functions/' + str(index))))
        assert extra_formal == dict(schema='richonline-formal-bounded-adaptation-1', disk_sha256=SHA,
            source_sha256=raw_digest, functions=expected, scope=scope)
    template = load(HERE / 'container_template_navigation.json')
    ref = template['source']
    path = (HERE / ref['path']).resolve()
    assert digest(path.read_bytes()) == ref['sha256']
    assert pointer(load(path), ref['pointer']) == template['original_record']
    record = template['original_record']['function']
    assert record['va'] == '0x85bb10'
    body = [i for c in record['chunks'] for i in code(c)]
    assert len(body) == len(record['instructions'])
    for ins, row in zip(body, record['instructions']):
        assert hex(ins.address) == row['va'] and ins.size == row['size'] and ins.bytes.hex() == row['hex']
    assert instructions[0x85bb33].op_str == 'ecx, dword ptr [ebp - 8]'
    assert instructions[0x85bb36].op_str == '0x60b7f6'
    assert instructions[0x85bb4e].mnemonic == 'ret'
    for w in template['original_record']['windows']:
        code(w['block'])
    manifest = load(HERE.parent / 'function_review.json')
    assert manifest['disk_sha256'] == SHA
    reviews = manifest['functions'] + manifest['reused_reviews']
    assert len(reviews) == 11 and {int(r['va'], 16) for r in reviews} == FRESH | REUSED | EXTRA
    for row in reviews:
        assert row['status'] == '局部语义已审阅' and row['unknown']
        assert row['fresh_evidence'] == (int(row['va'], 16) in FRESH | EXTRA)
        assert len(row['source_records']) == 1
        ref = row['source_records'][0]
        path = HERE.parent / ref['path']
        assert digest(path.read_bytes()) == ref['sha256']
        original = pointer(load(path), ref['pointer'])
        assert original['va'] == row['va'] and original.get('declared_chunks', []) == row['declared_chunks']
        assert original.get('chunk_byte_ranges', original.get('byte_ranges')) == row['original_byte_ranges']
        expected_anchors = [dict(path=ref['path'], pointer=ref['pointer'] + '/assembly/' + str(i) + '/text',
                                 site_va=r['va'], value=r['text'])
                            for i, r in enumerate(original['assembly']) if r.get('is_code', True)]
        assert row['anchors'] == expected_anchors
    merger = runpy.run_path(str(DOCS / '全量分析/merge_reviews.py'), run_name='independent_readonly')
    recognized = []
    for path in HERE.parent.rglob('*.json'):
        if path.name.startswith('independent_'):
            continue
        for node, at in merger['walk'](json.loads(path.read_bytes())):
            address = node.get('va', node.get('address', node.get('ea', node.get('地址'))))
            status = node.get('status', node.get('review_status', node.get('状态')))
            conclusion = node.get('conclusion', node.get('结论'))
            if address is not None and isinstance(status, str) and isinstance(conclusion, str):
                recognized.append((str(path.relative_to(HERE.parent)), at, address))
    assert len(recognized) == 11 and all(r[0] == 'function_review.json' for r in recognized)
    semantic_rows = []
    for site, expected in ANCHORS.items():
        ins = instructions[site]
        actual = (ins.mnemonic + ' ' + ins.op_str).rstrip()
        assert actual == expected, (hex(site), actual, expected)
        semantic_rows.append(dict(site_va=hex(site), text=actual, bytes_hex=ins.bytes.hex()))
    boolean_samples = []
    for value in (0, 1, 2, 0xff, 0x12345678, 0x80000000, 0xffffffff):
        negated = (-value) & 0xffffffff
        actual = (negated & 0xffffff00) | int(value == 0)
        assert actual & 0xff == int(value == 0)
        boolean_samples.append(dict(input=hex(value), pushed_dword=hex(actual),
                                    consumed_low_byte=int(value == 0)))
    preview_bindings = {}
    preview_bindings.update(PREVIEW_SHA)
    documents = list(HERE.parent.glob('*.txt'))
    assert all(not line.strip() or line.startswith('//') for path in documents
               for line in path.read_text('utf-8').splitlines())
    final_bindings = {}
    for relative, expected in FINAL_SHA.items():
        actual = digest((HERE.parent / relative).read_bytes())
        assert actual == expected, (relative, '终稿改变，须重新独审')
        final_bindings[relative] = actual
    result = dict(status='PASS' if FINAL_SHA else '补证语义通过；终稿SHA待锁', pe_sha256=SHA,
        functions=function_rows, original_window_records=len(windows), unique_windows=list(unique_windows.values()),
        unique_bridges=len(bridges), semantic_anchors=semantic_rows, sources=sources,
        historical_network_ranges=historical_ranges, byte_boolean_samples=boolean_samples,
        reused_contracts= reuse_rows, central_recognized_reviews=recognized,
        supplemental_review=supplemental,
        global_new_entry_count=8, recollected_crt_count=2,
        reviewed_preview_sha256=preview_bindings,
        reviewed_final_sha256=final_bindings,
        deferred_helpers=['0x85b740', '0x85c660', '0x60b7f6'],
        boundary='四新主体/六本轮重采依赖（四全局新入口、两旧CRT重采）/一旧主体局部语义及七有限依赖已独审；共八全局新入口，fresh_evidence只指本轮采证；取槽深映射、生产清理和动态业务继续未知；未运行游戏')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], '显式审阅', len(result['central_recognized_reviews']), '终稿绑定', len(result['reviewed_final_sha256']))
