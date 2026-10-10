"""只读当前PE和范围原证；虚拟快照、主体、复用、桥分别核验。"""
import hashlib
import json
from pathlib import Path
import struct

import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = {0x72E250, 0x72E2D0, 0x72E2F0, 0x7348F0, 0x7349D0, 0x7667A0, 0x766920}


def validate():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 60)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(va, count):
        matches = [(rva, off) for _, rva, size, off in sections
                   if rva <= va - base and va - base + count <= rva + size]
        assert len(matches) == 1, (hex(va), count)
        rva, off = matches[0]
        return image[off + va - base - rva:off + va - base - rva + count]

    checked, snapshots = [], []

    def walk(node, inherited_va=None):
        if isinstance(node, dict):
            address = node.get('start_va', node.get('va', node.get('site_va', inherited_va)))
            if node.get('idb_hex') is not None:
                va = int(address, 16) if isinstance(address, str) else address
                blob = bytes.fromhex(node['idb_hex'])
                assert len(blob) == node['size']
                if node.get('sha256'):
                    assert hashlib.sha256(blob).hexdigest() == node['sha256']
                if node.get('disk_hex') is None:
                    assert node.get('matching') is None
                    assert va in (0xA84FE8, 0xA859C4, 0xA859CC) and len(blob) == 4
                    snapshots.append(dict(va=hex(va), scope='仅IDB虚拟快照；非磁盘或运行时初值'))
                else:
                    assert blob == bytes.fromhex(node['disk_hex']) == read(va, len(blob))
                    assert node['matching'] is True
                    checked.append((hex(va), len(blob)))
            for value in node.values():
                walk(value, address)
        elif isinstance(node, list):
            for value in node:
                walk(value, inherited_va)

    raw_path = HERE / 'bounded_raw.json'
    raw_bytes = raw_path.read_bytes()
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == EXPECTED
    assert {int(f['seed_va'], 16) for f in raw['functions']} == SEEDS
    walk(raw)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    subjects = []
    for f in raw['functions']:
        addresses, total_bytes, total_instructions = set(), 0, 0
        for block in f['chunk_byte_ranges']:
            start = int(block['start_va'], 16)
            decoded = list(decoder.disasm(bytes.fromhex(block['idb_hex']), start))
            assert sum(i.size for i in decoded) == block['size']
            addresses.update(i.address for i in decoded)
            total_bytes += block['size']
            total_instructions += len(decoded)
            if block['start_va'] == f['seed_va']:
                assert start + block['size'] == int(f['end_va'], 16)
        assert len(f['chunk_byte_ranges']) == (2 if f['seed_va'] == '0x7348f0' else 1)
        assert addresses == {int(i['site_va'], 16) for i in f['assembly'] if i['is_code']}
        subjects.append(dict(va=f['seed_va'], chunks=len(f['chunk_byte_ranges']),
                             bytes=total_bytes, instructions=total_instructions))
    assert sum(f['bytes'] for f in subjects) == 1079
    assert sum(f['instructions'] for f in subjects) == 304
    formal = json.loads((HERE / 'formal_functions.json').read_text(encoding='utf-8'))
    assert formal['disk_sha256'] == EXPECTED
    assert formal['source_sha256'] == hashlib.sha256(raw_bytes).hexdigest()
    assert len(formal['functions']) == len(raw['functions'])
    for index, (original, adapted) in enumerate(zip(raw['functions'], formal['functions'])):
        assert adapted['va'] == original['seed_va']
        for key in ('end_va', 'name', 'pseudocode', 'decompile_error'):
            assert adapted[key] == original[key]
        assert adapted['source'] == dict(path='证据/bounded_raw.json',
                                        sha256=formal['source_sha256'],
                                        json_pointer='/functions/' + str(index))
        assert adapted['assembly'] == [dict(va=i['site_va'], text=i['text'], is_code=i['is_code'])
                                       for i in original['assembly']]
        ranges = [dict(va=b['start_va'], **{k: v for k, v in b.items() if k != 'start_va'})
                  for b in original['chunk_byte_ranges']]
        assert adapted['chunk_byte_ranges'] == ranges
        assert adapted['declared_chunks'] == [dict(start_va=b['va'],
            end_va=hex(int(b['va'], 16)+b['size']), is_main=b['va']==original['seed_va']) for b in ranges]
        assert adapted['bytes_match_disk'] is True
    bridges = raw['verified_direct_bridges']
    for bridge in bridges:
        data = bytes.fromhex(bridge['idb_hex'])
        assert len(data) == 5 and data[0] == 0xE9
        assert int(bridge['start_va'], 16)+5+struct.unpack_from('<i', data, 1)[0] == int(bridge['target_va'], 16)
    reused = []
    relative = '专题/主界面角色通知/证据/notify_contract.json'
    path = DOCS / relative
    contents = path.read_bytes()
    contract = json.loads(contents)
    assert contract['disk_sha256'] == EXPECTED
    for index, va in ((10, '0x81bc80'), (11, '0x81bcb0')):
        f = contract['functions'][index]
        assert f['va'] == va
        walk(f['byte_ranges'])
        reused.append(dict(path=relative, json_pointer='/functions/'+str(index), va=va,
                           sha256=hashlib.sha256(contents).hexdigest(), scope='仅指定短契约'))
    for relative, index, va in (
        ('专题/727F控件状态接口/证据/seeds.json', 1, '0x728060'),
        ('专题/727F控件状态接口/证据/seeds.json', 2, '0x728120'),
        ('专题/40B0系列事件/证据/ui24_control_id.json', 0, '0x7278e0'),
    ):
        path = DOCS / relative
        contents = path.read_bytes()
        contract = json.loads(contents)
        assert contract['disk_sha256'] == EXPECTED
        f = contract['functions'][index]
        assert f['va'] == va
        walk(f['byte_ranges'])
        for block in f['byte_ranges']:
            decoded = list(decoder.disasm(bytes.fromhex(block['idb_hex']), int(block['va'], 16)))
            assert sum(i.size for i in decoded) == block['size']
        reused.append(dict(path=relative, json_pointer='/functions/'+str(index), va=va,
                           sha256=hashlib.sha256(contents).hexdigest(), scope='仅指定短契约'))
    supplements = []
    for filename in ('dependency_raw.json', 'slot_owner_context.json'):
        path = HERE / filename
        data = json.loads(path.read_bytes())
        assert data['disk_sha256'] == EXPECTED
        walk(data)
        if filename == 'dependency_raw.json':
            assert len(data['functions']) == 1
            f = data['functions'][0]
            assert f['va'] == '0x796be0'
            block = f['chunk_byte_ranges'][0]
            decoded = list(decoder.disasm(bytes.fromhex(block['idb_hex']), int(block['va'], 16)))
            assert sum(i.size for i in decoded) == block['size'] == 12
            assert {i.address for i in decoded} == {int(i['va'], 16) for i in f['assembly']}
        else:
            assert len(data['windows']) == 8
            for window in data['windows']:
                for row in window['assembly']:
                    block = row['bytes']
                    decoded = list(decoder.disasm(bytes.fromhex(block['idb_hex']), int(row['site_va'], 16)))
                    assert len(decoded) == 1 and decoded[0].size == block['size']
        supplements.append(dict(path=filename, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    xref_path = HERE / 'slot_xrefs.json'
    xrefs = json.loads(xref_path.read_bytes())
    for slot in xrefs['slots']:
        for reference in slot['references']:
            va = int(reference['site_va'], 16)
            instruction = next(decoder.disasm(read(va, 10), va))
            assert instruction.mnemonic in ('mov', 'cmp')
            assert hex(int(slot['slot_va'], 16)) in instruction.op_str
    supplements.append(dict(path=xref_path.name, sha256=hashlib.sha256(xref_path.read_bytes()).hexdigest(),
                            scope='仅指定直接静态xref，不穷尽间接别名'))
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//')
                   for line in path.read_text(encoding='utf-8-sig').splitlines()), path.name
    manifest = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert {int(f['va'], 16) for f in manifest['functions']
            if f['coverage_origin'] == '本批新增完整主体'} == SEEDS
    assert len(manifest['functions']) == 36 and len(manifest['windows']) == 4
    assert {w['owner_va'] for w in manifest['windows']} == {'0x6e8d10', '0x733960', '0x734000', '0x751180'}
    assert all(not {'va', 'status', 'conclusion'}.intersection(w) for w in manifest['windows'])
    return dict(status='PASS', scope='作者静态字节及范围验证；不替代独审、运行时或完整生命周期',
                disk_sha256=EXPECTED, raw_sha256=formal['source_sha256'], subjects=subjects,
                disk_ranges_checked=len(checked), virtual_snapshots=snapshots,
                direct_bridges=len(bridges), reuse=reused, supplements=supplements,
                formal_sha256=hashlib.sha256((HERE / 'formal_functions.json').read_bytes()).hexdigest())


if __name__ == '__main__':
    result = validate()
    (HERE / 'author_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
