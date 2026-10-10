"""作者范围核验：当前PE、IDA有限原证及复用记录；不调用IDA。"""
import hashlib
import json
from pathlib import Path
import struct

import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SEEDS = {0x6E3A30, 0x71AA20, 0x71AAC0, 0x747C70}


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

    checked = []

    def walk(node, inherited_va=None):
        if isinstance(node, dict):
            address = node.get('start_va', node.get('va', node.get('site_va', inherited_va)))
            if node.get('idb_hex') is not None and node.get('disk_hex') is not None:
                assert address is not None
                va = int(address, 16) if isinstance(address, str) else address
                raw = bytes.fromhex(node['idb_hex'])
                assert len(raw) == node['size']
                assert raw == bytes.fromhex(node['disk_hex']) == read(va, len(raw))
                assert node['matching'] is True
                if node.get('sha256'):
                    assert hashlib.sha256(raw).hexdigest() == node['sha256']
                checked.append((hex(va), len(raw)))
            for value in node.values():
                walk(value, address)
        elif isinstance(node, list):
            for value in node:
                walk(value, inherited_va)

    sources = []
    raw_path = HERE / 'bounded_raw.json'
    raw = json.loads(raw_path.read_text(encoding='utf-8'))
    assert raw['disk_sha256'] == EXPECTED
    assert {int(f['seed_va'], 16) for f in raw['functions']} == SEEDS
    walk(raw)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    subjects = []
    for function in raw['functions']:
        declared = function['chunk_byte_ranges']
        assert len(declared) == 1
        block = declared[0]
        start = int(block['start_va'], 16)
        instructions = list(decoder.disasm(bytes.fromhex(block['idb_hex']), start))
        assert sum(i.size for i in instructions) == block['size']
        assert int(function['end_va'], 16) == start + block['size']
        assert {i.address for i in instructions} == {
            int(row['site_va'], 16) for row in function['assembly'] if row['is_code']}
        subjects.append(dict(va=hex(start), chunks=1, bytes=block['size'],
                             instructions=len(instructions)))
    formal_path = HERE / 'formal_functions.json'
    formal = json.loads(formal_path.read_text(encoding='utf-8'))
    assert formal['disk_sha256'] == EXPECTED
    assert formal['source_sha256'] == hashlib.sha256(raw_path.read_bytes()).hexdigest()
    assert len(formal['functions']) == len(raw['functions'])
    for index, (original, adapted) in enumerate(zip(raw['functions'], formal['functions'])):
        assert adapted['va'] == original['seed_va']
        assert adapted['end_va'] == original['end_va']
        assert adapted['pseudocode'] == original['pseudocode']
        assert adapted['decompile_error'] == original['decompile_error']
        assert adapted['source']['json_pointer'] == '/functions/' + str(index)
        assert adapted['source']['sha256'] == formal['source_sha256']
        assert adapted['assembly'] == [dict(va=i['site_va'], text=i['text'],
                                           is_code=i['is_code']) for i in original['assembly']]
        assert adapted['chunk_byte_ranges'] == [
            dict(va=r['start_va'], **{k: v for k, v in r.items() if k != 'start_va'})
            for r in original['chunk_byte_ranges']]
    dependencies = []
    for filename in ('dependency_raw.json', 'owner_context_raw.json'):
        path = HERE / filename
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['disk_sha256'] == EXPECTED
        walk(data)
        if filename == 'dependency_raw.json':
            assert {f['va'] for f in data['functions']} == {'0x6e4520', '0x727800', '0x922798'}
            for function in data['functions']:
                assert len(function['chunk_byte_ranges']) == 1
                block = function['chunk_byte_ranges'][0]
                start = int(block['va'], 16)
                instructions = list(decoder.disasm(bytes.fromhex(block['idb_hex']), start))
                assert sum(i.size for i in instructions) == block['size']
                assert int(function['end_va'], 16) == start + block['size']
                assert {i.address for i in instructions} == {int(i['va'], 16)
                                                            for i in function['assembly']}
                dependencies.append(dict(va=function['va'], bytes=block['size'],
                                         instructions=len(instructions), chunks=1))
        sources.append(dict(path=filename,
                            source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
    for relative, va in (
        ('专题/控件树与对象生命周期/证据/创建与链表.json', 0x8E2C10),
        ('专题/控件树与对象生命周期/证据/状态与销毁.json', 0x8E3EB0),
        ('专题/股票与交易流程/证据/stock_core.json', 0x692FA0),
    ):
        path = DOCS / relative
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['disk_sha256'] == EXPECTED
        function = next(f for f in data['functions'] if int(f['va'], 16) == va)
        walk(function.get('chunk_byte_ranges', function.get('byte_ranges', [])))
        sources.append(dict(path=relative, va=hex(va),
                            source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    focus_path = DOCS / '专题/输入与快捷键/ida_input_raw.json'
    focus = json.loads(focus_path.read_text(encoding='utf-8'))['functions']['0x8ea570']
    for block in focus['ranges']:
        start = int(block['start'], 16)
        blob = bytes.fromhex(block['idb_bytes_hex'])
        assert len(blob) == int(block['end'], 16) - start
        assert blob == read(start, len(blob))
        checked.append((hex(start), len(blob)))
    sources.append(dict(path=str(focus_path.relative_to(DOCS)), va='0x8ea570',
                        scope='旧版本声明基线；仅指定函数范围重核当前字节',
                        source_sha256=hashlib.sha256(focus_path.read_bytes()).hexdigest()))
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//')
                   for line in path.read_text(encoding='utf-8-sig').splitlines()), path.name
    incoming = []
    for va, rows in raw['incoming'].items():
        owners = {row['owner_window']['owner_va'] for row in rows
                  if row.get('owner_window', {}).get('owner_va')}
        incoming.append(dict(va=va, rows=len(rows), owners=sorted(owners),
                             owner_count=len(owners),
                             bridges=sum(row['verified_bridge'] for row in rows)))
    for path in sorted(HERE.glob('*supplement*.json')):
        if path.name.endswith('validation.json'):
            continue
        data = json.loads(path.read_text(encoding='utf-8'))
        walk(data)
        sources.append(dict(path=str(path.relative_to(HERE)),
                            source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    return dict(scope='作者字节与范围核验；不替代人工语义审阅或独审',
                disk_sha256=EXPECTED, raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                subjects=subjects, dependencies=dependencies,
                incoming=incoming, byte_ranges_checked=len(checked),
                formal_sha256=hashlib.sha256(formal_path.read_bytes()).hexdigest(),
                reuse_and_supplement_sources=sources)


if __name__ == '__main__':
    result = validate()
    destination = HERE / 'author_validation.json'
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
