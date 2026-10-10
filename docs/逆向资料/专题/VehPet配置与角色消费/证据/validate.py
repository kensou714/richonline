"""作者离线验证：完整函数与桥、上下文副本、资源词法和中文备注文档。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def validate():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 60)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40 * i + 8) for i in range(count)]

    def disk(va, size):
        matches = [off + va - base - rva for _, rva, length, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(matches) == 1
        return blob[matches[0]:matches[0] + size]

    def load(name):
        return json.loads((HERE / name).read_text(encoding='utf-8'))

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    functions, bridges, instructions = [], {}, 0
    for name in ('vehpet_raw.json', 'supplement_raw.json'):
        source = load(name)
        assert source['disk_sha256'] == hashlib.sha256(blob).hexdigest()
        thunks = {int(row['va'], 16): row for row in source['thunks']}
        for row in source['thunks']:
            va = int(row['va'], 16)
            raw = bytes.fromhex(row['idb_hex'])
            assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
            assert raw[0] == 0xE9 and va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
            bridges[va] = raw.hex()
        for function in source['functions']:
            decoded, seen = {}, set()
            for row in function['chunk_byte_ranges']:
                va = int(row['va'], 16)
                assert bytes.fromhex(row['idb_hex']) == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
            for row in function['byte_ranges']:
                va = int(row['va'], 16)
                raw = bytes.fromhex(row['idb_hex'])
                assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
                block = list(decoder.disasm(raw, va))
                assert sum(ins.size for ins in block) == len(raw), row['va']
                decoded.update((ins.address, ins) for ins in block)
            assert set(decoded) == {int(row['va'], 16) for row in function['assembly']}
            for call in function['calls']:
                site = int(call['site'], 16)
                ins = decoded[site]
                assert ins.bytes[0] in (0xE8, 0xE9) and ins.size == 5
                target = site + 5 + int.from_bytes(ins.bytes[1:], 'little', signed=True)
                assert target == int(call['target'], 16)
                for thunk in call['thunks']:
                    assert target == int(thunk, 16)
                    target = int(thunks[target]['target'], 16)
                assert target == int(call['implementation'], 16)
            instructions += len(decoded)
            functions.append(function['va'])
    contexts = []
    context_bridge_targets = {0x612155: 0x63FB20, 0x60CDCC: 0x629570,
                              0x60212E: 0x640020, 0x60A0D6: 0x627CF0}
    context_bridges = set()
    for name in ('vehpet_context_verified.json', 'supplement_context_verified.json'):
        source = load(name)
        assert source['disk_sha256'] == hashlib.sha256(blob).hexdigest()
        for row in source.get('data', []):
            va, raw = int(row['va'], 16), bytes.fromhex(row['hex'])
            assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
            if va in context_bridge_targets:
                assert len(raw) == 5 and raw[0] == 0xE9
                assert va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == context_bridge_targets[va]
                context_bridges.add(va)
        for row in source['literals']:
            raw, text = bytes.fromhex(row['hex']), bytes.fromhex(row['content_hex'])
            assert raw == text + b'\0' and text and all(32 <= value <= 126 for value in text)
            assert raw == disk(int(row['target'], 16), row['size']) == bytes.fromhex(row['disk_hex'])
            if 'bounded_hex' in row:
                assert bytes.fromhex(row['bounded_hex']) == disk(int(row['target'], 16), 128)
        for group in (*source.get('windows', []), *source['incoming']):
            for row in group['context']:
                raw = bytes.fromhex(row['hex'])
                assert raw == disk(int(row['va'], 16), row['size']) == bytes.fromhex(row['disk_hex'])
                block = list(decoder.disasm(raw, int(row['va'], 16)))
                assert len(block) == 1 and block[0].size == row['size']
        contexts.append(dict(source=name, rows=sum(len(g['context']) for g in (*source.get('windows', []), *source['incoming']))))
    assert context_bridges == set(context_bridge_targets)
    resource = load('resources.json')
    original = (ROOT / resource['path']).read_bytes()
    assert hashlib.sha256(original).hexdigest() == resource['source_sha256']
    plain = bytes.fromhex(resource['decoded_hex'])
    assert b''.join(bytes.fromhex(row['hex']) for row in resource['lines']) == plain
    assert len(plain) == resource['decoded_size'] and hashlib.sha256(plain).hexdigest() == resource['decoded_sha256']
    for row in resource['entries']:
        value = bytes.fromhex(row['value_hex'])
        assert plain[row['value_offset']:row['value_offset'] + len(value)] == value
    documents = []
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines()), path.name
        documents.append(path.name)
    reviews = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8'))['functions']
    assert all(set(('va', 'status', 'conclusion', 'unknown', 'evidence')) <= set(row) for row in reviews)
    assert set(functions) <= {row['va'].lower() for row in reviews}
    sources = [dict(path=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
               for path in HERE.glob('*.json') if path.name not in ('validation.json', 'independent_review.json')]
    result = dict(status='PASS', disk_sha256=hashlib.sha256(blob).hexdigest(),
                  new_body_functions=len(functions), body_instructions=instructions,
                  unique_bridges=len(bridges), context_fixed_bridges=len(context_bridges),
                  contexts=contexts, documents=documents,
                  resource_lines=len(resource['lines']), resource_sections=len(resource['sections']),
                  resource_entries=len(resource['entries']), sources=sources,
                  scope='作者验证；有限业务语义由正文与独立审阅负责，数量不替代审阅')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: value for key, value in result.items() if key != 'sources'}


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True))
