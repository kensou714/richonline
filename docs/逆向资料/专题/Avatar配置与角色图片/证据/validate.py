"""作者离线总验：主体、桥、上下文、旧原证、全资源与分级清单。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from inspect_resource import lexical

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def validate():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(blob) == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(va, size):
        offsets = [off + va - base - rva for _, rva, length, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(offsets) == 1
        return blob[offsets[0]:offsets[0] + size]

    def load(name):
        return json.loads((HERE / name).read_bytes())

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    functions, bridges, calls, instructions, declared_bytes = [], {}, 0, 0, 0
    for name in ('avatar_raw.json', 'supplement_raw.json', 'coordinate_constructor_raw.json'):
        source = load(name)
        assert source['disk_sha256'] == SHA
        thunks = {int(row['va'], 16): row for row in source['thunks']}
        for row in source['thunks']:
            va, raw = int(row['va'], 16), bytes.fromhex(row['idb_hex'])
            assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
            assert raw[0] == 0xE9 and len(raw) == 5
            assert va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
            bridges[va] = row['target']
        for function in source['functions']:
            decoded = {}
            for row in function['chunk_byte_ranges']:
                va, raw = int(row['va'], 16), bytes.fromhex(row['idb_hex'])
                assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
                declared_bytes += len(raw)
            for row in function['byte_ranges']:
                va, raw = int(row['va'], 16), bytes.fromhex(row['idb_hex'])
                assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
                block = list(decoder.disasm(raw, va))
                assert sum(ins.size for ins in block) == len(raw)
                decoded.update((ins.address, ins) for ins in block)
            assert set(decoded) == {int(row['va'], 16) for row in function['assembly']}
            for call in function['calls']:
                ins = decoded[int(call['site'], 16)]
                assert ins.mnemonic == 'call'
                if call['target'] is None:
                    continue
                assert ins.bytes[0] == 0xE8 and ins.size == 5
                target = ins.address + 5 + int.from_bytes(ins.bytes[1:], 'little', signed=True)
                assert target == int(call['target'], 16)
                for thunk in call['thunks']:
                    assert target == int(thunk, 16)
                    target = int(thunks[target]['target'], 16)
                assert target == int(call['implementation'], 16)
                calls += 1
            instructions += len(decoded)
            functions.append(function['va'])
    contexts, literal_count = [], 0
    for source_name, checked_name in (('avatar_context.json', 'avatar_context_verified.json'),
                                      ('supplement_context.json', 'supplement_context_verified.json')):
        source, checked = load(source_name), load(checked_name)
        assert checked['source_sha256'] == digest((HERE / source_name).read_bytes())
        assert checked['disk_sha256'] == SHA
        if source_name == 'avatar_context.json':
            assert len(source['literals']) == 11
        else:
            assert not source['literals']
        for row in checked['literals']:
            raw, text = bytes.fromhex(row['hex']), bytes.fromhex(row['content_hex'])
            assert raw == text + b'\0' and text and all(32 <= value <= 126 for value in text)
            assert raw == disk(int(row['target'], 16), row['size']) == bytes.fromhex(row['disk_hex'])
            literal_count += 1
        for row in checked['data']:
            va, raw = int(row['va'], 16), bytes.fromhex(row['hex'])
            assert raw == disk(va, row['size']) == bytes.fromhex(row['disk_hex'])
            if 'target' in row:
                assert raw[0] == 0xE9 and len(raw) == 5
                assert va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
                bridges[va] = row['target']
            if 'first_nul' in row:
                assert row['first_nul'] == raw.find(b'\0')
        context_rows = 0
        for original, group in zip((*source['windows'], *source['incoming']), (*checked['windows'], *checked['incoming']), strict=True):
            assert len(original['context']) == len(group['context'])
            for before, row in zip(original['context'], group['context'], strict=True):
                assert all(row[key] == value for key, value in before.items())
                raw = bytes.fromhex(row['hex'])
                assert raw == disk(int(row['va'], 16), row['size']) == bytes.fromhex(row['disk_hex'])
                block = list(decoder.disasm(raw, int(row['va'], 16)))
                assert len(block) == 1 and block[0].size == row['size']
                context_rows += 1
        contexts.append(dict(source=source_name, rows=context_rows))
    reused = load('reused_verified.json')
    assert len(reused['functions']) == 5 and reused['disk_sha256'] == SHA
    for function in reused['functions']:
        source_path = ROOT / 'docs/逆向资料/专题' / function['source']
        assert digest(source_path.read_bytes()) == function['source_sha256']
        for row in function['chunks']:
            assert bytes.fromhex(row['idb_hex']) == disk(int(row['va'], 16), row['size']) == bytes.fromhex(row['disk_hex'])
    resources = load('resources.json')
    files = resources['files']
    actual = {(ROOT / 'Avatar' / path.name).relative_to(ROOT).as_posix()
              for path in (ROOT / 'Avatar').iterdir() if path.is_file() and path.suffix.lower() in ('.avt', '.kpd')}
    assert actual == {row['path'] for row in files} and len(files) == 70
    for row in files:
        raw = (ROOT / row['path']).read_bytes()
        assert raw.hex() == row['source_hex'] and len(raw) == row['source_size'] and digest(raw) == row['source_sha256']
        packed = bytes((value - raw[0]) & 255 for value in raw[1:])
        size, compressed = struct.unpack_from('<II', packed)
        assert row['key'] == raw[0] and row['packed_size'] == len(packed)
        assert row['packed_sha256'] == digest(packed) and compressed == len(packed) - 8 == row['compressed_size']
        assert row['compressed_sha256'] == digest(packed[8:])
        plain = lzokay.decompress(packed[8:], size)
        assert lexical(plain) == row['lexical']
    manifest = json.loads((HERE.parent / '函数审阅清单.json').read_bytes())
    assert manifest['pe_sha256'] == SHA and len(manifest['functions']) == 15
    assert manifest['status_counts'] == dict(Counter(row['status'] for row in manifest['functions']))
    assert set(functions) <= {row['va'] for row in manifest['functions']}
    for row in manifest['functions']:
        assert (HERE.parent / row['document']).is_file()
        path = HERE.parent / row['evidence'][0]
        source = json.loads(path.read_bytes())
        value = source
        for segment in row['evidence_pointer'].split('/')[1:]:
            value = value[int(segment)] if isinstance(value, list) else value[segment]
        assert int(value.get('va', value.get('address')), 16) == int(row['va'], 16)
        assert row['chunks'] == value.get('chunk_byte_ranges', value.get('chunks'))
        assert row['instructions'] == len(value.get('assembly', value.get('instructions')))
    docs = []
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
        if path.name != '06_独立审阅.txt':
            docs.append(dict(path=path.name, sha256=digest(path.read_bytes())))
    sources = [dict(path=path.name, sha256=digest(path.read_bytes())) for path in HERE.glob('*.json')
               if path.name not in ('validation.json', 'independent_validation.json')]
    result = dict(status='PASS', pe_sha256=SHA, new_body_functions=len(functions), body_instructions=instructions,
                  declared_body_bytes=declared_bytes, direct_calls=calls, unique_bridges=len(bridges),
                  strict_literals=literal_count, contexts=contexts, reused_functions=5, resource_files=len(files),
                  documents=docs, sources=sources, scope='作者离线检查；语义审阅边界由正文和清单限定')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key not in ('documents', 'sources')}, ensure_ascii=True))


if __name__ == '__main__':
    validate()
