"""作者核验：原范围与当前PE、跳板、指令锚点、资源偏移和文稿格式。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TOPIC = HERE.parent


def validate():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    assert sha == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe = struct.unpack_from('<I', blob, 60)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    start = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, start + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    comparisons, instructions, bridges = set(), set(), set()

    def disk(va, size):
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if 0 <= va-base-rva and va-base-rva+size <= length]
        assert len(matches) == 1, (hex(va), size)
        rva, offset = matches[0]
        return blob[offset+va-base-rva:offset+va-base-rva+size]

    def scan(value):
        if isinstance(value, dict):
            if {'va', 'size', 'idb_hex'} <= value.keys():
                va, size = int(value['va'], 16), value['size']
                assert disk(va, size).hex() == value['idb_hex']
                if value.get('disk_hex') is not None:
                    assert value['disk_hex'] == value['idb_hex']
                comparisons.add((va, size))
                if 'target' in value:
                    raw = disk(va, size)
                    assert raw[0] == 0xE9 and va+5+struct.unpack_from('<i', raw, 1)[0] == int(value['target'], 16)
                    bridges.add(va)
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    def function(row):
        for ins in row.get('assembly', row.get('instructions', [])):
            va = int(ins['va'], 16)
            decoded = list(decoder.disasm(disk(va, 15), va, count=1))
            assert len(decoded) == 1
            if 'hex' in ins:
                assert decoded[0].bytes.hex() == ins['hex']
            if 'size' in ins:
                assert decoded[0].size == ins['size']
            instructions.add(va)

    input_hashes = {}
    for name in ('facectrl_raw.json', 'lifecycle_raw.json', 'consumer_constructor_raw.json',
                 'actual_consumer_raw.json', 'actual_consumer_vtable.json', 'facectrl_context.json'):
        raw = (HERE / name).read_bytes()
        input_hashes[name] = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        assert data['disk_sha256'] == sha
        scan(data)
        for row in data.get('functions', []):
            function(row)
    reuse = json.loads((HERE / 'reused_evidence.json').read_bytes())
    for source in reuse['sources']:
        path = ROOT / 'docs/逆向资料' / source['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['sha256']
    scan(reuse)
    for row in reuse['functions']:
        function(row['record'])
    table = json.loads((HERE / 'actual_consumer_vtable.json').read_bytes())
    assert struct.unpack_from('<I', disk(0xA27120, 24), 16)[0] == 0x60A72F
    assert table['implementation'] == '0x73a590'

    resource = json.loads((HERE / 'resources.json').read_bytes())
    raw = (ROOT / resource['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == resource['source_sha256']
    packed = bytes((x-raw[0]) & 255 for x in raw[1:])
    length, compressed_size = struct.unpack_from('<II', packed)
    assert compressed_size == len(packed)-8
    plain = lzokay.decompress(packed[8:], length)
    assert len(plain) == length == resource['decoded_size']
    for data, label in ((packed, 'packed'), (packed[8:], 'compressed'), (plain, 'decoded')):
        assert hashlib.sha256(data).hexdigest() == resource[label + '_sha256']
    assert b''.join(bytes.fromhex(r['bytes']) for r in resource['lines']) == plain
    for entry in resource['entries']:
        for field in ('key', 'value'):
            value = bytes.fromhex(entry[field + '_hex'])
            offset = entry[field + '_offset']
            assert plain[offset:offset+len(value)] == value
    aliases = [bytes.fromhex(e['leading_space_trimmed_value_hex']) for e in resource['entries']
               if e['key_ascii'].startswith('ctrl')]
    assert len(aliases) == 45 and max(map(len, aliases)) == 5 and min(map(len, aliases)) == 2
    review = json.loads((TOPIC / 'function_review.json').read_bytes())
    assert len(review['functions']) == 22
    for row in review['functions']:
        assert {'va', 'status', 'conclusion', 'unknown', 'evidence', 'original_byte_ranges', 'declared_chunks'} <= row.keys()
        assert row['original_byte_ranges'] and row['unknown'] and row['evidence']
    manuscripts = []
    for path in sorted(TOPIC.glob('*.txt')):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
        manuscripts.append(path.name)
    result = dict(status='PASS', disk_sha256=sha, unique_saved_ranges=len(comparisons),
                  unique_instruction_sites=len(instructions), unique_e9_bridges=len(bridges),
                  functions=22, fresh=7, reused=15, vtable_slot='A27120+10 -> 60A72F -> 73A590',
                  resources=dict(items=9, entries=54, aliases=45, maximum_alias_bytes=5),
                  manuscripts=manuscripts, input_sha256=input_hashes,
                  limitation='只核验已保存范围与静态合同，不代表全函数语义或游戏实机验证；6E8F50旧主范围例外保留')
    (HERE / 'author_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True))
