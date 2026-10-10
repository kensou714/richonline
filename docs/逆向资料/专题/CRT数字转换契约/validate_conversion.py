"""独立PE映射核字节，绑定转换关键指令；模型不是机器码执行。"""
import ast
import hashlib
import json
import re
import struct
from pathlib import Path
from model_conversion import verify_samples

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    fingerprint = hashlib.sha256(image).hexdigest()
    nt = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + index * 40 + 8)
                for index in range(struct.unpack_from('<H', image, nt + 6)[0])]
    spans, functions, hashes, thunks = [], {}, {}, {}

    def check(span):
        address, size = int(span['va'], 16), span['size']
        mapped = [(rva, off) for _, rva, raw, off in sections
                  if base + rva <= address and address + size <= base + rva + raw]
        assert len(mapped) == 1, span['va']
        rva, off = mapped[0]
        disk = image[off + address - base - rva:off + address - base - rva + size]
        assert disk.hex() == span['idb_hex'], span['va']
        if 'disk_hex' in span:
            assert disk.hex() == span['disk_hex']
        if 'target' in span:
            assert size == 5 and disk[0] == 0xE9
            assert address + 5 + struct.unpack_from('<i', disk, 1)[0] == int(span['target'], 16)
            thunks[address] = int(span['target'], 16)
        spans.append((address, size))

    def check_function(function):
        functions[function['va']] = function
        declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']}
        actual = {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in function['chunk_byte_ranges']}
        assert declared == actual
        for span in function['byte_ranges'] + function['chunk_byte_ranges']:
            check(span)

    for filename in ('classification_helpers.json', 'locale_update.json', 'navigation.json', 'seeds.json'):
        path = HERE / '证据' / filename
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            continue
        hashes['证据/' + path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if 'disk_sha256' in data:
            assert data['disk_sha256'] == fingerprint
        for function in data.get('functions', []):
            check_function(function)
        for span in data.get('thunks', []) + data.get('spans', []):
            check(span)
    local_count = len(functions)
    local_addresses = set(functions)
    manifest = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert manifest['disk_sha256'] == fingerprint
    for row in manifest['functions']:
        assert row['status'] and row['conclusion'] and row['unknown']
        for ref in row['evidence']:
            filename, pointer = ref.split('#')
            path = HERE / filename
            data = json.loads(path.read_text(encoding='utf-8'))
            assert data['disk_sha256'] == fingerprint
            function = data['functions'][int(pointer.rsplit('/', 1)[1])]
            assert function['va'] == row['va']
            if row['va'] not in functions:
                check_function(function)
                hashes[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert set(functions) == {r['va'] for r in manifest['functions']}

    def asm(address):
        return '\n'.join(item['text'] for item in functions[address]['assembly'])

    def calls(address):
        return {call['implementation'] for call in functions[address]['calls']}

    conversion = asm('0x91f800')
    assert calls('0x91f950') == {'0x91f800'}
    assert len(bytes.fromhex(functions['0x91f950']['chunk_byte_ranges'][0]['idb_hex'])) == 17
    assert calls('0x91f800') >= {'0x930960', '0x92de70', '0x9305c0', '0x930660'}
    for token in ('[eax+64h]', 'off_A69A34', 'cmp     dword ptr [edx+28h], 1',
                  'jle     short loc_91F847', 'imul    ecx, 0Ah', 'add     ecx, [ebp+var_10]',
                  'neg     eax', "30h ; '0'", "39h ; '9'"):
        assert token in conversion, token
    assert conversion.count('push    8') == 2
    assert conversion.count('movzx   ecx, byte ptr [eax]') == 2
    assert not re.search(r'\b(?:jo|jno)\s', conversion)
    assert 'jbe     short loc_9305EE' in asm('0x9305c0') and 'int     3' in asm('0x9305c0')
    assert '[edx+48h]' in asm('0x9305c0') and '[ecx+48h]' in asm('0x930660')
    assert 'ja      short loc_930688' in asm('0x930660')
    assert '8000h' in asm('0x930660') and 'call    j____crtGetStringTypeA' in asm('0x930660')
    assert asm('0x92de70').count('push    0Ch') == 2
    assert 'call    ___updatetlocinfo_lk' in asm('0x92de70')
    navigation = json.loads((HERE / '证据/navigation.json').read_text(encoding='utf-8'))
    assert any(r['function'] == '0x6daa10' for r in navigation['references'])
    assert any(r['function'] == '0x6da7b0' for r in navigation['references'])
    assert '0x91f950' in calls('0x6daa10')
    model = verify_samples()
    for path in HERE.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'))
    for path in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    result = dict(pe_sha256=fingerprint, functions=len(functions), local_functions=local_count,
                  reused_functions=len(functions) - local_count,
                  local_declared_bytes=sum(c['size'] for address, f in functions.items()
                                           if address in local_addresses for c in f['chunk_byte_ranges']),
                  reused_declared_bytes=sum(c['size'] for address, f in functions.items()
                                            if address not in local_addresses for c in f['chunk_byte_ranges']),
                  declared_chunks=sum(len(f['declared_chunks']) for f in functions.values()),
                  span_records=len(spans), unique_spans=len(set(spans)),
                  unique_bytes=len({address + offset for address, size in spans for offset in range(size)}),
                  unique_attached_thunks=len(thunks), byte_mismatches=0,
                  navigation_records=len(navigation['references']),
                  status_counts={status: sum(row['status'] == status for row in manifest['functions'])
                                 for status in sorted({row['status'] for row in manifest['functions']})},
                  model=model, source_hashes=hashes,
                  limitation='静态原证和32位模型核对；不是机器码仿真，不涵盖真实locale切换或所有业务调用者。')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
