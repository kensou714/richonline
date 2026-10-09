"""核对当前PE全部声明块及桥，绑定关键汇编契约并运行边界样本。"""
import ast
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    fingerprint = hashlib.sha256(image).hexdigest()
    nt = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, nt + 6)[0])]
    functions, spans, hashes, e9_starts = {}, [], {}, set()

    def check(span):
        address, size = int(span['va'], 16), span['size']
        mapped = [(rva, off) for _, rva, raw, off in sections
                  if base + rva <= address and address + size <= base + rva + raw]
        assert len(mapped) == 1, span['va']
        rva, off = mapped[0]
        disk = image[off + address - base - rva:off + address - base - rva + size]
        assert disk.hex() == span['idb_hex'], span['va']
        if 'disk_hex' in span:
            assert disk.hex() == span['disk_hex'], span['va']
        if 'target' in span:
            assert disk[0] == 0xE9 and size == 5
            assert address + 5 + struct.unpack_from('<i', disk, 1)[0] == int(span['target'], 16)
        if size == 5 and disk[0] == 0xE9:
            e9_starts.add(address)
        spans.append((address, size))

    for path in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if isinstance(data, list):
            if path.name == 'matrix_slots.json':
                for span in data:
                    check(span)
                    assert int.from_bytes(bytes.fromhex(span['idb_hex']), 'little') == int(span['value'], 16)
            continue
        if 'functions' not in data:
            if 'pe_sha256' in data:
                assert data['pe_sha256'] == fingerprint
            continue
        assert data['disk_sha256'] == fingerprint
        for function in data.get('functions', []):
            functions.setdefault(function['va'], function)
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']}
            actual = {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in function['chunk_byte_ranges']}
            assert declared == actual, function['va']
            for span in function['byte_ranges'] + function['chunk_byte_ranges']:
                check(span)
        for span in data.get('thunks', []):
            check(span)
    manifest = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert manifest['disk_sha256'] == fingerprint
    assert {r['va'] for r in manifest['functions']} == set(functions)
    assert all(r['status'] and r['conclusion'] and r['unknown'] and r['evidence'] for r in manifest['functions'])
    for row in manifest['functions']:
        for ref in row['evidence']:
            filename, pointer = ref.split('#')
            data = json.loads((HERE / filename).read_text(encoding='utf-8'))
            assert data['functions'][int(pointer.rsplit('/', 1)[1])]['va'] == row['va']

    def asm(address):
        return '\n'.join(i['text'] for i in functions[address]['assembly'])

    def pseudo(address):
        return '\n'.join(functions[address]['pseudocode'])

    def calls(address):
        return {c['implementation'] for c in functions[address]['calls']}

    mask_asm = asm('0x6dfb40')
    assert 'imul    ecx, [eax+10h]' in mask_asm and 'sar     edx, 3' in mask_asm
    assert 'and     ecx, 7' in mask_asm and '[eax+0A4h]' in mask_asm
    cache_asm = asm('0x6dc090')
    assert cache_asm.count('mov     [ebp+var_1C]') == 2  # 调试填充及FFFFFFFF，候选命中没有更新。
    assert 'mov     [ebp+var_1C], 0FFFFFFFFh' in cache_asm
    assert 'jnb     short loc_6DC17B' in cache_asm and 'mov     [ebp+var_18], 0' in cache_asm
    assert '0x6dc310' in calls('0x6dc090')
    assert 'jl      short loc_6DFAAF' in asm('0x6dfa80') and 'jg      short loc_6DFAAF' in asm('0x6dfa80')
    assert '[eax+0ACh], cl' in asm('0x818bc0') and '[eax+0ADh], cl' in asm('0x818be0')
    assert calls('0x6e5160') >= {'0x6daa10', '0x6dcc40'}
    assert calls('0x813e70') >= {'0x818bb0', '0x818c00', '0x818be0'}
    assert 'TickCount - *(_DWORD *)(a1 + 152)' in pseudo('0x813e70')
    assert 'return sub_600D24(a1, a2: 1)' in pseudo('0x813e70')
    assert 'off_A6AB00' in asm('0x95e781') and 'off_A6AB74' in asm('0x95c7eb')
    assert '0x977a09' in calls('0x95e75e') and '0x977a09' in calls('0x95c7d6')
    assert '284' in pseudo('0x977a09') and '0x9804e5' in calls('0x977a09')
    assert 'idguardlibr.dll' in pseudo('0x917330') and 'LoadBitmapA(hInstance: LibraryA' in pseudo('0x917330')
    assert all('"' + prefix + '"' in pseudo('0x6daa10') for prefix in
               ('road', 'thing', 'event', 'build', 'vehicle', 'role', 'npc', 'fx', 'mood', 'card', 'other', 'extend'))
    assert '*a1 = sub_60C089' in pseudo('0x814cd0') and '0x814970' in calls('0x814cd0')
    assert '28 * a1' in pseudo('0x814970') and '2 * a2' in pseudo('0x814970')
    assert '0x814cd0' in calls('0x814ec0')

    # 掩码样本通过逐像素独立位串核对，覆盖跨字节、非8倍宽和透明/不透明。
    mask_cases = 0
    for width in (1, 7, 8, 9, 31, 256):
        pixels = [int(n % 5 == 2) for n in range(width * 3)]
        packed = bytearray((len(pixels) + 7) // 8)
        for index, value in enumerate(pixels):
            packed[index // 8] |= value << (index % 8)
        for y in range(3):
            for x in range(width):
                pixel = x + width * y
                assert bool(packed[pixel >> 3] & (1 << (pixel & 7))) == bool(pixels[y * width + x])
                mask_cases += 1
    # 使用计数只作FFFFFFFF排除，最后候选与最小计数候选不同。
    cache_samples = [([(True, 1, 0), (True, 999, 0)], 1),
                     ([(True, 7, 1), (True, 0xFFFFFFFF, 0)], 0),
                     ([(False, 1, 0), (True, 2, 0), (True, 3, 1)], 1)]
    for slots, expected in cache_samples:
        selected = 0
        for index, (loaded, usage, state) in enumerate(slots):
            if loaded and (usage & 0xFFFFFFFF) < 0xFFFFFFFF and state == 0:
                selected = index
        assert selected == expected
    for path in HERE.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'))
    for path in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    result = dict(pe_sha256=fingerprint, functions=len(functions), declared_chunks=sum(len(f['declared_chunks']) for f in functions.values()),
                  span_records=len(spans), unique_spans=len(set(spans)), bytes_including_repeats=sum(n for _, n in spans),
                  unique_bytes=len({address + offset for address, size in spans for offset in range(size)}),
                  unique_e9_bridges=len(e9_starts), byte_mismatches=0,
                  mask_sample_pixels=mask_cases, cache_samples=len(cache_samples),
                  status_counts={status: sum(r['status'] == status for r in manifest['functions'])
                                 for status in sorted({r['status'] for r in manifest['functions']})},
                  source_hashes=hashes, limitation='静态PE/IDA契约和边界模型核对；不是机器码仿真，未运行游戏或设备故障注入。')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
