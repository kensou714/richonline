"""独立核对PE原证、完整声明块、E9目标与文档分级；不运行客户端。"""
import ast
import hashlib
import json
import math
import re
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
    count = 0
    size_sum = 0
    unique = set()
    functions = {}
    hashes = {}

    def check(span):
        nonlocal count, size_sum
        address, size = int(span['va'], 16), span['size']
        mapped = [(rva, off) for _, rva, raw, off in sections
                  if base + rva <= address and address + size <= base + rva + raw]
        assert len(mapped) == 1, hex(address)
        rva, off = mapped[0]
        disk = image[off + address - base - rva:off + address - base - rva + size]
        assert disk.hex() == span['idb_hex'], hex(address)
        if 'disk_hex' in span:
            assert disk.hex() == span['disk_hex'], hex(address)
        if 'target' in span:
            assert disk[0] == 0xE9 and size == 5
            assert address + 5 + struct.unpack_from('<i', disk, 1)[0] == int(span['target'], 16)
        count += 1
        size_sum += size
        unique.add((address, size))

    for path in sorted((HERE / '证据').glob('*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or 'disk_sha256' not in data:
            continue
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert data['disk_sha256'] == fingerprint
        for f in data.get('functions', []):
            functions.setdefault(f['va'], f)
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in f['declared_chunks']}
            actual = {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in f['chunk_byte_ranges']}
            assert declared == actual, f['va']
            for span in f['byte_ranges'] + f['chunk_byte_ranges']:
                check(span)
        for span in data.get('thunks', []) + data.get('spans', []):
            check(span)
        for key in ('code_range', 'adjacent_data'):
            if key in data:
                span = data[key]
                check(dict(va=span['start_va'], size=int(span['end_va'], 16) - int(span['start_va'], 16),
                           idb_hex=span['idb_hex']))
    manifest = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert {r['va'] for r in manifest['functions']} == set(functions)
    assert all(r['status'] and r['conclusion'] and r['unknown'] and r['evidence'] for r in manifest['functions'])
    assert manifest['code_ranges'][0]['start_va'] == '0x81b8b0'
    assert '0x81b8b0' not in functions
    def asm(address):
        return '\n'.join(i['text'] for i in functions[address]['assembly'])
    assert 'offset unk_ABAB9C' in asm('0x81b980')
    assert 'mov     ecx, 16h' in asm('0x828e90') and 'rep stosd' in asm('0x828e90')
    assert '0x9243e0' in {c['implementation'] for c in functions['0x81c190']['calls']}
    assert '0x924480' in {c['implementation'] for c in functions['0x9243e0']['calls']}
    assert '0x924000' in {c['implementation'] for c in functions['0x923f60']['calls']}
    assert not any(c['implementation'] == '0x81d6e0' for c in functions['0x81c2b0']['calls'])
    pad = json.loads((HERE / '证据/digest_padding.json').read_text(encoding='utf-8'))['spans'][0]
    assert bytes.fromhex(pad['idb_hex']) == b'\x80' + b'\0' * 63
    # 与原导出直接绑定：内联旋转表达式会重复常量，按相邻重复折叠后核64步次序。
    pseudo = '\n'.join(functions['0x8284e0']['pseudocode'])
    constants = [((1 if sign == '+' else -1) * int(number)) & 0xFFFFFFFF
                 for sign, number in re.findall(r'([+-]) (\d{5,})', pseudo)]
    ordered = [value for index, value in enumerate(constants)
               if index == 0 or value != constants[index - 1]]
    assert ordered == [int(abs(math.sin(index + 1)) * 2 ** 32) for index in range(64)]
    for path in HERE.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'))
    for path in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    result = dict(pe_sha256=fingerprint, functions=len(functions), span_records=count,
                  unique_spans=len(unique), bytes_including_repeats=size_sum, byte_mismatches=0,
                  status_counts={status: sum(r['status'] == status for r in manifest['functions'])
                                 for status in sorted({r['status'] for r in manifest['functions']})},
                  undeclared_code_ranges=len(manifest['code_ranges']), source_hashes=hashes,
                  md5_ordered_round_constants=len(ordered),
                  limitation='静态字节与契约断言；不等于实机文件权限、磁盘故障或异常输入回归')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
