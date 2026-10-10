"""独立检查 KoNews 关键指令、桥链与人工审阅边界，不调用 IDA。"""
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    image_base = struct.unpack_from('<I', image, pe + 52)[0]
    section_start = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_start + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(va, length):
        choices = [(rva, offset) for _, rva, size, offset in sections
                   if image_base + rva <= va and va + length <= image_base + rva + size]
        assert len(choices) == 1, hex(va)
        rva, offset = choices[0]
        start = offset + va - image_base - rva
        return image[start:start + length]

    names = ('reused_raw.json', 'closure_raw.json', 'consumer_raw.json',
             'helpers_raw.json', 'leaves_raw.json')
    functions, bridges = {}, {}
    for name in names:
        raw = json.loads((HERE / '证据' / name).read_text('utf-8'))
        for f in raw['functions']:
            functions[f['va']] = f
        for t in raw['thunks']:
            bridges[t['va']] = t

    # 这些字节分别固定模式谓词、步长、文本偏移、payload 和索引符号扩展。
    instructions = {
        0x629E15: '837d0804',
        0x63E9A1: '8b4818',
        0x696F11: '69c088000000',
        0x694FEA: '83c008',
        0x80A736: '83c00c',
        0x808F32: '83c01c',
        0x807CFB: '0fbf4804',
        0x807D07: '0fbf4804',
        0x808C7E: '6888000000',
        0x806811: '68cce5a200',
        0x809107: '6a00',
        0x80A001: 'c7400400000000',
        0x80A00B: 'c7410800000000',
        0x80A015: 'c7420c00000000',
    }
    for va, expected in instructions.items():
        target = bytes.fromhex(expected)
        assert disk(va, len(target)) == target, hex(va)
        assert any(any(int(r['va'], 16) <= va and va + len(target) <= int(r['va'], 16) + r['size']
                       and bytes.fromhex(r['idb_hex'])[va - int(r['va'], 16):va - int(r['va'], 16) + len(target)] == target
                       for r in f['byte_ranges']) for f in functions.values()), hex(va)

    edges = {
        0x605531: 0x808C70, 0x60ED89: 0x808E40, 0x60654E: 0x808D40,
        0x60CBB5: 0x809000, 0x6002BB: 0x8090E0, 0x602273: 0x809FF0,
        0x60F80B: 0x809D60, 0x6104A4: 0x80A730,
        0x604703: 0x63E990, 0x61260F: 0x629E10, 0x600EDC: 0x8069A0,
        0x6061D4: 0x695260, 0x606968: 0x695D40, 0x600284: 0x695F80,
        0x6074FD: 0x695F50, 0x6110C0: 0x696F00, 0x605B71: 0x696EC0,
        0x6092BC: 0x694FD0, 0x6059DC: 0x809210, 0x60078E: 0x809170,
    }
    for va, target in edges.items():
        data = disk(va, 5)
        assert data[0] == 0xE9 and va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        assert int(bridges[hex(va)]['target'], 16) == target

    reviews = json.loads((HERE / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert {r['va'] for r in reviews} == set(functions)
    assert len(reviews) == len(functions) == 39
    assert all('局部' in r['status'] or '仅导出' in r['status'] for r in reviews)
    limited = next(r for r in reviews if r['va'] == '0x80abb0')
    assert '仅导出' in limited['status'] and '不变量' in limited['unknown']
    for name in ('00_阅读入口与证据边界.txt', '01_记录解析与当前资源.txt',
                 '02_装配查找与容器边界.txt', '03_模式4消费者与扩展边界.txt'):
        assert all(not line.strip() or line.startswith('//')
                   for line in (HERE / name).read_text('utf-8').splitlines())

    result = {'status': 'PASS', 'disk_sha256': digest, 'instruction_sites': len(instructions),
              'bridge_edges': len(edges), 'reviewed_unique_functions': len(functions),
              'boundary': '独审核验静态指令及审阅分级；未验证动态生命周期、树不变量或服务端抽样。'}
    (HERE / '证据' / '独审检查.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
