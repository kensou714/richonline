"""独立复核磁盘原字节、指令锚点和显式审阅分级；不启动客户端。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def main():
    raw = json.loads((HERE / 'teachmode_raw.json').read_text(encoding='utf-8'))
    bridges = json.loads((HERE / 'bridge_raw.json').read_text(encoding='utf-8'))
    reviews = json.loads((HERE.parent / '函数审阅清单.json').read_text(encoding='utf-8'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    assert sha == raw['disk_sha256'] == bridges['disk_sha256'] == reviews['pe_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    start = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, start + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(va, size):
        found = [(rva, off) for _, rva, length, off in sections
                 if base + rva <= va and va + size <= base + rva + length]
        assert len(found) == 1, hex(va)
        rva, off = found[0]
        offset = off + va - base - rva
        return image[offset:offset + size]

    counts = Counter()
    instructions = {}
    for function in raw['functions']:
        counts['functions'] += 1
        for chunk in function['chunks']:
            code = read(int(chunk['va'], 16), chunk['size'])
            assert chunk['equal'] and code.hex() == chunk['idb_hex'] == chunk['disk_hex']
            assert hashlib.sha256(code).hexdigest() == chunk['sha256']
            counts['chunks'] += 1
        for instruction in function['instructions']:
            va = int(instruction['va'], 16)
            assert read(va, instruction['size']).hex() == instruction['hex']
            if va in instructions:
                assert instructions[va] == instruction
            instructions[va] = instruction
            counts['instructions'] += 1
    for bridge in bridges['bridges']:
        va = int(bridge['va'], 16)
        code = read(va, 5)
        assert bridge['size'] == 5 and bridge['equal']
        assert code.hex() == bridge['idb_hex'] == bridge['disk_hex']
        assert code[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', code, 1)[0] == int(bridge['target'], 16)
        counts['bridges'] += 1

    # 锚点由独审按原证汇编选取；包括有符号/无符号边界与异常尾块。
    anchors = {
        0x628E69: 'push    8; Size',
        0x810341: 'mov     dword ptr [eax], 0',
        0x81034A: 'mov     dword ptr [ecx+4], 0',
        0x8102FE: 'push    170h; Size',
        0x8104E6: 'push    170h; unsigned int',
        0x8104DA: 'push    offset sub_5FF852; void *(__thiscall *)(void *)',
        0x810D7E: 'or      eax, 0FFFFFFFFh',
        0x6B7C41: 'imul    eax, 170h',
        0x6B7C4A: 'add     eax, [ecx+4]',
        0x6A14E8: 'jbe     short loc_6A1508',
        0x6A14F6: 'movsx   eax, byte ptr [ecx+edx]',
        0x6A15E9: 'sub     edx, 1',
        0x6A15F7: 'setle   cl',
        0x6A3DB8: 'sub     edx, 1',
        0x6A1322: 'sub     eax, 1',
        0x6A1325: 'cmp     [ebp+var_C], eax',
        0x6A135E: 'cmp     [ebp+var_C], 0FFFFFFFFh',
        0x767D30: 'jz      short loc_767DAA',
        0x767D40: 'jge     short loc_767DAA',
        0x7284C1: 'mov     eax, [eax+68h]',
        0xA116AB: 'mov     eax, offset stru_A55158',
    }
    for va, text in anchors.items():
        assert instructions[va]['text'] == text, (hex(va), instructions[va])
    equipment = [(0x7F3DD3 + 0x12 * i, 0x10C + 4 * i,
                  0x7F3DD9 + 0x12 * i, 0x90 + 4 * i) for i in range(6)]
    equipment += [(0x7F3E3F + 0x12 * i, 0x124 + 4 * i,
                   0x7F3E45 + 0x12 * i, 0xAC + 4 * i) for i in range(6)]
    for src_va, src, dst_va, dst in equipment:
        assert f'[eax+{src:X}h]' in instructions[src_va]['text'].replace('[eax+0', '[eax+')
        assert f'[edx+{dst:X}h]' in instructions[dst_va]['text'].replace('[edx+0', '[edx+')
    assert read(0xA76714, 4) == bytes(4)
    assert read(0xA116AB, 5) == bytes.fromhex('b85851a500')
    statuses = Counter(row['status'] for row in reviews['functions'])
    assert dict(statuses) == reviews['status_counts']
    assert len(reviews['functions']) == counts['functions'] == 131
    assert statuses['仅导出未审阅'] == 109
    result = dict(checks='pass', pe_sha256=sha, counts=dict(counts),
                  instruction_anchor_count=len(anchors), equipment_pairs=12,
                  review_status_counts=dict(statuses),
                  scope='独立原字节和已审汇编锚点核验；不模拟运行或外部助手')
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
