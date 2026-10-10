"""离线核验声明块、桥、有限语义、复用身份与当前资源；不连接IDA。"""
from collections import Counter
from pathlib import Path
import ast
import hashlib
import json
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
from inspect_resources import inspect

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = HERE / '证据'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
NEW = {0x8009A0, 0x800BF0, 0x8012A0, 0x8015B0, 0x7FEA30, 0x7FEBF0, 0x7D5BD0}
DIRECT = {0x609695: 0x7FEA30, 0x6009E1: 0x7D5BD0}


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    nt = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, nt + 6)[0])]

    def disk(va, size):
        offsets = [off + va - base - rva for _, rva, raw, off in sections
                   if base + rva <= va and va + size <= base + rva + raw]
        assert len(offsets) == 1 and offsets[0] + size <= len(image), hex(va)
        return image[offsets[0]:offsets[0] + size]

    def load(name):
        return json.loads((BASE / name).read_text('utf-8'))

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    functions, instructions, ranges, bridges = {}, {}, set(), {}

    def byte_range(row):
        va, size = int(row['va'], 16), row['size']
        assert row['matching'] is True
        raw = disk(va, size)
        assert raw.hex() == row['idb_hex'] == row['disk_hex']
        return va, size, raw

    def code_range(row):
        va, size, raw = byte_range(row)
        decoded = list(decoder.disasm(raw, va))
        assert sum(i.size for i in decoded) == size, hex(va)
        ranges.add((va, size))
        for ins in decoded:
            assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        return {ins.address for ins in decoded}

    def bridge(va, target):
        raw = disk(va, 5)
        assert raw[0] == 0xE9
        actual = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert actual == target
        assert bridges.setdefault(va, target) == target

    exports = [load(name) for name in ('functions_raw.json', 'supplement_raw.json',
                                       'source_constructor_raw.json')]
    reused = load('reused_raw.json')
    reused_map = {int(f['va'], 16): f for f in reused['functions']}
    proven, source_bridges = set(), {}
    for source in reused['provenance']:
        raw = (ROOT / source['source']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == source['source_sha256']
        original_data = json.loads(raw)
        original = {int(f['va'], 16): f for f in original_data['functions']}
        for row in original_data.get('thunks', []):
            assert source_bridges.setdefault(row['va'], row) == row
        for value in source['functions']:
            va = int(value, 16)
            assert va not in proven and reused_map[va] == original[va]
            proven.add(va)
    assert proven == set(reused_map) and len(proven) == 17
    assert {r['va']: r for r in reused['thunks']} == source_bridges
    for data in exports:
        assert data['disk_sha256'] == SHA
    for data in exports + [reused]:
        for row in data.get('thunks', []):
            byte_range(row)
            bridge(int(row['va'], 16), int(row['target'], 16))
        for f in data['functions']:
            va = int(f['va'], 16)
            assert va not in functions and f['bytes_match_disk'] is True
            functions[va] = f
            chunks = f.get('chunk_byte_ranges', f['byte_ranges'])
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16))
                        for c in f.get('declared_chunks', [])}
            bounds = {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks}
            assert declared == bounds if declared else bounds == {(va, int(f['end_va'], 16))}
            covered = set().union(*(code_range(c) for c in chunks))
            reported = set().union(*(code_range(c) for c in f['byte_ranges']))
            assert covered == reported == {int(r['va'], 16) for r in f['assembly']}
            direct_calls = {ea for ea in covered if instructions[ea].mnemonic == 'call'
                            and instructions[ea].op_str.startswith('0x')}
            assert direct_calls == {int(c['site'], 16) for c in f['calls']}
            for call in f['calls']:
                target = int(call['target'], 16)
                assert instructions[int(call['site'], 16)].op_str == hex(target)
                for value in call['thunks']:
                    assert target == int(value, 16)
                    raw = disk(target, 5)
                    destination = target + 5 + struct.unpack_from('<i', raw, 1)[0]
                    bridge(target, destination)
                    target = destination
                assert target == int(call['implementation'], 16)
    assert set(functions) == NEW | set(DIRECT) | proven
    for va, target in DIRECT.items():
        bridge(va, target)

    constants = load('constants_raw.json')
    assert constants['disk_sha256'] == SHA and len(constants['constant_windows']) == 16
    for row in constants['constant_windows']:
        byte_range(row)
    keys = {0xA2E0F8: b'ITEM', 0xA2E100: b'ITEM', 0xA2E108: b'src%d',
            0xA2E110: b'dest', 0xA2E118: b'enable', 0xA2E120: b'true',
            0xA2E12C: b'NEW', 0xA2E130: b'PRI', 0xA2E134: b'limit',
            0xA2E13C: b'NEW', 0xA2E140: b'prop', 0xA2E148: b'pri'}
    for va, key in keys.items():
        assert disk(va, len(key) + 1) == key + b'\0'

    anchors = {
        0x8009D3: ('jge', '0x800a32'),
        0x8009EB: ('imul', 'edx, edx, 0x468'),
        0x800A04: ('fld', 'qword ptr [ecx + edx + 0x2c]'),
        0x800A08: ('fstp', 'qword ptr [esi + eax + 0x1c]'),
        0x800A28: ('fld', 'qword ptr [eax + ecx + 0x34]'),
        0x800A2C: ('fstp', 'qword ptr [esi + edx + 0x24]'),
        0x800CA3: ('mov', 'dword ptr [ecx + 0xc], 0'),
        0x800D0D: ('imul', 'edx, edx, 0x3c'),
        0x800D2C: ('push', '0x609695'),
        0x800D38: ('push', '0x3c'),
        0x800D77: ('mov', 'dword ptr [ecx + 8], edx'),
        0x800DB3: ('cmp', 'dword ptr [ebp - 0x38], 8'),
        0x800DEB: ('jmp', '0x800e76'),
        0x800E2C: ('mov', 'word ptr [ecx + edx], ax'),
        0x800E6C: ('mov', 'word ptr [edx + ecx + 2], ax'),
        0x800E85: ('mov', 'dword ptr [ecx + edx + 0x30], eax'),
        0x800ECB: ('mov', 'dword ptr [edx + ecx + 0x34], eax'),
        0x800F1B: ('mov', 'byte ptr [ecx + edx + 0x38], al'),
        0x80134C: ('mov', 'dword ptr [ecx + 0x94], 0'),
        0x8013C4: ('shl', 'edx, 3'),
        0x8013DF: ('mov', 'dword ptr [eax + 0x98], ecx'),
        0x80143D: ('mov', 'dword ptr [ecx + 0x90], eax'),
        0x8014C8: ('mov', 'dword ptr [edx + ecx*8], eax'),
        0x801510: ('mov', 'dword ptr [edx + ecx*8 + 4], eax'),
        0x8015E5: ('jge', '0x801601'),
        0x8015F3: ('mov', 'eax, dword ptr [ecx + edx*8]'),
        0x8015FB: ('mov', 'al, 1'),
        0x801601: ('xor', 'al, al'),
        0x7FEA3E: ('push', '0x6009e1'),
        0x7FEA43: ('push', '8'),
        0x7FEA45: ('push', '6'),
        0x7FEA53: ('mov', 'dword ptr [ecx + 0x30], 0'),
        0x7FEA5D: ('mov', 'dword ptr [edx + 0x34], 0xffffffff'),
        0x7FEA67: ('mov', 'byte ptr [eax + 0x38], 0'),
        0x7D5BE1: ('mov', 'word ptr [eax], 0xffff'),
        0x7D5BE9: ('mov', 'word ptr [ecx + 2], 0'),
        0x7D5BF2: ('mov', 'byte ptr [edx + 4], 0'),
        0x7D5BF9: ('mov', 'byte ptr [eax + 5], 0xff'),
        0x800FF4: ('mov', 'byte ptr [ebp - 0x31], 0'),
        0x8010B9: ('movsx', 'eax, word ptr [edx + ecx]'),
        0x8010D1: ('movsx', 'edx, word ptr [edx + ecx]'),
        0x8010DC: ('add', 'eax, 1'),
        0x8010FE: ('movsx', 'eax, word ptr [ecx + edx + 2]'),
        0x801120: ('movsx', 'edx, word ptr [eax + ecx + 2]'),
        0x801165: ('mov', 'dword ptr [ebp - 0x28], 7'),
        0x801192: ('mov', 'word ptr [ecx + eax], 0xffff'),
        0x8011A1: ('mov', 'word ptr [eax + edx + 2], 0'),
        0x8011A8: ('mov', 'byte ptr [ebp - 0x31], 1'),
        0x8011AF: ('mov', 'dword ptr [ebp - 0x30], ecx'),
        0x8011DC: ('mov', 'cx, word ptr [ecx + edx + 0x34]'),
        0x801201: ('mov', 'word ptr [eax + edx + 2], 1'),
        0x801249: ('jmp', '0x801023'),
        0x7FF0B6: ('push', '3'),
        0x7FF0BB: ('call', '0x60ca48'),
        0x7FF0CF: ('mov', 'dword ptr [ecx], 0'),
        0x8052FE: ('mov', 'edx, dword ptr [ecx - 4]'),
        0x805302: ('push', '0x468'),
        0x742C05: ('call', '0x611124'),
        0x742FFF: ('call', '0x611124'),
    }
    for ea, expected in anchors.items():
        ins = instructions[ea]
        assert (ins.mnemonic, ins.op_str) == expected, (hex(ea), ins.mnemonic, ins.op_str)
    body = {int(r['va'], 16): instructions[int(r['va'], 16)]
            for r in functions[0x800FD0]['assembly']}
    assert [ea for ea, i in body.items() if i.mnemonic == 'mov'
            and i.op_str == 'byte ptr [ebp - 0x31], 0'] == [0x800FF4]
    # 逐组核指针检测、调用、清零，只闭合本体动作，不给未命名数组赋业务含义。
    offsets = [0x98, 0x9C, 0xA0, 0xAC, 0xB0, 0xBC, 0xC0, 0xCC, 0xD0,
               0xDC, 0xE0, 0xEC, 0xF0, 0xFC, 0x100, 0x10C, 0x110,
               0x11C, 0x120, 0x12C, 0x130, 0x13C, 0x140, 8]
    delete_calls = [c for c in functions[0x7FEBF0]['calls'] if c['target'] == '0x601cd3']
    assert len(delete_calls) == len(offsets) == 24
    for offset, call in zip(offsets, delete_calls):
        ea = int(call['site'], 16)
        group = [i for address, i in instructions.items() if ea - 25 <= address <= ea + 15]
        def zero_field(ins, mnemonic):
            operands = ins.operands
            return (ins.mnemonic == mnemonic and len(operands) == 2
                    and operands[0].type == X86_OP_MEM and operands[0].size == 4
                    and operands[0].mem.disp == offset
                    and operands[1].type == X86_OP_IMM and operands[1].imm == 0)
        assert any(zero_field(i, 'cmp') for i in group), hex(offset)
        assert any(zero_field(i, 'mov') for i in group), hex(offset)
        assert call['implementation'] == '0x91f7e0'

    resource = inspect()
    assert resource == load('resources_author.json')
    ledger = json.loads((HERE / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert len(ledger) == 26 and {int(r['va'], 16) for r in ledger} == set(functions)
    for row in ledger:
        assert all(row.get(k) for k in ('status', 'conclusion', 'unknown', 'evidence'))
        assert all((HERE / name).is_file() for name in row['evidence'])
        va = int(row['va'], 16)
        assert row['status'].startswith('复用') if va in proven else row['status'].startswith('完成')
    documents = list(HERE.glob('*.txt'))
    for doc in documents:
        assert all(not line.strip() or line.lstrip().startswith('//')
                   for line in doc.read_text('utf-8').splitlines())
    scripts = list(HERE.rglob('*.py'))
    for script in scripts:
        ast.parse(script.read_text('utf-8'), filename=str(script))
    result = dict(status='PASS', disk_sha256=SHA, unique_functions=26,
                  new_business_functions=7, new_direct_bridges=2, reused_functions=17,
                  checked_ranges=len(ranges), checked_unique_instructions=len(instructions),
                  checked_unique_bridges=len(bridges),
                  bridge_count_boundary='含复用来源保存的全部桥窗口；不是本批新增函数数量。',
                  new_exported_bridge_windows=len({r['va'] for d in exports for r in d.get('thunks', [])}),
                  reused_exported_bridge_windows=len(source_bridges), constant_windows=16,
                  exact_ascii_keys=len(keys), semantic_anchors=len(anchors),
                  direct_delete_pointer_offsets=[hex(i) for i in offsets],
                  resource_records=[dict(source=r['source'], source_size=r['source_size'],
                                         raw_size=r['raw_size'], packed_size=r['packed_size'])
                                    for r in resource['records']],
                  documents=len(documents), parsed_scripts=len(scripts),
                  semantic_status=dict(Counter(r['status'] for r in ledger)),
                  boundary='有限本体及必要消费契约；桥不计新业务主体，复用不升级新增，未运行游戏。')
    (BASE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
