"""独立从当前PE重解码，核对文本解析正文；不导入作者验证器或执行游戏。"""
import hashlib
import json
import struct
from pathlib import Path

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_EBP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
BOUNDS = {
    0x8191D0: 0x81921F, 0x819220: 0x819244, 0x819250: 0x8193E7,
    0x8193F0: 0x81946D, 0x819470: 0x819657, 0x819660: 0x8198D8,
    0x819FB0: 0x81A08E,
}


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    assert image[:2] == b'MZ'
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 4)[0] == 0x14C
    optional = pe + 24
    assert struct.unpack_from('<H', image, optional)[0] == 0x10B
    base = struct.unpack_from('<I', image, optional + 28)[0]
    section_table = optional + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_table + 40 * n + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        matches = [(raw + ea - base - rva) for _, rva, length, raw in sections
                   if 0 <= ea - base - rva and ea - base - rva + size <= length]
        assert len(matches) == 1, (hex(ea), size)
        return image[matches[0]:matches[0] + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded = {}
    bodies = {}
    for start, end in BOUNDS.items():
        instructions = list(decoder.disasm(disk(start, end - start), start))
        assert instructions and instructions[-1].address + instructions[-1].size == end
        assert sum(i.size for i in instructions) == end - start
        assert instructions[-1].mnemonic == 'ret'
        bodies[start] = instructions
        decoded.update({i.address: i for i in instructions})

    functions_raw = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    rows = {int(f['va'], 16): f for f in functions_raw['functions']}
    assert set(rows) == set(BOUNDS)
    assert functions_raw['disk_sha256'] == SHA
    ranges = 0
    for start, row in rows.items():
        assert int(row['end_va'], 16) == BOUNDS[start]
        assert len(row['declared_chunks']) == len(row['chunk_byte_ranges']) == 1
        assert [int(a['va'], 16) for a in row['assembly']] == [i.address for i in bodies[start]]
        declared = row['declared_chunks'][0]
        assert int(declared['start_va'], 16) == start
        assert int(declared['end_va'], 16) == BOUNDS[start]
        for raw in row['chunk_byte_ranges'] + row['byte_ranges']:
            ea, size = int(raw['va'], 16), raw['size']
            assert start <= ea and ea + size <= BOUNDS[start]
            assert bytes.fromhex(raw['idb_hex']) == bytes.fromhex(raw['disk_hex']) == disk(ea, size)
            ranges += 1
        calls = {i.address: i.operands[0].imm for i in bodies[start]
                 if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM}
        assert calls == {int(c['site'], 16): int(c['target'], 16) for c in row['calls']}

    extra = json.loads((HERE / 'bridges_constants_raw.json').read_text('utf-8'))
    bridges = {}
    for raw in functions_raw['thunks'] + extra['bridges']:
        ea = int(raw['va'], 16)
        actual = disk(ea, 5)
        assert actual == bytes.fromhex(raw['idb_hex']) == bytes.fromhex(raw['disk_hex'])
        instruction = list(decoder.disasm(actual, ea))
        assert len(instruction) == 1 and instruction[0].mnemonic == 'jmp'
        assert actual[0] == 0xE9
        target = instruction[0].operands[0].imm
        assert target == int(raw['target'], 16)
        assert target == ea + 5 + struct.unpack_from('<i', actual, 1)[0]
        assert ea not in bridges or bridges[ea] == target
        bridges[ea] = target
    assert len(bridges) == 18
    for raw in extra['constant_windows']:
        assert disk(int(raw['va'], 16), raw['size']) == bytes.fromhex(raw['idb_hex'])
        assert raw['idb_hex'] == raw['disk_hex']
    assert disk(0xA2EA6C, 3) == b'rt\0'
    for ea in (0xABAA60, 0xABAB00):
        assert any(base + rva <= ea < base + rva + virtual for virtual, rva, _, _ in sections)
        assert not any(base + rva <= ea < base + rva + size for _, rva, size, _ in sections)

    anchors = []

    def instruction(ea, mnemonic, operands):
        actual = decoded[ea]
        assert actual.mnemonic == mnemonic and actual.op_str == operands, (hex(ea), actual.op_str)
        anchors.append({'va': hex(ea), 'mnemonic': mnemonic, 'operands': operands,
                        'disk_hex': actual.bytes.hex()})

    # 分支取自磁盘指令，覆盖无效模式、生命周期、段末空白与键后等号路径。
    checks = [
        (0x819271, 'call', '0x607c3c'),
        (0x819298, 'jne', '0x819356'),
        (0x819356, 'cmp', 'dword ptr [ebp + 8], 2'),
        (0x81935A, 'jne', '0x819397'),
        (0x819397, 'movzx', 'edx, byte ptr [ebp + 0x14]'),
        (0x81939D, 'je', '0x8193a7'),
        (0x8193A2, 'call', '0x60d71d'),
        (0x8193B0, 'mov', 'dword ptr [eax + 0x8c], edx'),
        (0x8193BF, 'mov', 'dword ptr [eax + 0x94], edx'),
        (0x8193C8, 'mov', 'dword ptr [eax + 0x9c], 1'),
        (0x8193D2, 'mov', 'eax, 1'),
        (0x81940A, 'mov', 'dword ptr [eax], 0'),
        (0x81944D, 'call', '0x604cfd'),
        (0x81A010, 'jge', '0x81a043'),
        (0x81A01F, 'cmp', 'eax, 0xd'),
        (0x81A022, 'je', '0x81a041'),
        (0x81A059, 'call', '0x604cfd'),
        (0x81A071, 'mov', 'dword ptr [eax + 4], ecx'),
        (0x81A07A, 'mov', 'dword ptr [edx + 0x88], eax'),
        (0x8194A5, 'jge', '0x819645'),
        (0x819520, 'jne', '0x819602'),
        (0x81959F, 'mov', 'byte ptr [edx], 0'),
        (0x8195AF, 'call', '0x60b2c4'),
        (0x8195B9, 'je', '0x8195d2'),
        (0x8195D0, 'jmp', '0x8195a2'),
        (0x8195E5, 'jne', '0x819600'),
        (0x819640, 'jmp', '0x81948d'),
        (0x81968C, 'mov', 'dword ptr [eax + 0x90], edx'),
        (0x8196AA, 'jge', '0x8198c6'),
        (0x8196BE, 'je', '0x8198c6'),
        (0x81973B, 'jmp', '0x8198c6'),
        (0x8197EE, 'jne', '0x819883'),
        (0x8197FB, 'je', '0x81983b'),
        (0x81981E, 'cmp', 'ecx, 0x3d'),
        (0x819839, 'jmp', '0x8197fd'),
        (0x819848, 'call', '0x60b2c4'),
        (0x819860, 'cmp', 'edx, 0xa'),
        (0x819863, 'je', '0x81987c'),
        (0x81987C, 'mov', 'eax, 1'),
    ]
    for check in checks:
        instruction(*check)

    def non_stack_writes(start):
        return [(i.address, i.operands[0].mem.disp) for i in bodies[start]
                if i.mnemonic == 'mov' and i.operands[0].type == X86_OP_MEM
                and i.operands[0].mem.base != X86_REG_EBP]

    assert {d for _, d in non_stack_writes(0x8191D0)} == {0, 4, 0x8C, 0x90, 0x94}
    assert {d for _, d in non_stack_writes(0x8193F0)} == {0, 4, 0x8C, 0x90, 0x94}
    assert [i.operands[0].imm for i in bodies[0x8193F0] if i.mnemonic == 'call'] == [0x604CFD, 0x60B576]
    assert not ({0x8C, 0x90, 0x94} & {d for _, d in non_stack_writes(0x819FB0)})
    assert not ({0x88, 0x98, 0x9C} & {d for _, d in non_stack_writes(0x8193F0)})
    assert {d for _, d in non_stack_writes(0x819470)} <= {0, 0x8C, 0x90}
    # 等号内循环只比较'='与本地标记，不访问长度、LF、NUL或段括号。
    equals_loop = [i for i in bodies[0x819660] if 0x8197FD <= i.address <= 0x819839]
    assert [(i.address, i.op_str) for i in equals_loop if i.mnemonic == 'cmp'] == [
        (0x81981E, 'ecx, 0x3d'), (0x819833, 'dword ptr [ebp - 0x14], 0')]
    assert [i.operands[0].imm for i in equals_loop if i.mnemonic == 'jmp'][-1] == 0x8197FD

    result = {
        'status': 'PASS', 'disk_sha256': SHA, 'capstone_version': capstone.__version__,
        'independent_body_count': len(BOUNDS), 'instruction_count': len(decoded),
        'evidence_ranges_rechecked': ranges, 'unique_e9_bridges': len(bridges),
        'semantic_anchors': anchors,
        'scope': '磁盘PE独立解码与逐指令控制流审阅；未执行游戏、畸形输入或外部CRT本体',
    }
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'semantic_anchors'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
