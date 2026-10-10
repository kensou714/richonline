"""独立从PE和KPD磁盘字节复核Feast原证；不导入作者验证器或执行客户端。"""
import hashlib
import json
import struct
from pathlib import Path

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
BOUNDS = {
    0x6288B0: [(0x6288B0, 0x6288EF)],
    0x7080D0: [(0x7080D0, 0x708314)],
    0x7D89D0: [(0x7D89D0, 0x7D8B75)],
    0x7D8BE0: [(0x7D8BE0, 0x7D8DBC), (0xA151B0, 0xA151C2)],
    0x7D8EB0: [(0x7D8EB0, 0x7D8F0A)],
}
PRIOR_BOUNDS = {
    0x7D8DE0: [(0x7D8DE0, 0x7D8E55)],
    0x7D8E60: [(0x7D8E60, 0x7D8EAB)],
    0x7D90E0: [(0x7D90E0, 0x7D90F9)],
    0x7EFF90: [(0x7EFF90, 0x7EFFA8)],
    0x63E590: [(0x63E590, 0x63E5AA)],
    0x727A70: [(0x727A70, 0x727A89)],
    0x727A90: [(0x727A90, 0x727AA9)],
    0x63F420: [(0x63F420, 0x63F43B)],
    0x662DC0: [(0x662DC0, 0x662E2C)],
    0x694320: [(0x694320, 0x694351)],
    0x63E210: [(0x63E210, 0x63E22A)],
    0x63ECA0: [(0x63ECA0, 0x63ECF6)],
    0x63EDF0: [(0x63EDF0, 0x63EE64)],
}


def load(name):
    return json.loads((HERE / name).read_text('utf-8'))


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
    table = optional + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * n + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        positions = [raw + ea - base - rva for _, rva, length, raw in sections
                     if 0 <= ea - base - rva and ea - base - rva + size <= length]
        assert len(positions) == 1
        data = image[positions[0]:positions[0] + size]
        assert len(data) == size
        return data

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded, bodies = {}, {}
    for ea, spans in {**BOUNDS, **PRIOR_BOUNDS}.items():
        body = []
        for lo, hi in spans:
            instructions = list(decoder.disasm(disk(lo, hi - lo), lo))
            assert instructions and sum(i.size for i in instructions) == hi - lo
            assert instructions[-1].address + instructions[-1].size == hi
            body.extend(instructions)
        bodies[ea] = body
        decoded.update({i.address: i for i in body})
    functions, bridges = {}, {}
    instruction_ranges = declared_ranges = reused_ranges = 0

    def verify_function(row, spans, declared):
        ea = int(row['va'], 16)
        assert int(row['end_va'], 16) == spans[0][1]
        assert [int(i['va'], 16) for i in row['assembly']] == [i.address for i in bodies[ea]]
        keys = ['byte_ranges']
        if declared:
            assert [(int(r['start_va'], 16), int(r['end_va'], 16))
                    for r in row['declared_chunks']] == spans
            keys.append('chunk_byte_ranges')
        for key in keys:
            assert [(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in row[key]] == spans
            for block in row[key]:
                assert disk(int(block['va'], 16), block['size']) == bytes.fromhex(block['idb_hex'])
                assert bytes.fromhex(block['idb_hex']) == bytes.fromhex(block['disk_hex'])
        calls = {}
        for ins in bodies[ea]:
            if ins.mnemonic != 'call':
                continue
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                calls[ins.address] = op.imm
            elif op.type == X86_OP_MEM and not op.mem.base and not op.mem.index:
                calls[ins.address] = op.mem.disp
        assert calls == {int(c['site'], 16): int(c['target'], 16) for c in row['calls']}

    def verify_bridge(row):
        ea = int(row['va'], 16)
        data = disk(ea, 5)
        assert data == bytes.fromhex(row['idb_hex']) == bytes.fromhex(row['disk_hex'])
        instructions = list(decoder.disasm(data, ea))
        assert data[0] == 0xE9 and len(instructions) == 1 and instructions[0].mnemonic == 'jmp'
        target = ea + 5 + struct.unpack_from('<i', data, 1)[0]
        assert target == instructions[0].operands[0].imm == int(row['target'], 16)
        assert ea not in bridges or bridges[ea] == target
        bridges[ea] = target

    for name in ('core_raw.json', 'supplemental_raw.json'):
        raw = load(name)
        assert raw['disk_sha256'] == SHA
        for row in raw['functions']:
            ea = int(row['va'], 16)
            assert ea in BOUNDS and ea not in functions
            verify_function(row, BOUNDS[ea], True)
            functions[ea] = row
            instruction_ranges += len(row['byte_ranges'])
            declared_ranges += len(row['chunk_byte_ranges'])
        for row in raw['thunks']:
            verify_bridge(row)
    assert set(functions) == set(BOUNDS)
    reused = load('reused_evidence.json')
    sources = {}
    for source, sha in reused['source_hashes'].items():
        source_path = ROOT / 'docs/逆向资料' / source
        source_bytes = source_path.read_bytes()
        assert hashlib.sha256(source_bytes).hexdigest() == sha
        sources[source] = {int(f['va'], 16): f for f in json.loads(source_bytes)['functions']}
    reused_addresses = set()
    for row in reused['reused']:
        ea = int(row['va'], 16)
        assert ea not in reused_addresses
        reused_addresses.add(ea)
        assert row['record'] == sources[row['source']][ea]
        spans = BOUNDS[ea] if ea in BOUNDS else PRIOR_BOUNDS[ea]
        verify_function(row['record'], spans, False)
        reused_ranges += len(row['record']['byte_ranges'])
    assert reused_addresses == set(PRIOR_BOUNDS) | {0x6288B0, 0x7080D0}
    for row in reused['thunks']:
        verify_bridge(row)
    anchors = []

    def anchor(ea, mnemonic, operands):
        ins = decoded[ea]
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(ea), ins.mnemonic, ins.op_str)
        anchors.append(dict(va=hex(ea), mnemonic=mnemonic, operands=operands, disk_hex=ins.bytes.hex()))

    checks = [
        (0x6288BB, 'cmp', 'dword ptr [0xa766d4], 0'),
        (0x6288C2, 'jne', '0x6288dc'),
        (0x6288C4, 'push', '0x340'),
        (0x6288C9, 'call', '0x601274'),
        (0x6288D7, 'mov', 'dword ptr [0xa766d4], eax'),
        (0x6288DC, 'mov', 'eax, dword ptr [0xa766d4]'),
        (0x7D8C0D, 'mov', 'dword ptr [ebp - 0x10], ecx'),
        (0x7D8C26, 'call', '0x60fd9c'),
        (0x7D8C2B, 'test', 'eax, eax'),
        (0x7D8C2D, 'jne', '0x7d8c4d'),
        (0x7D8C2F, 'mov', 'dword ptr [ebp - 0x30], 0'),
        (0x7D8C58, 'call', '0x610dfa'),
        (0x7D8C5D, 'push', 'eax'),
        (0x7D8C61, 'call', '0x610440'),
        (0x7D8C66, 'push', 'eax'),
        (0x7D8C67, 'mov', 'ecx, dword ptr [ebp - 0x10]'),
        (0x7D8C6A, 'push', 'ecx'),
        (0x7D8C6B, 'call', '0x60e3e8'),
        (0x7D8D77, 'mov', 'dword ptr [ebp - 0x34], 1'),
        (0xA151B0, 'lea', 'ecx, [ebp - 0x28]'),
        (0xA151B3, 'jmp', '0x602575'),
        (0x7D8DFA, 'sub', 'eax, 0x7d4'),
        (0x7D8E14, 'cmp', 'dword ptr [ebp - 8], 0xd'),
        (0x7D8E18, 'jge', '0x7d8e4c'),
        (0x7D8E1D, 'imul', 'edx, edx, 0x1a'),
        (0x7D8E26, 'movsx', 'ecx, byte ptr [edx + eax*2]'),
        (0x7D8E3B, 'movsx', 'ecx, byte ptr [edx + eax*2 + 1]'),
        (0x7D8E4C, 'or', 'eax, 0xffffffff'),
        (0x7D8E8C, 'call', '0x612817'),
        (0x7D8E93, 'cmp', 'eax, -1'),
        (0x7D8E96, 'setne', 'cl'),
        (0x7D8EC1, 'call', '0x602dbd'),
        (0x7D8ECB, 'je', '0x7d8edb'),
        (0x7D8ED0, 'add', 'ecx, dword ptr [ebp + 0xc]'),
        (0x7D8ED3, 'mov', 'al, byte ptr [ecx + 0x326]'),
        (0x7D8EDE, 'call', '0x606797'),
        (0x7D8EE8, 'je', '0x7d8ef8'),
        (0x7D8EF0, 'mov', 'al, byte ptr [eax + 0x333]'),
        (0x7D8EF8, 'xor', 'al, al'),
        (0x727A81, 'movsx', 'eax, byte ptr [eax + 0xa]'),
        (0x727AA1, 'movsx', 'eax, byte ptr [eax + 0xb]'),
        (0x7D90F1, 'movsx', 'eax, word ptr [eax + 8]'),
        (0x662DF9, 'movsx', 'edx, byte ptr [ecx + 7]'),
        (0x662E01, 'movsx', 'ecx, byte ptr [eax + 6]'),
        (0x662E09, 'movsx', 'eax, word ptr [edx + 4]'),
        (0x662E11, 'add', 'ecx, 0xc44'),
        (0x694335, 'mov', 'word ptr [eax + 8], cx'),
        (0x69433F, 'mov', 'byte ptr [edx + 0xa], al'),
        (0x694348, 'mov', 'byte ptr [ecx + 0xb], dl'),
        (0x7D89EA, 'movsx', 'ecx, byte ptr [eax + 0xb]'),
        (0x7D89F2, 'movsx', 'eax, byte ptr [edx + 0xa]'),
        (0x7D89FA, 'movsx', 'edx, word ptr [ecx + 8]'),
        (0x7D8A06, 'call', '0x612817'),
        (0x7D8A0E, 'mov', 'dword ptr [ecx + 0x10], eax'),
        (0x7D8A14, 'cmp', 'dword ptr [edx + 0x10], -1'),
        (0x7D8A18, 'je', '0x7d8a3d'),
        (0x7D8A24, 'call', '0x6037ae'),
        (0x7D8A31, 'call', '0x6042e9'),
        (0x7D8A36, 'movzx', 'edx, al'),
        (0x7D8A39, 'test', 'edx, edx'),
        (0x7D8A3D, 'mov', 'eax, 1'),
        (0x7D8A50, 'cmp', 'dword ptr [ebp - 8], 0xc'),
        (0x7D8A54, 'ja', '0x7d8b60'),
        (0x7D8B60, 'mov', 'eax, 1'),
        (0x7080F9, 'call', '0x60b841'),
        (0x708101, 'mov', 'dword ptr [ebp - 0x20], 5'),
        (0x708118, 'call', '0x603d17'),
        (0x70811D, 'movzx', 'eax, al'),
        (0x708120, 'test', 'eax, eax'),
        (0x708122, 'je', '0x70812b'),
        (0x708124, 'mov', 'dword ptr [ebp - 0x20], 0x41'),
        (0x708135, 'call', '0x5ffa6e'),
        (0x7081CC, 'call', '0x608d35'),
        (0x70825C, 'call', '0x6034e8'),
        (0x63E5A1, 'add', 'eax, 0xc44'),
        (0x63F431, 'mov', 'eax, dword ptr [eax + 0x1475c]'),
        (0x63E221, 'add', 'eax, 0x65c'),
        (0x63ECBA, 'call', '0x5ffbe0'),
        (0x63ECC4, 'jne', '0x63ecde'),
        (0x63ECC9, 'call', '0x6011ca'),
        (0x63ECD3, 'jne', '0x63ecde'),
        (0x63ECD5, 'mov', 'dword ptr [ebp - 8], 0'),
        (0x63ECDE, 'mov', 'dword ptr [ebp - 8], 1'),
        (0x63EE0A, 'call', '0x608628'),
        (0x63EE14, 'jne', '0x63ee4c'),
        (0x63EE19, 'call', '0x604375'),
        (0x63EE23, 'jne', '0x63ee4c'),
        (0x63EE28, 'call', '0x610c06'),
        (0x63EE32, 'jne', '0x63ee4c'),
        (0x63EE37, 'call', '0x604703'),
        (0x63EE41, 'jne', '0x63ee4c'),
        (0x63EE43, 'mov', 'dword ptr [ebp - 8], 0'),
        (0x63EE4C, 'mov', 'dword ptr [ebp - 8], 1'),
    ]
    for check in checks:
        anchor(*check)
    display_groups = [(0x70813B, 0x708147, 0x708156, 81, 0x708171, 0x708182, 0x70818D, 0x708195, 0x7081B4, 0x7081BB),
                      (0x7081D2, 0x7081DE, 0x7081ED, 83, 0x708208, 0x708219, 0x708224, 0x70822C, 0x70824B, 0x708252),
                      (0x708262, 0x70826E, 0x70827D, 85, 0x708298, 0x7082A9, 0x7082B4, 0x7082BC, 0x7082DB, 0x7082E2)]
    for fmt, sprintf, slot_site, slot, limit, subtract, add, image_call, lookup, attach in display_groups:
        assert decoded[fmt].mnemonic == 'push' and decoded[fmt].operands[0].type == X86_OP_IMM
        assert disk(decoded[fmt].operands[0].imm, 5) == b'%02d\0'
        assert decoded[sprintf].mnemonic == 'call'
        anchor(slot_site, 'mov', f'dword ptr [ebp - 0x14], {hex(slot)}')
        anchor(limit, 'cmp', 'dword ptr [ebp - 0x10], 2')
        anchor(subtract, 'sub', 'edx, 0x30')
        anchor(add, 'add', 'eax, dword ptr [ebp - 0x18]')
        anchor(image_call, 'call', '0x60554a')
        anchor(lookup, 'call', '0x610297')
        anchor(attach, 'call', '0x60bb48')
    flag_stores = []
    for ins in bodies[0x7D8BE0]:
        if ins.mnemonic == 'mov' and ins.operands[0].type == X86_OP_MEM and ins.operands[1].type == X86_OP_IMM:
            offset, value = ins.operands[0].mem.disp, ins.operands[1].imm
            if 806 <= offset <= 831:
                assert ins.operands[0].size == 1
                flag_stores.append((offset, value, ins.address))
    expected_flags = [1] * 26
    expected_flags[20] = expected_flags[23] = 0
    assert len(flag_stores) == 26
    assert sorted((offset, value) for offset, value, _ in flag_stores) == list(enumerate(expected_flags, 806))
    lookup_conditions = [ins for ins in bodies[0x7D8DE0] if ins.mnemonic in ('cmp', 'test')]
    assert [ins.address for ins in lookup_conditions] == [0x7D8E14, 0x7D8E2A, 0x7D8E40]
    navigation = load('navigation_raw.json')
    assert navigation['disk_sha256'] == SHA
    navigation_count = 0
    for target in navigation['targets']:
        for row in target['references']:
            if row['bytes'] is None:
                continue
            block = row['bytes']
            ea, size = int(block['va'], 16), block['size']
            data = disk(ea, size)
            assert data == bytes.fromhex(block['idb_hex']) == bytes.fromhex(block['disk_hex'])
            instructions = list(decoder.disasm(data, ea))
            assert len(instructions) == 1 and instructions[0].size == size
            instruction = instructions[0]
            target_ea = int(row['target'], 16)
            if row['bridge']:
                verify_bridge(dict(va=block['va'], idb_hex=block['idb_hex'],
                                   disk_hex=block['disk_hex'], target=row['target']))
            elif instruction.mnemonic in ('call', 'jmp'):
                assert instruction.operands[0].type == X86_OP_IMM
                assert instruction.operands[0].imm == target_ea
            else:
                assert any(op.type == X86_OP_MEM and op.mem.disp == target_ea for op in instruction.operands)
            navigation_count += 1
    for block in navigation['windows']:
        assert disk(int(block['va'], 16), block['size']) == bytes.fromhex(block['idb_hex']) == bytes.fromhex(block['disk_hex'])
    startup_path = ROOT / 'docs/逆向资料/专题/游戏时间与计时调度/证据/functions.json'
    startup_bytes = startup_path.read_bytes()
    startup = json.loads(startup_bytes)
    assert startup['disk_sha256'] == SHA
    startup_row = next(row for row in startup['functions'] if int(row['va'], 16) == 0x623EE0)
    for block in startup_row['byte_ranges']:
        ea, size = int(block['va'], 16), block['size']
        data = disk(ea, size)
        assert data == bytes.fromhex(block['idb_hex']) == bytes.fromhex(block['disk_hex'])
        decoded.update({i.address: i for i in decoder.disasm(data, ea)})
    for check in [(0x623EFF, 'push', '0xa2233c'),
                  (0x623F04, 'call', '0x60aa90'),
                  (0x623F0B, 'call', '0x60e492'),
                  (0x623F10, 'test', 'eax, eax'),
                  (0x623F12, 'jne', '0x623f1b'),
                  (0x623F14, 'xor', 'eax, eax'),
                  (0x623F16, 'jmp', '0x624072')]:
        anchor(*check)
    assert disk(0xA2233C, 16).startswith(b'Data\\Feast.kpd\0')
    contexts = load('context_raw.json')
    assert contexts['disk_sha256'] == SHA
    context_count = 0
    for context in contexts['contexts']:
        assert [i['va'] for i in context['instructions']] == [i['va'] for i in context['assembly']]
        for block in context['instructions']:
            ea, size = int(block['va'], 16), block['size']
            data = disk(ea, size)
            assert data == bytes.fromhex(block['idb_hex']) == bytes.fromhex(block['disk_hex'])
            instructions = list(decoder.disasm(data, ea))
            assert len(instructions) == 1 and instructions[0].size == size
            decoded[ea] = instructions[0]
            context_count += 1
    switch = contexts['switch_table']
    assert int(switch['va'], 16) == 0x7D8B75 and switch['size'] == 52
    assert disk(0x7D8B75, 52) == bytes.fromhex(switch['idb_hex']) == bytes.fromhex(switch['disk_hex'])
    switch_targets = list(struct.unpack('<13I', disk(0x7D8B75, 52)))
    assert switch_targets == [0x7D8A64, 0x7D8AA3, 0x7D8AB8, 0x7D8ACD, 0x7D8AE2,
                              0x7D8B4E, 0x7D8A79, 0x7D8A8E, 0x7D8AF4, 0x7D8B06,
                              0x7D8B18, 0x7D8B2A, 0x7D8B3C]
    case_bridges = [0x600586, 0x603F1F, 0x60538D, 0x60BFD5, 0x609CD5, 0x60A3F1,
                    0x6001E4, 0x60C3A4, 0x60838A, 0x60B107, 0x612452, 0x605A86, 0x600419]
    case_impls = [0x7BC6D0, 0x7BD060, 0x7BD140, 0x7BD220, 0x7BD300, 0x7BE080,
                  0x7BC9B0, 0x7BCD90, 0x7BD3E0, 0x7BD6C0, 0x7BD7A0, 0x7BDA70, 0x7BDD50]
    for entry, bridge, implementation in zip(switch_targets, case_bridges, case_impls):
        seq = list(decoder.disasm(disk(entry, 32), entry))[:7]
        assert [i.mnemonic for i in seq] == ['mov', 'push', 'mov', 'push', 'mov', 'call', 'jmp']
        assert seq[0].op_str.endswith('dword ptr [ebp + 0x10]')
        assert seq[0].operands[0].reg == seq[1].operands[0].reg
        assert seq[2].op_str.endswith('dword ptr [ebp + 0xc]')
        assert seq[2].operands[0].reg == seq[3].operands[0].reg
        assert seq[4].op_str == 'ecx, dword ptr [ebp + 8]'
        assert seq[5].operands[0].imm == bridge and bridges[bridge] == implementation
        assert seq[6].operands[0].imm == 0x7D8B65
    for check in [(0x7C19DA, 'add', 'ecx, 0xc44'),
                  (0x7C19E0, 'call', '0x609b90'),
                  (0x624864, 'cmp', 'dword ptr [0xa766d4], 0'),
                  (0x62487F, 'call', '0x604cfd'),
                  (0x624887, 'mov', 'dword ptr [0xa766d4], 0'),
                  (0x7C19B0, 'call', '0x603ccc'),
                  (0x7C19BA, 'je', '0x7c19ee'),
                  (0x7C19BF, 'call', '0x607098'),
                  (0x7C19C9, 'jne', '0x7c19ee'),
                  (0x7C19E5, 'test', 'eax, eax'),
                  (0x7C19E7, 'jne', '0x7c19ee'),
                  (0x7C19E9, 'jmp', '0x7c2de1'),
                  (0x7D8A5D, 'jmp', 'dword ptr [edx*4 + 0x7d8b75]')]:
        anchor(*check)
    resource = (ROOT / 'Data/Feast.kpd').read_bytes()
    resource_hash = hashlib.sha256(resource).hexdigest()
    assert resource_hash == '000cf125b6ed51d2a1b9ffccac80be87c9ff9ab58b6b5f991c2ba579fd60933d'
    key = resource[0]
    size, packed = struct.unpack('<II', bytes((b - key) & 255 for b in resource[1:9]))
    assert (len(resource), key, size, packed) == (462, 39, 806, 453)
    assert len(resource) == 9 + packed
    plain = lzokay.decompress(bytes((b - key) & 255 for b in resource[9:]), size)
    assert len(plain) == 806
    plain_hash = hashlib.sha256(plain).hexdigest()
    assert plain_hash == '032df6a9b301f13586f77415171e4dc67e02d0e7583b17f076d03b2f27e5b972'
    sample = load('resource_raw.json')
    assert sample['decoded_hex'] == plain.hex()
    assert sample['source_sha256'] == resource_hash and sample['decoded_sha256'] == plain_hash
    assert sample['record_size'] == 26 and len(sample['rows']) == 31
    for index, row in enumerate(sample['rows']):
        assert row['index'] == index and row['offset'] == index * 26 and row['year_by_lookup'] == 2004 + index
        raw = plain[index * 26:(index + 1) * 26]
        assert row['raw_hex'] == raw.hex()
        assert len(row['pairs']) == 13
        for slot, pair in enumerate(row['pairs']):
            assert (pair['slot'], pair['month'], pair['day']) == (slot, raw[2 * slot], raw[2 * slot + 1])
    duplicates = []
    for index in range(31):
        by_date = {}
        for slot in range(13):
            pair = tuple(plain[index * 26 + slot * 2:index * 26 + slot * 2 + 2])
            by_date.setdefault(pair, []).append(slot)
        for pair, slots in by_date.items():
            if len(slots) > 1:
                duplicates.append([2004 + index, *pair, slots])
    assert duplicates == [[2010, 2, 14, [1, 6]], [2014, 2, 14, [1, 7]],
                          [2020, 10, 25, [10, 11]], [2025, 10, 6, [10, 11]], [2033, 2, 14, [1, 7]]]
    object_bytes = plain + bytes(expected_flags)
    assert len(object_bytes) == 832
    assert object_bytes[(2035 - 2004) * 26:(2035 - 2004) * 26 + 2] == bytes([1, 1])
    review = load('function_review.json')
    review_rows = {int(row['va'], 16): row for row in review['functions']}
    assert len(review['functions']) == len(review_rows) == 20
    assert set(review_rows) == set(bodies) | {0x7C0C50, 0x624080}
    assert review['counts'] == {'复用已审阅': 15, '局部语义已审阅': 3, '部分分析': 2}
    local_ranges = {int(row['owner'], 16): row['instructions'] for row in contexts['contexts']}
    for ea, row in review_rows.items():
        assert row['full_dependency_closure'] is False
        assert row['unknown'] and row['conclusion']
        if ea in local_ranges:
            assert row['reviewed_chunks'] == [] and row['status'] == '部分分析'
            assert row['reviewed_evidence_ranges'] == local_ranges[ea]
        else:
            assert row['status'] == ('局部语义已审阅' if ea in {0x7D89D0, 0x7D8BE0, 0x7D8EB0} else '复用已审阅')
            spans = BOUNDS[ea] if ea in BOUNDS else PRIOR_BOUNDS[ea]
            assert [(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in row['reviewed_evidence_ranges']] == spans
            for r in row['reviewed_evidence_ranges']:
                assert disk(int(r['va'], 16), r['size']) == bytes.fromhex(r['idb_hex']) == bytes.fromhex(r['disk_hex'])
            if row['reviewed_chunks']:
                assert [(int(r['start_va'], 16), int(r['end_va'], 16)) for r in row['reviewed_chunks']] == spans
        for source in row['evidence']:
            assert (ROOT / 'docs/逆向资料' / source).is_file()
    document_hashes = {}
    for path in HERE.parent.glob('*.txt'):
        if path.name == '独立审阅.txt':
            continue
        text = path.read_text('utf-8-sig')
        assert all(not line.strip() or line.startswith('//') for line in text.splitlines()), path
        document_hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(document_hashes) >= 8
    result = dict(status='PASS', disk_sha256=SHA,
                  capstone_version=capstone.__version__, core_functions=5,
                  core_instructions=sum(len(bodies[ea]) for ea in BOUNDS),
                  core_instruction_ranges=instruction_ranges, core_declared_ranges=declared_ranges,
                  prior_records=len(reused_addresses), prior_ranges=reused_ranges,
                  unique_function_addresses=len(bodies),
                  unique_instruction_addresses=len({i.address for body in bodies.values() for i in body}), unique_e9_bridges=len(bridges),
                  navigation_instruction_records=navigation_count, context_instruction_records=context_count,
                  semantic_anchors=anchors, flag_writes=flag_stores, switch_targets=[hex(v) for v in switch_targets],
                  case_bridges=[hex(v) for v in case_bridges], case_targets=[hex(v) for v in case_impls],
                  duplicate_dates=duplicates, default_2035_january_first_static_slot=0,
                  reviewed_entries=20, document_hashes=document_hashes,
                  startup_support=dict(source=str(startup_path.relative_to(ROOT)),
                                       source_sha256=hashlib.sha256(startup_bytes).hexdigest(),
                                       scope='旧原证范围逐字节核对，只审Feast调用与失败分支，不增加完整语义函数计量'),
                  resource=dict(source_sha256=resource_hash, decoded_sha256=plain_hash,
                                bytes=806, rows=31, pairs=403, runtime_loading_verified=False),
                  scope='独立静态字节与局部语义核验；旧范围不补造声明尾块；分派目标导航不等于下游效果审阅')
    (HERE / 'independent_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('semantic_anchors', 'flag_writes')}, ensure_ascii=True))


if __name__ == '__main__':
    main()
