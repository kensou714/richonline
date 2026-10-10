"""从当前 PE 独立解码并核验 TeachMode 状态来源；不导入作者验证器。"""
import hashlib
import json
import struct
from pathlib import Path

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
BOUNDS = {
    0x628270: [(0x628270, 0x62830D), (0xA11450, 0xA11465)],
    0x6AC390: [(0x6AC390, 0x6AC4D5)],
    0x6AFA40: [(0x6AFA40, 0x6AFA66)],
    0x82B090: [(0x82B090, 0x82B7E3)],
    0x69DF50: [(0x69DF50, 0x69E5F7), (0xA11EE0, 0xA11F9A)],
    0x6A11E0: [(0x6A11E0, 0x6A1253)],
    0x6A1660: [(0x6A1660, 0x6A1729)],
    0x6A18B0: [(0x6A18B0, 0x6A1944)],
    0x6A21A0: [(0x6A21A0, 0x6A223E)],
    0x728C10: [(0x728C10, 0x728F34), (0xA14324, 0xA14339)],
    0x72C050: [(0x72C050, 0x72C2CE)],
    0x72C2D0: [(0x72C2D0, 0x72C66E)],
    0x63E210: [(0x63E210, 0x63E22A)],
    0x6A14B0: [(0x6A14B0, 0x6A1522)],
    0x7284B0: [(0x7284B0, 0x7284C8)],
    0x62BB80: [(0x62BB80, 0x62BBBB)],
    0x8974F0: [(0x8974F0, 0x89761E), (0xA198C0, 0xA198DD)],
    0x62B8E0: [(0x62B8E0, 0x62B904)],
    0x897440: [(0x897440, 0x8974C4), (0xA198A0, 0xA198B2)],
    0xA205F0: [(0xA205F0, 0xA2062C)],
    0x82A900: [(0x82A900, 0x82A930)],
    0x82AB80: [(0x82AB80, 0x82ABB0)],
    0x82BC80: [(0x82BC80, 0x82BCC2)],
    0x8976E0: [(0x8976E0, 0x897772), (0xA198F0, 0xA19908)],
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
    table = optional + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * n + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        positions = [raw + ea - base - rva for _, rva, length, raw in sections
                     if 0 <= ea - base - rva and ea - base - rva + size <= length]
        assert len(positions) == 1, (hex(ea), size)
        return image[positions[0]:positions[0] + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded, bodies = {}, {}
    for start, spans in BOUNDS.items():
        body = []
        for lo, hi in spans:
            instructions = list(decoder.disasm(disk(lo, hi - lo), lo))
            assert instructions and sum(i.size for i in instructions) == hi - lo
            assert instructions[-1].address + instructions[-1].size == hi
            body.extend(instructions)
        bodies[start] = body
        decoded.update({i.address: i for i in body})

    raw_functions, bridges = {}, {}
    byte_ranges = declared_ranges = 0
    for file in sorted(HERE.glob('*_raw.json')):
        raw = json.loads(file.read_text('utf-8'))
        assert raw['disk_sha256'] == SHA
        for function in raw['functions']:
            start = int(function['va'], 16)
            assert start in BOUNDS and start not in raw_functions
            raw_functions[start] = function
            assert int(function['end_va'], 16) == BOUNDS[start][0][1]
            assert [(int(c['start_va'], 16), int(c['end_va'], 16))
                    for c in function['declared_chunks']] == BOUNDS[start]
            assert [int(a['va'], 16) for a in function['assembly']] == [i.address for i in bodies[start]]
            for key in ('byte_ranges', 'chunk_byte_ranges'):
                assert [(int(r['va'], 16), int(r['va'], 16) + r['size'])
                        for r in function[key]] == BOUNDS[start]
                for row in function[key]:
                    assert disk(int(row['va'], 16), row['size']) == bytes.fromhex(row['idb_hex'])
                    assert row['idb_hex'] == row['disk_hex']
                    byte_ranges += key == 'byte_ranges'
                    declared_ranges += key == 'chunk_byte_ranges'
            calls = {i.address: i.operands[0].imm for i in bodies[start]
                     if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM}
            calls.update({i.address: i.operands[0].mem.disp for i in bodies[start]
                          if i.mnemonic == 'call' and i.operands[0].type == X86_OP_MEM
                          and not i.operands[0].mem.base and not i.operands[0].mem.index})
            exported_calls = {int(c['site'], 16): int(c['target'], 16) for c in function['calls']}
            assert calls == exported_calls, (hex(start), calls, exported_calls)
        for row in raw['thunks']:
            ea = int(row['va'], 16)
            data = disk(ea, 5)
            assert data == bytes.fromhex(row['idb_hex']) == bytes.fromhex(row['disk_hex'])
            ins = list(decoder.disasm(data, ea))
            assert data[0] == 0xE9 and len(ins) == 1 and ins[0].mnemonic == 'jmp'
            target = ea + 5 + struct.unpack_from('<i', data, 1)[0]
            assert target == ins[0].operands[0].imm == int(row['target'], 16)
            assert ea not in bridges or bridges[ea] == target
            bridges[ea] = target
    assert set(raw_functions) == set(BOUNDS) and len(bridges) == 108

    anchors = []

    def anchor(ea, mnemonic, operands):
        ins = decoded[ea]
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(ea), ins.mnemonic, ins.op_str)
        anchors.append(dict(va=hex(ea), mnemonic=mnemonic, operands=operands, disk_hex=ins.bytes.hex()))

    checks = [
        (0x6282A9, 'push', '0xabc'),
        (0x6282C9, 'call', '0x610b7a'),
        (0x6282EA, 'mov', 'dword ptr [0xa76728], ecx'),
        (0x69DFFC, 'mov', 'dword ptr [ecx + 0x25c], 0'),
        (0x6A11FD, 'mov', 'word ptr [ebp - 0x10], 0xffff'),
        (0x6A1203, 'mov', 'word ptr [ebp - 0xe], 0xffff'),
        (0x6A1209, 'mov', 'word ptr [ebp - 0xc], 0xffff'),
        (0x6A1221, 'push', '0x2f'),
        (0x6A1223, 'call', '0x60f1e4'),
        (0x6A122E, 'mov', 'dword ptr [ecx + 0x25c], eax'),
        (0x82B779, 'call', '0x60ed48'),
        (0x82B77E, 'mov', 'ecx, eax'),
        (0x82B780, 'call', '0x6005e0'),
        (0x82B785, 'mov', 'ecx, eax'),
        (0x82B787, 'call', '0x60df01'),
        (0x82B78C, 'mov', 'ecx, eax'),
        (0x82B78E, 'call', '0x6062ce'),
        (0x82ABA6, 'mov', 'eax, dword ptr [eax + 0x20]'),
        (0x82A926, 'mov', 'eax, dword ptr [eax + 0x50]'),
        (0x82BCA6, 'add', 'ecx, 0x68'),
        (0x82BCA9, 'call', '0x60590a'),
        (0x62B8F1, 'call', '0x612a47'),
        (0x62BB9A, 'cmp', 'dword ptr [eax + 0x18], 0x10'),
        (0x62BB9E, 'jb', '0x62bbab'),
        (0x62BBA3, 'mov', 'edx, dword ptr [ecx + 4]'),
        (0x62BBAE, 'add', 'eax, 4'),
        (0x897718, 'and', 'eax, 1'),
        (0x89771B, 'jne', '0x89774f'),
        (0x897731, 'mov', 'ecx, 0xacbb30'),
        (0x89773B, 'push', '0xa205f0'),
        (0x89774F, 'mov', 'eax, 0xacbb30'),
        (0xA2060E, 'mov', 'ecx, 0xacbb30'),
        (0xA20613, 'call', '0x608e9d'),
        (0x89757B, 'mov', 'eax, dword ptr [eax + 0x1c]'),
        (0x8975A1, 'push', '1'),
        (0x8975B1, 'call', 'dword ptr [eax]'),
        (0x6A1688, 'mov', 'eax, dword ptr [eax]'),
        (0x6A1696, 'idiv', 'ecx'),
        (0x6A16A4, 'idiv', 'ecx'),
        (0x6A16B5, 'lea', 'ecx, [eax + edx*4 + 0xaf]'),
        (0x6A16C7, 'lea', 'ecx, [eax + edx*4 + 5]'),
        (0x6A16D1, 'cmp', 'dword ptr [edx + 0x25c], 0'),
        (0x6A16EF, 'jbe', '0x6a170f'),
        (0x6A1701, 'cmp', 'edx, 2'),
        (0x6A18CD, 'imul', 'eax, eax, 7'),
        (0x6A18D0, 'add', 'eax, 0x6e'),
        (0x6A18D6, 'mov', 'dword ptr [ebp - 0xc], 4'),
        (0x6A18F2, 'jbe', '0x6a1931'),
        (0x6A1906, 'cmp', 'dword ptr [ebp - 0x10], 7'),
        (0x6A191F, 'cmp', 'ecx, 1'),
        (0x6A1929, 'add', 'edx, 1'),
        (0x63E221, 'add', 'eax, 0x65c'),
        (0x7284C1, 'mov', 'eax, dword ptr [eax + 0x68]'),
        (0x6AFA51, 'call', '0x611e94'),
        (0x6AFA63, 'ret', '4'),
        (0x6AC3C9, 'call', '0x611e94'),
    ]
    for check in checks:
        anchor(*check)
    for ea, target in {0x610B7A: 0x69DF50, 0x60F1E4: 0x82B090,
                       0x60ED48: 0x8976E0, 0x6005E0: 0x82AB80,
                       0x60DF01: 0x82A900, 0x6062CE: 0x82BC80,
                       0x60590A: 0x62B8E0, 0x612A47: 0x62BB80,
                       0x608E9D: 0x8974F0, 0x604555: 0x897440,
                       0x611E94: 0x6A11E0}.items():
        assert bridges[ea] == target

    # 分派表从磁盘间接跳转操作数定位，47只是该本地函数的索引。
    switch = decoded[0x82B0CA]
    assert switch.mnemonic == 'jmp' and switch.operands[0].type == X86_OP_MEM
    switch_table = switch.operands[0].mem.disp
    case47 = disk(switch_table + 47 * 4, 4)
    assert struct.unpack('<I', case47)[0] == 0x82B779
    loop = [i for i in bodies[0x6A18B0] if 0x6A18F4 <= i.address <= 0x6A192F]
    assert [(i.address, i.op_str) for i in loop if i.mnemonic == 'cmp'] == [
        (0x6A1906, 'dword ptr [ebp - 0x10], 7'), (0x6A191F, 'ecx, 1')]

    candidate_counts, contexts = {}, 0
    for file in sorted(HERE.glob('*_candidates.json')):
        raw = json.loads(file.read_text('utf-8'))
        candidate_counts[file.name] = len(raw['candidates'])
        for row in raw['candidates']:
            assert row['status'].startswith('候选')
            for item in row['context']:
                ea, size = int(item['va'], 16), item['size']
                data = disk(ea, size)
                assert data == bytes.fromhex(item['hex'])
                ins = list(decoder.disasm(data, ea))
                assert len(ins) == 1 and ins[0].size == size
                contexts += 1
    assert candidate_counts == {'absolute_index_candidates.json': 4,
                                'embedded_roots_candidates.json': 7,
                                'field_candidates.json': 956}
    prior = json.loads((HERE.parents[1] / 'TeachMode对象与消费者/证据/teachmode_raw.json').read_text('utf-8'))
    prior_functions = {int(f['va'], 16): f for f in prior['functions']}
    for ea in (0x6A14B0, 0x7284B0):
        assert [(int(c['va'], 16), int(c['end_va'], 16))
                for c in prior_functions[ea]['chunks']] == BOUNDS[ea]
        for row in prior_functions[ea]['chunks']:
            assert disk(int(row['va'], 16), row['size']) == bytes.fromhex(row['idb_hex'])
            assert row['idb_hex'] == row['disk_hex']
    prior_sites = {}
    for ea in (0x7F3C70, 0x717C70):
        for row in prior_functions[ea]['instructions']:
            at = int(row['va'], 16)
            if (0x7F3CC4 <= at <= 0x7F3CD2 or 0x7F3D71 <= at <= 0x7F3D74
                    or 0x71851F <= at <= 0x718526):
                data = disk(at, row['size'])
                assert data == bytes.fromhex(row['hex'])
                ins = list(decoder.disasm(data, at))
                assert len(ins) == 1 and ins[0].size == row['size']
                decoded[at] = ins[0]
                prior_sites[at] = data.hex()
    for check in [(0x7F3CC7, 'mov', 'ecx, dword ptr [eax + 0x57c]'),
                  (0x7F3CCD, 'call', '0x6037ae'),
                  (0x7F3D71, 'mov', 'ecx, dword ptr [ebp - 0x18]'),
                  (0x7F3D74, 'call', '0x612a38'),
                  (0x71851F, 'call', '0x6037ae'),
                  (0x718524, 'mov', 'ecx, eax'),
                  (0x718526, 'call', '0x612a38')]:
        anchor(*check)
    prior_bridges = []
    for ea, target in [(0x6037AE, 0x63E210), (0x612A38, 0x7284B0)]:
        data = disk(ea, 5)
        assert data[0] == 0xE9 and ea + 5 + struct.unpack_from('<i', data, 1)[0] == target
        prior_bridges.append(dict(va=hex(ea), target=hex(target), disk_hex=data.hex()))
    reviews = json.loads((HERE.parent / '函数审阅清单.json').read_text('utf-8'))
    assert len(reviews['functions']) == 24
    assert {int(r['va'], 16) for r in reviews['functions']} == set(BOUNDS)
    for file in HERE.parent.glob('*.txt'):
        assert all(not s.strip() or s.startswith('//') for s in file.read_text('utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=SHA, capstone_version=capstone.__version__,
                  functions_redecoded=24, instruction_count=sum(len(b) for b in bodies.values()),
                  declared_ranges_rechecked=declared_ranges, instruction_ranges_rechecked=byte_ranges,
                  unique_e9_bridges=len(bridges), semantic_anchors=anchors,
                  case47_table=dict(va=hex(switch_table + 47 * 4), disk_hex=case47.hex(), target='0x82b779'),
                  candidate_counts=candidate_counts, candidate_contexts_redecoded=contexts,
                  prior_body_reuse_verified=['0x6a14b0', '0x7284b0'],
                  prior_consumer_sites_rechecked=len(prior_sites), prior_consumer_bridges=prior_bridges,
                  scope='独立磁盘字节和解码核验；完整/局部/既有复用语义分级保留；未实机执行，未审字符串写入链和序号写入者')
    (HERE / 'independent_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'semantic_anchors'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
