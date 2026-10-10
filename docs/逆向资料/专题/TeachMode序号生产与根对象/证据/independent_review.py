"""独立解析当前 PE，核验根对象及序号生产原证；不运行游戏或导入作者验证器。"""
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
BOUNDS = {
    0x629C90: [(0x629C90, 0x629D2D), (0xA11730, 0xA11745)],
    0x64F2A0: [(0x64F2A0, 0x64F633)],
    0x7DF010: [(0x7DF010, 0x7E0DDF), (0xA1543A, 0xA154F7)],
    0x7BAE60: [(0x7BAE60, 0x7BB13C), (0xA15040, 0xA1507F)],
    0x7DE310: [(0x7DE310, 0x7DE5C0), (0xA153E0, 0xA15406)],
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
        offsets = [raw + ea - base - rva for _, rva, length, raw in sections
                   if 0 <= ea - base - rva and ea - base - rva + size <= length]
        assert len(offsets) == 1, (hex(ea), size)
        return image[offsets[0]:offsets[0] + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded, bodies = {}, {}
    for start, spans in BOUNDS.items():
        body = []
        for lo, hi in spans:
            ins = list(decoder.disasm(disk(lo, hi - lo), lo))
            assert ins and sum(i.size for i in ins) == hi - lo
            assert ins[-1].address + ins[-1].size == hi
            body.extend(ins)
        bodies[start] = body
        decoded.update({i.address: i for i in body})
    functions, bridges = {}, {}
    ranges = 0
    for file in sorted(HERE.glob('*_raw.json')):
        raw = json.loads(file.read_text('utf-8'))
        assert raw['disk_sha256'] == SHA
        for row in raw['functions']:
            ea = int(row['va'], 16)
            assert ea in BOUNDS and ea not in functions
            functions[ea] = row
            assert int(row['end_va'], 16) == BOUNDS[ea][0][1]
            assert [(int(c['start_va'], 16), int(c['end_va'], 16))
                    for c in row['declared_chunks']] == BOUNDS[ea]
            assert [int(a['va'], 16) for a in row['assembly']] == [i.address for i in bodies[ea]]
            for key in ('byte_ranges', 'chunk_byte_ranges'):
                assert [(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in row[key]] == BOUNDS[ea]
                for block in row[key]:
                    assert disk(int(block['va'], 16), block['size']) == bytes.fromhex(block['idb_hex'])
                    assert block['idb_hex'] == block['disk_hex']
                    ranges += 1
            calls = {i.address: i.operands[0].imm for i in bodies[ea]
                     if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM}
            calls.update({i.address: i.operands[0].mem.disp for i in bodies[ea]
                          if i.mnemonic == 'call' and i.operands[0].type == X86_OP_MEM
                          and not i.operands[0].mem.base and not i.operands[0].mem.index})
            assert calls == {int(c['site'], 16): int(c['target'], 16) for c in row['calls']}
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
    assert set(functions) == set(BOUNDS)
    anchors = []

    def anchor(ea, mnemonic, operands):
        ins = decoded[ea]
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(ea), ins.mnemonic, ins.op_str)
        anchors.append(dict(va=hex(ea), mnemonic=mnemonic, operands=operands, disk_hex=ins.bytes.hex()))

    checks = [
        (0x629CC0, 'cmp', 'dword ptr [0xa7672c], 0'),
        (0x629CC7, 'jne', '0x629d10'),
        (0x629CC9, 'push', '0x14794'),
        (0x629CCE, 'call', '0x601274'),
        (0x629CD6, 'mov', 'dword ptr [ebp - 0x14], eax'),
        (0x629CE0, 'cmp', 'dword ptr [ebp - 0x14], 0'),
        (0x629CE4, 'je', '0x629cf3'),
        (0x629CE6, 'mov', 'ecx, dword ptr [ebp - 0x14]'),
        (0x629CE9, 'call', '0x600c43'),
        (0x629CEE, 'mov', 'dword ptr [ebp - 0x18], eax'),
        (0x629CF3, 'mov', 'dword ptr [ebp - 0x18], 0'),
        (0x629D0A, 'mov', 'dword ptr [0xa7672c], ecx'),
        (0x629D10, 'mov', 'eax, dword ptr [0xa7672c]'),
        (0xA11730, 'mov', 'eax, dword ptr [ebp - 0x14]'),
        (0xA11733, 'push', 'eax'),
        (0xA11734, 'call', '0x604cfd'),
        (0x7BAF06, 'mov', 'ecx, dword ptr [ebp - 0x10]'),
        (0x7BAF09, 'add', 'ecx, 0x65c'),
        (0x7BAF0F, 'call', '0x60700c'),
        (0x7DE3C1, 'mov', 'dword ptr [edx + 0x68], 0'),
        (0x7DE3CB, 'mov', 'dword ptr [eax + 0x6c], 0'),
        (0x7DE3D5, 'mov', 'dword ptr [ecx + 0x70], 0'),
        (0x64F2D8, 'add', 'eax, 8'),
        (0x64F2B6, 'mov', 'dword ptr [ebp - 4], ecx'),
        (0x64F2DE, 'add', 'edi, 0x40'),
        (0x64F2E1, 'mov', 'ecx, 0x16'),
        (0x64F2E8, 'rep movsd', 'dword ptr es:[edi], dword ptr [esi]'),
        (0x64F32D, 'add', 'ecx, 0x65c'),
        (0x64F32A, 'mov', 'ecx, dword ptr [ebp - 4]'),
        (0x64F333, 'call', '0x60469a'),
        (0x64F338, 'test', 'eax, eax'),
        (0x64F33A, 'jne', '0x64f343'),
        (0x64F33C, 'xor', 'eax, eax'),
        (0x7DF04B, 'mov', 'dword ptr [ebp - 0x14], ecx'),
        (0x7DF0B4, 'cmp', 'dword ptr [ebp - 0x88], 0'),
        (0x7DF0C4, 'push', '1'),
        (0x7DF0C6, 'push', '0x10'),
        (0x7DF0CF, 'call', '0x5ffc49'),
        (0x7DF0DE, 'push', '1'),
        (0x7DF0E0, 'push', '4'),
        (0x7DF0E5, 'add', 'eax, 4'),
        (0x7DF0E9, 'call', '0x5ff1ea'),
        (0x7DF0F1, 'push', '1'),
        (0x7DF0F3, 'push', '0x5ae4'),
        (0x7DF0FF, 'call', '0x5ffc49'),
        (0x7DF115, 'add', 'eax, 0x18'),
        (0x7DF119, 'call', '0x5ff1ea'),
        (0x7DF124, 'cmp', 'dword ptr [ecx + 4], 2'),
        (0x7DF128, 'jl', '0x7df15e'),
        (0x7DF131, 'push', '1'),
        (0x7DF133, 'push', '4'),
        (0x7DF138, 'add', 'eax, 0x68'),
        (0x7DF13C, 'call', '0x5ff1ea'),
        (0x7DF152, 'add', 'edx, 0x6c'),
        (0x7DF156, 'call', '0x5ff1ea'),
        (0x7DF161, 'cmp', 'dword ptr [eax + 4], 3'),
        (0x7DF165, 'jl', '0x7df181'),
        (0x7DF175, 'add', 'edx, 0x70'),
        (0x7DF179, 'call', '0x5ff1ea'),
    ]
    for check in checks:
        anchor(*check)
    for ea, target in [(0x600C43, 0x7BAE60), (0x60700C, 0x7DE310),
                       (0x60469A, 0x7DF010), (0x5FF1EA, 0x923F60)]:
        assert bridges[ea] == target
    # 核初始版本读取和+104读取之间，没有检查fseek/fread返回值的条件跳转。
    header = [i for i in bodies[0x7DF010] if 0x7DF0C4 <= i.address < 0x7DF15E]
    assert [(i.address, i.mnemonic) for i in header if i.group(capstone.CS_GRP_JUMP)] == [(0x7DF128, 'jl')]
    assert not any(i.mnemonic in ('cmp', 'test') and i.address != 0x7DF124 for i in header)
    navigation = json.loads((HERE / 'roots_incoming.json').read_text('utf-8'))
    navigation_contexts = 0
    for row in navigation['incoming']:
        assert row['status'].startswith('调用者导航')
        for item in row['context']:
            ea, size = int(item['va'], 16), item['size']
            data = disk(ea, size)
            assert data == bytes.fromhex(item['hex'])
            ins = list(decoder.disasm(data, ea))
            assert len(ins) == 1 and ins[0].size == size
            navigation_contexts += 1
    prior_dir = HERE.parents[1]
    prior_roles = json.loads((prior_dir / '角色1416字段来源/证据/functions.json').read_text('utf-8'))
    prior_functions = {int(f['va'], 16): f for f in prior_roles['functions']}
    for ea in (0x7BAE60, 0x7DE310):
        assert prior_functions[ea]['byte_ranges'] == functions[ea]['byte_ranges']
    prior_sources = [('TeachMode状态与序号来源/证据/seed_raw.json', (0x63E210, 0x7284B0)),
                     ('文件访问与路径契约/证据/file_wrappers.json', (0x923F60,))]
    prior_ranges = 0
    for name, wanted in prior_sources:
        prior = json.loads((prior_dir / name).read_text('utf-8'))
        assert prior['disk_sha256'] == SHA
        for row in prior['functions']:
            if int(row['va'], 16) not in wanted:
                continue
            for block in row['byte_ranges']:
                ea, size = int(block['va'], 16), block['size']
                data = disk(ea, size)
                assert data == bytes.fromhex(block['idb_hex']) == bytes.fromhex(block['disk_hex'])
                ins = list(decoder.disasm(data, ea))
                assert sum(i.size for i in ins) == size
                decoded.update({i.address: i for i in ins})
                prior_ranges += 1
    for check in [(0x63E221, 'add', 'eax, 0x65c'),
                  (0x7284C1, 'mov', 'eax, dword ptr [eax + 0x68]'),
                  (0x923FAE, 'mov', 'dword ptr [ebp - 0x1c], eax'),
                  (0x923FCC, 'mov', 'eax, dword ptr [ebp - 0x1c]')]:
        anchor(*check)
    role_block = prior_functions[0x7F3C70]['byte_ranges'][0]
    role_start = int(role_block['va'], 16)
    role_idb = bytes.fromhex(role_block['idb_hex'])
    role_sites = []
    for ea in (0x7F3CAD, 0x7F3CC7, 0x7F3CCD, 0x7F3D74):
        ins = list(decoder.disasm(disk(ea, 15), ea, count=1))[0]
        assert ins.bytes == role_idb[ea - role_start:ea - role_start + ins.size]
        decoded[ea] = ins
        role_sites.append(dict(va=hex(ea), disk_hex=ins.bytes.hex()))
    for check in [(0x7F3CAD, 'mov', 'dword ptr [eax + 0x57c], ecx'),
                  (0x7F3CC7, 'mov', 'ecx, dword ptr [eax + 0x57c]'),
                  (0x7F3CCD, 'call', '0x6037ae'),
                  (0x7F3D74, 'call', '0x612a38')]:
        anchor(*check)
    samples_raw = json.loads((HERE / 'emp_header_samples.json').read_text('utf-8'))
    expected = {
        'Map/BS_1_1.emp': (27187, '841d2e09abb60b2ce344c816c3c13c8d48a1d63ca674a98ae440be5c0428c55c', 3, [3, 0, 0, 11]),
        'Map/TC_CM_1.emp': (28157, 'f6992e8bcaa10bdf1779ee716dd943732f238469d8895e3e9af7c76abf9b52e2', 3, [2, 0, 0, 0]),
        'Map/CM_CS_2.emp': (27540, '7e37eaa1569b90a84129cd9a6696990fc4ebab4911b99bdee2391b61df00a8b8', 1, [0, 16, 18, 0xD8B563C1]),
    }
    samples = []
    assert {s['path'] for s in samples_raw['samples']} == set(expected)
    for row in samples_raw['samples']:
        name = row['path']
        data = (ROOT / name).read_bytes()
        length, sha, version, values = expected[name]
        assert len(data) == row['length'] == length
        assert hashlib.sha256(data).hexdigest() == row['sha256'] == sha
        assert row['version_int32'] == struct.unpack_from('<i', data, 16)[0] == version
        assert row['version_offset'] == 16 and row['version_hex'] == data[16:20].hex()
        assert len(row['fields']) == 4
        for field, offset, member, minimum, value in zip(row['fields'],
                (23288, 23292, 23296, 23300), (24, 104, 108, 112), (None, 2, 2, 3), values):
            assert field['file_offset'] == offset and field['map_offset_if_gate_passes'] == member
            assert field['width'] == 4 and field['signed_version_minimum'] == minimum
            assert field['hex'] == data[offset:offset + 4].hex()
            assert field['uint32'] == struct.unpack_from('<I', data, offset)[0] == value
            assert field['read_by_proven_header_path'] == (minimum is None or version >= minimum)
        samples.append(dict(path=name, sha256=sha, length=length, signed_version=version,
                            observed_words=values, runtime_loading_verified=False))
    manifest = json.loads((HERE.parent / '函数审阅清单.json').read_text('utf-8'))
    expected_review = {
        0x629C90: ('完整语义已审阅', BOUNDS[0x629C90]),
        0x64F2A0: ('局部语义已审阅', [(0x64F2A0, 0x64F343)]),
        0x7DF010: ('局部语义已审阅', [(0x7DF010, 0x7DF181)]),
        0x7BAE60: ('局部语义已审阅', [(0x7BAF06, 0x7BAF14)]),
        0x7DE310: ('局部语义已审阅', [(0x7DE3BE, 0x7DE3DC)]),
    }
    assert len(manifest['functions']) == 5
    assert {int(row['va'], 16) for row in manifest['functions']} == set(expected_review)
    assert manifest['new_unique_va'] == 0 and manifest['existing_constructor_rechecks'] == 2
    for row in manifest['functions']:
        status, spans = expected_review[int(row['va'], 16)]
        assert row['status'] == status
        assert [(int(a, 16), int(b, 16)) for a, b in row['reviewed_ranges']] == spans
        assert all(row[k] for k in ('conclusion', 'unknown', 'evidence', 'reuse'))
    assert manifest['status_counts'] == dict(Counter(row['status'] for row in manifest['functions']))
    checked_texts = []
    for file in sorted(HERE.parent.glob('*.txt')):
        lines = file.read_text('utf-8').splitlines()
        assert all(not line.strip() or line.startswith('//') for line in lines), file.name
        assert all(line == line.rstrip() for line in lines), file.name
        checked_texts.append(file.name)
    for file in HERE.glob('*.py'):
        assert all(line == line.rstrip() for line in file.read_text('utf-8').splitlines()), file.name
    result = dict(status='PASS', disk_sha256=SHA,
                  capstone_version=capstone.__version__, functions_redecoded=len(functions),
                  instruction_count=sum(len(b) for b in bodies.values()), declared_ranges_rechecked=ranges // 2,
                  instruction_ranges_rechecked=ranges // 2, unique_e9_bridges=len(bridges),
                  semantic_anchors=anchors, navigation_contexts_redecoded=navigation_contexts,
                  prior_body_ranges_rechecked=prior_ranges, prior_role_sites=role_sites,
                  emp_samples_independently_rechecked=samples,
                  manifest_status_counts=manifest['status_counts'], new_unique_va=0,
                  text_format_checked=checked_texts,
                  scope='本地PE静态核验；EMP头读取目的与signed版本门；未实机加载、未审完整载荷或网络写入')
    (HERE / 'independent_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'semantic_anchors'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
