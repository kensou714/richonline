"""独立核建筑选择 ABI、完整块、旧依赖和作者终稿；不导入作者或采证器。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM
from capstone.x86_const import X86_REG_EBP

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '12d260f584924374b55572c24d3301f232d425bfca853a49a7b5a3d02a4228e1'
SLOTS_SHA = '020fa6e36a83a35e7f784e316b3f8eef9044541988f62de52797691eb8935227'
SEEDS = {0x712980, 0x71F130, 0x71F230, 0x7CEF00, 0x6A3A00}
AUTHOR_BINDINGS = {
    '00_有限采证实施计划.txt': 'a90932e19e753a18b8963283b016cece48dd5f904c4ae8473d5d6abe297bd585',
    '01_名称回调与输入区别.txt': '9a9468776fbf2b19e9b37c70acec12c8ef3d6f747900639a4859349ff30165ad',
    '02_选择提交与消息边界.txt': '8ee4a0fa48d9963a8da03a927577a34694c069a4310c3a55e94d130b725fa94f',
    '03_许可证门与记录身份.txt': '489911784749b01d6f75a712b662995e389afc91a10c2529facd512ea255cff4',
    '04_生产样本与回调指针.txt': 'c8bbabac4e99489a789d5c014030a11fd57b8c5a207099b184a0ff23c1829eb4',
    '05_原证与复核边界.txt': '6fbaff709a6129d158ac84d0425b6c526e2846a8ebce729db472fc5f9065c90c',
    '函数审阅清单.json': '0bd163045cf4689f0e892ba8407b659a723f9030003e6bf42a0f5319adea89c8',
    '证据/bounded_audit.json': '0e17b02f153c2df7e853052e54e0e60b67e4bae601c094cab65872cab335284d',
    '证据/bounded_raw.json': RAW_SHA,
    '证据/callback_slots/bounded_raw.json': SLOTS_SHA,
    '证据/export_bounded.py': 'f366660506768b08182a3c70ed35161b339f0afa939daf22365294c6bd6c5936',
    '证据/export_callback_slots.py': 'b116f1eec0d319a4a44375be4e68e181e370c26821f96f760fd876f5ee41522e',
    '证据/formal_functions.json': 'bf209a6be4121a32fbe3e274b2a2a78004c23790f47fdcea4fc0aaec29d00dfd',
    '证据/reused_audit.json': '7810b8f945e5385d8f3d216c8d846505e86cac2d11be59f8f0facd978db32e26',
    '证据/verify_bounded.py': '0c7e3a32bf463280ba2c893e4f92bb2801779843c9946e549b4172f57d0fb336',
    '验证结果.json': '0e17b02f153c2df7e853052e54e0e60b67e4bae601c094cab65872cab335284d',
}
REUSE_VAS = {0x628270, 0x628900, 0x629C90, 0x629E60, 0x7278E0, 0x8E15B0,
             0x8E2C10, 0x91F6D0, 0x8E1570, 0x694B30, 0x7F85C0, 0x71ED30}
LEGACY_VAS = {0x7BC3D0, 0x7D60E0, 0x63E440, 0x63F760}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pointer(node, location):
    for part in location.split('/')[1:]:
        part = part.replace('~1', '/').replace('~0', '~')
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def verify(preflight=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXE_SHA
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 4)[0] == 0x14C
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    saved, sites, bodies, sources, bridges = {}, {}, {}, {}, {}

    def disk(va, size):
        offsets = [off + va - base - rva for _, rva, length, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        off, = offsets
        data = image[off:off + size]
        assert len(data) == size
        return data

    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        data = disk(va, row['size'])
        assert data.hex() == row['disk_hex'] == row.get('idb_hex', row.get('ida_hex')), hex(va)
        assert row.get('matching', row.get('equal')) is True
        digest = hashlib.sha256(data).hexdigest()
        if 'sha256' in row:
            assert digest == row['sha256']
        saved[(va, len(data))] = digest
        return data

    def decode(row):
        va = int(row.get('start_va', row.get('va')), 16)
        data = audit(row)
        decoded = list(cs.disasm(data, va))
        cursor = va
        for instruction in decoded:
            assert instruction.address == cursor
            cursor += instruction.size
            sites[instruction.address] = instruction
        assert cursor == va + len(data)
        return decoded

    def recursive(node):
        if isinstance(node, dict):
            if ('disk_hex' in node and 'size' in node and ('va' in node or 'start_va' in node)
                    and ('idb_hex' in node or 'ida_hex' in node)):
                audit(node)
            for value in node.values():
                recursive(value)
        elif isinstance(node, list):
            for value in node:
                recursive(value)

    def source(ref, origin):
        path = (origin / ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        digest = ref.get('sha256', ref.get('source_sha256'))
        assert sha(path) == digest, str(path)
        sources[path.relative_to(DOCS).as_posix()] = digest
        return pointer(json.loads(path.read_bytes()), ref.get('pointer', ref.get('json_pointer', '')))

    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    slots = json.loads((HERE / 'callback_slots/bounded_raw.json').read_bytes())
    assert sha(HERE / 'bounded_raw.json') == RAW_SHA
    assert sha(HERE / 'callback_slots/bounded_raw.json') == SLOTS_SHA
    assert raw['disk_sha256'] == slots['disk_sha256'] == EXE_SHA
    assert sha(TOPIC.parent / '四类型辅助请求与队列/证据/export_preparation_core.py') == raw['exporter_sha256'] == slots['exporter_sha256']
    assert {int(f['seed_va'], 16) for f in raw['functions']} == SEEDS
    assert not raw['reused_seeds'] and not raw['data_windows']
    assert not slots['functions'] and not slots['calls'] and not slots['reused_seeds']
    for node in (raw, slots):
        recursive(node)
        for ref in node['reuse_sources']:
            source(ref, DOCS)
    current = {r['seed_va']: r['chunk_byte_ranges'] for r in raw['current_chunk_audits']}
    measurements = []
    for f in raw['functions']:
        va = int(f['seed_va'], 16)
        assert f['chunk_byte_ranges'] == current[hex(va)]
        decoded = [i for block in f['chunk_byte_ranges'] for i in decode(block)]
        assert [i.address for i in decoded] == [int(a['site_va'], 16) for a in f['assembly']]
        bodies[va] = decoded
        measurements.append(dict(va=hex(va), bytes=sum(c['size'] for c in f['chunk_byte_ranges']), instructions=len(decoded)))
    assert sum(r['bytes'] for r in measurements) == 464
    assert sum(r['instructions'] for r in measurements) == 153
    for row in raw['verified_direct_bridges'] + slots['verified_direct_bridges']:
        va = int(row['start_va'], 16)
        data = audit(row)
        target = int(row['target_va'], 16)
        assert len(data) == 5 and data[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        assert va not in bridges or bridges[va] == target
        bridges[va] = target
    for call in raw['calls']:
        instruction = sites[int(call['site_va'], 16)]
        assert instruction.mnemonic in ('call', 'jmp')
        assert instruction.operands[0].type == CS_OP_IMM
        target = instruction.operands[0].imm & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert target == int(bridge, 16)
            target = bridges[target]
        assert target == int(call['implementation_va'], 16)
    windows = raw['explicit_owner_windows'] + [r['owner_window'] for rows in raw['incoming'].values()
                                              for r in rows if 'owner_window' in r]
    window_heads, unique_windows, ownerless = 0, {}, []
    for w in windows:
        if w['owner_va'] is None:
            assert w['assembly'] == []
            ownerless.append(w['site_va'])
            continue
        addresses = []
        assert len(w['assembly']) <= 11
        for row in w['assembly']:
            instruction, = decode(row['bytes'])
            assert instruction.address == int(row['site_va'], 16)
            addresses.append(instruction.address)
            window_heads += 1
        assert addresses == sorted(set(addresses)) and int(w['site_va'], 16) in addresses
        key = (w['owner_va'], w['site_va'])
        assert key not in unique_windows or unique_windows[key] == w
        unique_windows[key] = w
    pointer_slots = []
    assert len(slots['data_windows']) == 3
    for row, (address, bridge, endpoint) in zip(slots['data_windows'], (
            (0xA24CF4, 0x60A71B, 0x712980), (0xA263B4, 0x60A96E, 0x71F130),
            (0xA263C8, 0x60CE17, 0x71F230))):
        assert int(row['start_va'], 16) == address and row['size'] == 4
        assert struct.unpack('<I', audit(row))[0] == bridge and bridges[bridge] == endpoint
        pointer_slots.append(dict(slot=hex(address), bridge=hex(bridge), endpoint=hex(endpoint)))
    semantic = []
    def anchor(va, mnemonic, operands):
        ins = sites[va]
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(va), ins.mnemonic, ins.op_str)
        semantic.append(dict(va=hex(va), mnemonic=mnemonic, operands=operands, disk_hex=ins.bytes.hex()))
    for check in (
        (0x7129A2, 'call', 'dword ptr [edx + 0x94]'), (0x7129B1, 'push', '0xa'),
        (0x7129C1, 'mov', 'ecx, dword ptr [ebp + 8]'),
        (0x7129C4, 'call', '0x6095c3'), (0x7129E1, 'call', 'dword ptr [edx + 0x90]'),
        (0x7129EE, 'mov', 'al, 1'), (0x7129FE, 'ret', '4'),
        (0x71F14F, 'push', '0'), (0x71F154, 'call', '0x60eacd'),
        (0x71F166, 'call', 'dword ptr [edx + 0x94]'), (0x71F175, 'push', '0x64'),
        (0x71F1A0, 'call', 'dword ptr [eax + 0x90]'), (0x71F1AD, 'mov', 'al, 1'),
        (0x71F1BD, 'ret', '4'), (0x71F24D, 'call', '0x60eacd'),
        (0x71F25F, 'call', 'dword ptr [edx + 0x98]'), (0x71F277, 'call', '0x6128cb'),
        (0x71F27C, 'mov', 'al, 1'), (0x71F28C, 'ret', '8'),
        (0x7CEF0E, 'call', '0x610db9'), (0x7CEF13, 'mov', 'ecx, eax'),
        (0x7CEF15, 'call', '0x60cc8c'), (0x7CEF27, 'ret', ''),
        (0x6A3A16, 'mov', 'eax, dword ptr [eax + 4]'),
        (0x6A3A19, 'mov', 'ecx, dword ptr [eax + 0x20]'),
        (0x6A3A1C, 'and', 'ecx, 0x1000'), (0x6A3A22, 'je', '0x6a3a28'),
        (0x6A3A24, 'xor', 'al, al'), (0x6A3A28, 'mov', 'al, 1'),
        (0x7BC407, 'mov', 'al, byte ptr [ebp + 8]'),
        (0x7BC40A, 'mov', 'byte ptr [ebp - 0xc], al'), (0x7BC42C, 'push', '6'),
    ):
        anchor(*check)
    result = dict(schema='richonline-independent-building-selection-27-1', result='PRECHECK_ONLY',
                  disk_sha256=EXE_SHA, raw_sha256=RAW_SHA, slots_sha256=SLOTS_SHA,
                  functions=measurements, byte_ranges=len(saved), bridges=len(bridges),
                  call_records=len(raw['calls']), owner_window_heads=window_heads,
                  ownerless_windows=ownerless,
                  unique_windows=len(unique_windows), code_pointer_slots=pointer_slots,
                  sources=sources, semantic_anchors=semantic)
    if preflight:
        print(json.dumps({k: v for k, v in result.items() if k not in ('sources', 'semantic_anchors')}, ensure_ascii=False, indent=2))
        return result

    for rel, digest in AUTHOR_BINDINGS.items():
        assert sha(TOPIC / rel) == digest, rel
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    manifest = json.loads((TOPIC / '函数审阅清单.json').read_bytes())
    adapted = json.loads((HERE / 'reused_audit.json').read_bytes())
    author = json.loads((TOPIC / '验证结果.json').read_bytes())
    assert author == json.loads((HERE / 'bounded_audit.json').read_bytes())
    assert author['status'] == 'PASS' and author['subject_bytes'] == 464
    assert author['dependency_functions'] == 12 and author['legacy_range_records'] == 4
    assert formal['disk_sha256'] == manifest['disk_sha256'] == adapted['disk_sha256'] == EXE_SHA
    assert formal['source_sha256'] == RAW_SHA
    assert len(formal['functions']) == len(manifest['functions']) == 5
    assert {int(f['va'], 16) for f in formal['functions']} == SEEDS
    assert len(formal['thunks']) == 15
    assert formal['thunks'] == [dict(r, va=r['start_va'], target=r['target_va'])
                                for r in raw['verified_direct_bridges']]
    for index, (original, converted, reviewed) in enumerate(
            zip(raw['functions'], formal['functions'], manifest['functions'])):
        va = int(original['seed_va'], 16)
        assert int(converted['va'], 16) == int(reviewed['va'], 16) == va
        assert converted['source_sha256'] == RAW_SHA and converted['json_pointer'] == f'/functions/{index}'
        assert converted['pseudocode'] == original['pseudocode']
        assert converted['assembly'] == [dict(r, va=r['site_va']) for r in original['assembly']]
        assert converted['byte_ranges'] == [dict(r, va=r['start_va']) for r in original['chunk_byte_ranges']]
        assert reviewed['status'] == '静态契约已审阅'
        assert reviewed['source_records'] == [dict(path='证据/bounded_raw.json', sha256=RAW_SHA,
                                                  json_pointer=f'/functions/{index}')]
        assert reviewed['original_byte_ranges'] == original['chunk_byte_ranges']
        assert [int(r['va'], 16) for r in reviewed['assembly_anchors']] == [i.address for i in bodies[va]]
        assert [r['hex'] for r in reviewed['assembly_anchors']] == [i.bytes.hex() for i in bodies[va]]
        assert [r['text'] for r in reviewed['assembly_anchors']] == [i.mnemonic + ' ' + i.op_str for i in bodies[va]]
        assert [(r['start_va'], r['end_va']) for r in reviewed['declared_chunks']] == [
            (r['start_va'], hex(int(r['start_va'], 16) + r['size'])) for r in original['chunk_byte_ranges']]

    assert len(adapted['references']) == 12 and len(adapted['legacy_ranges']) == 4
    assert {int(x['owner_va'], 16) for x in adapted['references']} == REUSE_VAS
    assert {int(x['owner_va'], 16) for x in adapted['legacy_ranges']} == LEGACY_VAS
    reuse_instruction_sites = {}
    for entry in adapted['references']:
        original = source(dict(path=entry['source'], sha256=entry['source_sha256'],
                               pointer=entry['json_pointer']), DOCS)
        va = int(entry['owner_va'], 16)
        assert int(original.get('seed_va', original.get('va')), 16) == va
        ranges = original['chunks'] if 'instructions' in original else original.get(
            'chunk_byte_ranges', original['byte_ranges'] if 'byte_ranges' in original else None)
        assert ranges is not None
        instructions = [ins for row in ranges for ins in decode(row)]
        declared = original.get('declared_chunks', original.get('chunks') if 'instructions' not in original else None)
        if declared is not None:
            assert {(r['start_va'], r['end_va']) for r in declared} == {
                (r.get('start_va', r.get('va')), hex(int(r.get('start_va', r.get('va')), 16) + r['size']))
                for r in ranges}
        assert [r['sha256'] for r in entry.get('observed_ranges', entry.get('chunks', []))] == [
            hashlib.sha256(disk(int(row.get('start_va', row.get('va')), 16), row['size'])).hexdigest()
            for row in ranges]
        assert [(r['va'], r['hex']) for r in entry['instructions']] == [
            (hex(ins.address), ins.bytes.hex()) for ins in instructions]
        reuse_instruction_sites[va] = {ins.address: ins for ins in instructions}
        if 'instructions' in original:
            assert [r['va'] for r in original['instructions']] == [hex(ins.address) for ins in instructions]
        else:
            assert [r.get('va', r.get('site_va')) for r in original['assembly']] == [hex(ins.address) for ins in instructions]

    legacy_sites = {}
    for entry in adapted['legacy_ranges']:
        original = source(dict(path=entry['source'], sha256=entry['source_sha256'],
                               pointer=entry['json_pointer']), DOCS)
        va = int(entry['owner_va'], 16)
        assert original == entry['original_record'] and int(original['address'], 16) == va
        data = disk(va, int(original['end'], 16) - va)
        assert data.hex() == original['bytes']
        assert entry['observed_range']['sha256'] == hashlib.sha256(data).hexdigest()
        instructions = list(cs.disasm(data, va))
        assert sum(ins.size for ins in instructions) == len(data)
        assert [r[0] for r in original['assembly']] == [hex(ins.address) for ins in instructions]
        assert [(r['va'], r['hex']) for r in entry['current_pe_instructions']] == [
            (hex(ins.address), ins.bytes.hex()) for ins in instructions]
        legacy_sites[va] = {ins.address: ins for ins in instructions}

    def old(va, mnemonic, operands):
        ins = next(table[va] for table in (*reuse_instruction_sites.values(), *legacy_sites.values()) if va in table)
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), hex(va)
        semantic.append(dict(va=hex(va), mnemonic=mnemonic, operands=operands, disk_hex=ins.bytes.hex()))

    for check in (
        (0x7278F1, 'mov', 'eax, dword ptr [eax + 4]'),
        (0x8E1583, 'jge', '0x8e1595'), (0x8E1585, 'mov', 'eax, dword ptr [ecx + 0x1a4]'),
        (0x8E158F, 'mov', 'eax, dword ptr [eax + edx*4]'), (0x8E1595, 'xor', 'eax, eax'),
        (0x8E15C3, 'jge', '0x8e15db'), (0x8E15D3, 'mov', 'dword ptr [eax + edx*4], ecx'),
        (0x694B41, 'imul', 'eax, eax, 0x184'),
        (0x629E71, 'mov', 'eax, dword ptr [eax + 0x5e0]'),
        (0x629E77, 'imul', 'eax, eax, 0x7c'),
        (0x7F8625, 'call', '0x611c05'), (0x7F862A, 'movzx', 'edx, al'),
        (0x7F862F, 'je', '0x7f868b'),
        (0x71EF2D, 'push', 'eax'), (0x71EF41, 'call', '0x607c32'),
        (0x7D60F1, 'mov', 'word ptr [eax], 0x37'),
        (0x63E451, 'mov', 'eax, dword ptr [eax + 4]'),
        (0x63F774, 'mov', 'eax, dword ptr [eax + 8]'),
        (0x63F777, 'sub', 'eax, dword ptr [ecx + 0xe28]'),
        (0x7BC403, 'mov', 'word ptr [ebp - 0xe], ax'),
        (0x7BC407, 'mov', 'al, byte ptr [ebp + 8]'),
        (0x7BC40A, 'mov', 'byte ptr [ebp - 0xc], al'),
        (0x7BC410, 'call', '0x609320'), (0x7BC415, 'movzx', 'ecx, al'),
        (0x7BC41A, 'jne', '0x7bc41e'), (0x7BC41C, 'jmp', '0x7bc43a'),
        (0x7BC41E, 'push', '0x29'), (0x7BC42C, 'push', '6'),
        (0x7BC432, 'call', '0x610977'),
    ):
        old(*check)

    assert len(adapted['callback_slots']) == 3
    for entry, slot in zip(adapted['callback_slots'], pointer_slots):
        assert int(entry['address'], 16) == int(slot['slot'], 16)
        assert int(entry['bridge'], 16) == int(slot['bridge'], 16)
        assert entry['source_sha256'] == SLOTS_SHA
    assert len(manifest['windows']) == len(unique_windows) == 7
    assert {(w['owner_va'], w['site']) for w in manifest['windows']} == set(unique_windows)
    assert len(ownerless) == 1 and ownerless[0] == '0x7f8f27'
    assert all(not line.strip() or line.startswith('//') for path in TOPIC.glob('*.txt')
               for line in path.read_text(encoding='utf-8').splitlines())
    assert not any(op.type == CS_OP_MEM and op.mem.base == X86_REG_EBP and op.mem.disp == 12
                   for ins in bodies[0x71F230] for op in ins.operands)
    assert bridges[0x611C05] == 0x7CEF00
    navigation = []
    for va, target in ((0x610977, 0x6BF380), (0x609320, 0x63F760), (0x60C08E, 0x7D60E0),
                       (0x601125, 0x63E440), (0x60837B, 0x6279C0), (0x610076, 0x6E4020),
                       (0x607C32, 0x8E15B0)):
        data = disk(va, 5)
        assert data[0] == 0xE9 and va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        navigation.append(dict(va=hex(va), target=hex(target), disk_hex=data.hex(),
                               boundary='独审离线PE导航；不新增IDA桥或函数覆盖'))
    # 只解释已核字节的有限位门；内存解引用由合成flags输入替代，不运行客户端。
    cases = []
    for pointer_value in (0, 0x12345678, 0xFFFFFFFF):
        for flags in (0, 1, 0xFFF, 0x1000, 0x1001, 0xFFFFEFFF, 0xFFFFFFFF):
            eax, ecx, zero, pc = pointer_value, 0, False, 0x6A3A19
            for _ in range(7):
                if pc == 0x6A3A2A:
                    break
                ins = sites[pc]
                next_pc = pc + ins.size
                if ins.mnemonic == 'mov' and ins.op_str == 'ecx, dword ptr [eax + 0x20]':
                    ecx = flags
                elif ins.mnemonic == 'and' and ins.op_str == 'ecx, 0x1000':
                    ecx &= ins.operands[1].imm
                    zero = ecx == 0
                elif ins.mnemonic == 'je':
                    if zero:
                        next_pc = ins.operands[0].imm
                elif ins.mnemonic == 'jmp':
                    next_pc = ins.operands[0].imm
                elif ins.mnemonic == 'xor' and ins.op_str == 'al, al':
                    eax &= 0xFFFFFF00
                elif ins.mnemonic == 'mov' and ins.op_str == 'al, 1':
                    eax = (eax & 0xFFFFFF00) | 1
                else:
                    raise AssertionError((hex(pc), ins.mnemonic, ins.op_str))
                pc = next_pc
            assert pc == 0x6A3A2A
            expected = (pointer_value & 0xFFFFFF00) | int(flags & 0x1000 == 0)
            assert eax == expected
            cases.append(dict(pointer=hex(pointer_value), flags=hex(flags), eax=hex(eax), al=eax & 255))
    assert len(cases) == 21
    result.update(result='PASS', author_bindings=AUTHOR_BINDINGS, reused_functions=len(REUSE_VAS),
                  offline_navigation=navigation,
                  byte_ranges=len(saved), limited_instruction_model=cases,
                  script_sha256=sha(Path(__file__)),
                  reused_bytes=sum(r['size'] for x in adapted['references']
                                   for r in x.get('observed_ranges', x.get('chunks', []))),
                  legacy_functions=len(LEGACY_VAS),
                  legacy_bytes=sum(x['observed_range']['size'] for x in adapted['legacy_ranges']),
                  reviewed_manifest_functions=len(manifest['functions']),
                  reviewed_manifest_windows=len(manifest['windows']),
                  boundary='静态字节及局部契约；动态虚表身份、回调注册、真实发送、服务端接受仍未证明')
    output = HERE / 'independent_final_audit.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    report = TOPIC / '独立审阅结论.txt'
    lines = [
        '// ============================================================================',
        '// 建筑选择界面与许可证门 / 第27批独立审阅结论',
        '// ============================================================================',
        '// 判定：PASS；仅认可当前 PE 下的限定静态契约，不等同实机流程验收。',
        f'// 当前 PE SHA256：{EXE_SHA}。',
        f'// 主原证 SHA256：{RAW_SHA}；回调槽原证 SHA256：{SLOTS_SHA}。',
        '// 五完整主体共464字节、153指令；15个E9桥、24个直接调用记录、三个4字节代码指针槽均逐项复核。',
        '// 12个旧依赖与四段历史单范围逐字节核当前PE；旧范围不补造IDA声明块或新完整覆盖。',
        '// 九个原始owner窗口记录去重为七个有限窗口；7F8F27无owner块，只保留未归属。',
        '// 名称两回调使用不同取值路径：S+4与参数槽0；均借用Build首字段name，未证明虚表+90复制。',
        '// 提交回调先读完整DWORD并无错误门，旧7BC3D0只截取低BYTE；回调尾部只写AL=1。',
        '// 7BC3D0六字节栈缓冲的最后一字节保留CCCCCCCC初始化结果；不定义为协议字段。',
        '// 旧发送门63F760为G+8与G+E28比较；门假不调用6BF380，回调仍可返回AL=1。',
        '// 6A3A00读取Q当前124字节记录+4指向对象的+20位1000h；仅改AL，高24位保留D指针。',
        '// 21组合成指针/flags通过实际指令有限解释器复核AL与高24位；它不是客户端动态执行。',
        '// 7CEF00正常路径转发该AL；7F85C0仅以movzx读取AL，不能把自动void命名当返回契约。',
        '// A24CF4/A263B4/A263C8只证实静态代码指针，不证明回调事件号、注册和实际控件实例。',
        '// Build根、Q根、P候选列表三套结构不得合并；许可证只读门并非消耗或服务端授权。',
        '// 未证：动态vtable目标、输入控件与生产样本同一实例、真实抓包、服务器接受、并发安全。',
        '// 原IDB输入指纹与当前PE不同；只认可本审计逐项匹配的字节范围，不宣称全IDB同版。',
        '// 来源：证据/independent_final_audit.json记录全部锚、源SHA和作者终稿SHA。',
        '// 独审脚本：证据/verify_independent.py；本文件和JSON由脚本生成。',
    ]
    lines.extend(f'// 作者终稿 SHA256 {rel}：{digest}。' for rel, digest in AUTHOR_BINDINGS.items())
    report.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('result', 'functions', 'byte_ranges', 'bridges',
                                            'reused_functions', 'legacy_functions', 'unique_windows')},
                     ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--preflight', action='store_true')
    verify(parser.parse_args().preflight)
