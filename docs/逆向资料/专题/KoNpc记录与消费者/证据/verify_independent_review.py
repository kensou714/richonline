"""独立从磁盘反汇编核验 KoNpc 关键契约；仅输出本独审证据。"""
from pathlib import Path
import hashlib
import json
import struct

import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
import lzokay


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA
    header = struct.unpack_from('<I', image, 0x3c)[0]
    assert image[:2] == b'MZ' and image[header:header + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, header + 52)[0]
    table = header + 24 + struct.unpack_from('<H', image, header + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, header + 6)[0])]

    def disk(ea, size):
        matches = [(rva, raw) for _, rva, count, raw in sections
                   if base + rva <= ea and ea + size <= base + rva + count]
        assert len(matches) == 1, hex(ea)
        rva, raw = matches[0]
        start = raw + ea - base - rva
        return image[start:start + size]

    names = ['reused_functions_raw.json', 'reused_accessors_raw.json',
             'npc_methods_raw.json', 'npc_consumers_raw.json',
             'npc_dependencies_raw.json', 'npc_supplement_raw.json']
    functions, ranges, bridges, records = {}, 0, 0, 0
    evidence = []
    for name in names:
        data = (HERE / name).read_bytes()
        raw = json.loads(data)
        evidence.append({'file': name, 'sha256': hashlib.sha256(data).hexdigest()})
        assert raw['disk_sha256'] == digest
        for function in raw['functions']:
            records += 1
            functions[function['va']] = function
            for block in function['byte_ranges'] + function['chunk_byte_ranges']:
                actual = disk(int(block['va'], 16), block['size'])
                assert actual.hex() == block['disk_hex'] == block['idb_hex']
                ranges += 1
        for bridge in raw['thunks']:
            ea = int(bridge['va'], 16)
            actual = disk(ea, 5)
            assert actual[0] == 0xe9
            assert actual.hex() == bridge['disk_hex'] == bridge['idb_hex']
            assert ea + 5 + struct.unpack_from('<i', actual, 1)[0] == int(bridge['target'], 16)
            bridges += 1
    links = json.loads((HERE / 'npc_supplement_links.json').read_text('utf-8'))
    for link in links:
        ea = int(link['bridge'], 16)
        actual = disk(ea, 5)
        assert actual.hex() == link['bridge_hex'] and actual[0] == 0xe9
        assert ea + 5 + struct.unpack_from('<i', actual, 1)[0] == int(link['target'], 16)

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    reviewed = {}

    def decode(va):
        function = functions[hex(va)]
        start, end = va, int(function['end_va'], 16)
        instructions = list(decoder.disasm(disk(start, end - start), start))
        assert sum(i.size for i in instructions) == end - start, hex(va)
        reviewed[hex(va)] = [{'va': hex(i.address), 'hex': i.bytes.hex(),
                              'instruction': i.mnemonic + ' ' + i.op_str}
                             for i in instructions]
        return instructions

    def store_offsets(instructions):
        return [i.operands[0].mem.disp for i in instructions
                if i.mnemonic == 'mov' and i.operands and i.operands[0].type == X86_OP_MEM
                and i.reg_name(i.operands[0].mem.base) in ('eax', 'ecx', 'edx')]

    ctor = decode(0x808a50)
    expected = {0, 4, 0x22a, 0x229, 0x228, 0x21d, 0x21c, 0x21f, 0x21e,
                0x22c, 0x224, 0x210, 0x214, 0x218, 0x230, 0xc, 0x8c,
                0x110, 0x190, 0x10c, 0x234, 0x220}
    assert set(store_offsets(ctor)) == expected
    assert 8 not in store_offsets(ctor)
    for i in ctor:
        if i.mnemonic == 'mov' and i.operands[0].type == X86_OP_MEM:
            dest = i.operands[0]
            if dest.mem.disp in (0xc, 0x8c, 0x110, 0x190):
                assert dest.size == 1 and i.operands[1].imm == 0

    loader = decode(0x806a30)
    indexed_displacements = {o.mem.disp - 0x2e0 for i in loader for o in i.operands
                             if o.type == X86_OP_MEM and o.mem.index != 0 and o.mem.disp >= 0x2e0}
    assert {0, 4, 8, 0xc, 0x8c, 0x10c, 0x110, 0x190, 0x210, 0x214, 0x218,
            0x21c, 0x21d, 0x21e, 0x21f, 0x220, 0x224, 0x228, 0x229, 0x22a,
            0x22c, 0x230, 0x234} <= indexed_displacements

    copied = decode(0x7f4550)
    assert {0x28, 0x2c, 0x17c, 0xac, 0x5e0} <= set(store_offsets(copied))
    calls = {i.operands[0].imm for i in copied
             if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM}
    assert 0x61040e in calls
    pointer = disk(0x61040e, 5)
    assert pointer[0] == 0xe9
    assert 0x610413 + struct.unpack_from('<i', pointer, 1)[0] == 0x9204c0

    overwrite_cash, overwrite_dice = decode(0x63f680), decode(0x727bd0)
    assert store_offsets(overwrite_cash) == [0x5e0]
    assert store_offsets(overwrite_dice) == [0x5b1]
    dice_write = next(i for i in overwrite_dice if i.address == 0x727be4)
    assert dice_write.operands[0].size == 1
    apply_fields = decode(0x7c08d0)
    calls = {i.operands[0].imm for i in apply_fields
             if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM}
    assert {0x60c3b3, 0x611d8b} <= calls
    for bridge, target in [(0x60c3b3, 0x63f680), (0x611d8b, 0x727bd0),
                           (0x60d38a, 0x7fa050), (0x6057bb, 0x7f83f0)]:
        raw = disk(bridge, 5)
        assert raw[0] == 0xe9
        assert bridge + 5 + struct.unpack_from('<i', raw, 1)[0] == target

    distance = decode(0x807950)
    assert any(i.address == 0x807a77 and i.mnemonic == 'jge' for i in distance)
    assert any(i.address == 0x807a85 and i.op_str == 'eax, dword ptr [ecx + edx*4]' for i in distance)
    add, subtract = decode(0x7fa050), decode(0x7f83f0)
    assert 0x5e0 in store_offsets(add)
    assert {0x5e0, 0x5e4} <= set(store_offsets(subtract))
    for va in [0x8054e0, 0x8073c0, 0x807440, 0x8074f0, 0x807750, 0x7e1600]:
        decode(va)

    # 反编译漏显文本指针赋值时，以磁盘指令确认该局部事件描述的来源。
    speak = list(decoder.disasm(disk(0x7c12ad, 0x7c12d5 - 0x7c12ad), 0x7c12ad))
    by_address = {i.address: i for i in speak}
    assert by_address[0x7c12b0].mnemonic == 'add'
    assert by_address[0x7c12b0].operands[1].imm == 0x8c
    assert by_address[0x7c12b6].mnemonic == 'mov'
    assert by_address[0x7c12b6].operands[0].mem.disp == -0x7c
    assert by_address[0x7c12d0].mnemonic == 'call'
    assert by_address[0x7c12d0].operands[0].imm == 0x609d34
    local_speak_instructions = [{'va': hex(i.address), 'hex': i.bytes.hex(),
                                 'instruction': i.mnemonic + ' ' + i.op_str} for i in speak]

    blob = (ROOT / 'Data/KoNpc.kpd').read_bytes()
    key = blob[0]
    decoded_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in blob[1:9]))
    assert packed_size == len(blob) - 9
    decoded = lzokay.decompress(bytes((b - key) & 255 for b in blob[9:]), decoded_size)
    assert hashlib.sha256(blob).hexdigest() == 'a47c088d06fa2e42c5af400fb86ee2fbd16a1eae33cf399bc0a63d0487810640'
    assert hashlib.sha256(decoded).hexdigest() == '8911db2e8954f66092ad473e8be2daca1724faa2ba0f656ccf1be592fb37e998'
    resources = json.loads((HERE / 'npc_resources.json').read_text('utf-8'))
    assert resources['decoded_hex'] == decoded.hex()
    assert len(resources['records']) == 8
    for resource in resources['records']:
        assert set(k for k in resource['fields'] if k.startswith('effect')) == {
            'effect' + str(i) for i in range(int(resource['fields']['tile']))}
        for key in ['name', 'speak']:
            assert resource['fields'][key].encode('latin1').hex() == resource['field_hex'][key]

    output = dict(status='PASS', disk_sha256=digest, capstone_version=capstone.__version__,
                  scope='磁盘PE独立反汇编与原证逐字节比较；资源独立解包；未运行游戏',
                  function_records=records, unique_functions=len(functions), byte_ranges=ranges,
                  bridges=bridges, supplement_links=len(links),
                  checked_ranges_and_bridges=ranges + bridges + len(links),
                  independently_decoded_functions=len(reviewed),
                  loader_record_offsets=sorted(indexed_displacements), constructor_offsets=sorted(expected),
                  resources=8, evidence=evidence, disk_instructions=reviewed,
                  speak_event_local_instructions=local_speak_instructions)
    (HERE / 'independent_review_validation.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in output.items()
                      if k not in ('evidence', 'disk_instructions', 'speak_event_local_instructions')},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
