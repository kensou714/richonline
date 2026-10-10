"""独立固定语义锚点、复用来源与块外 switch 数据表核验。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True

    def disk(va, size):
        mappings = [(rva, offset) for _, rva, length, offset in sections
                    if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(mappings) == 1
        rva, offset = mappings[0]
        result = image[offset + va - base - rva:offset + va - base - rva + size]
        assert len(result) == size
        return result

    def instruction(va):
        return next(cs.disasm(disk(va, 15), va))

    anchors = {
        0x70A09C: ('push', '0x80'), 0x70A0A1: ('push', '0'),
        0x70A0A6: ('add', 'ecx, 0x5d'),
        0x70A0C4: ('cmp', 'dword ptr [ebp - 0x20], 4'),
        0x70A0D0: ('mov', 'dword ptr [ecx + eax*4 + 0x4c], 0'),
        0x70A227: ('mov', 'eax, dword ptr [0xa8748c]'),
        0x70A22C: ('cdq', ''), 0x70A22D: ('sub', 'eax, edx'),
        0x70A22F: ('sar', 'eax, 1'), 0x70A234: ('mov', 'dword ptr [ecx + 0x58], eax'),
        0x70A2DF: ('mov', 'dword ptr [ecx + 0x54], edx'),
        0x70A3D3: ('mov', 'dword ptr [eax + 0x50], ecx'),
        0x70A3DE: ('mov', 'dword ptr [edx + 0x54], eax'),
        0x70A3FE: ('mov', 'byte ptr [ecx + 0x5c], 0'),
        0x70A89B: ('mov', 'byte ptr [ecx + 0x48], al'),
        0x70A8F2: ('mov', 'dl, byte ptr [ecx + 0x48]'),
        0x70A8F5: ('push', 'edx'),
        0x70AA14: ('je', '0x70aa9b'),
        0x70ADE5: ('sar', 'eax, 1'),
        0x70AF6F: ('mov', 'word ptr [ebp - 0x1e], ax'),
        0x70AF76: ('sub', 'eax, 0x14'), 0x70AF79: ('mov', 'byte ptr [ebp - 0x1c], al'),
        0x70AF7C: ('push', '6'),
        0x70B056: ('mov', 'eax, 0xcccccccc'),
        0x70B05E: ('mov', 'dword ptr [ebp - 0x10], eax'),
        0x70B061: ('mov', 'dword ptr [ebp - 0xc], eax'),
        0x70B088: ('mov', 'word ptr [ebp - 0xe], ax'),
        0x70B08F: ('mov', 'byte ptr [ebp - 0xc], al'),
        0x70B092: ('push', '6'), 0x727CD1: ('mov', 'word ptr [eax], 0x14'),
        0x727861: ('mov', 'ecx, dword ptr [eax + 8]'),
        0x727867: ('mov', 'eax, dword ptr [edx + ecx*4 + 0x600]'),
        0x727870: ('cmp', 'eax, dword ptr [ebp + 8]'), 0x727873: ('setge', 'cl'),
        0x63E451: ('mov', 'eax, dword ptr [eax + 4]'),
        0x63E5A1: ('add', 'eax, 0xc44'),
        0x7B9DD0: ('mov', 'dword ptr [ecx*4 + 0xa87480], eax'),
    }
    for va, pair in anchors.items():
        item = instruction(va)
        assert (item.mnemonic, item.op_str) == pair, (hex(va), item.mnemonic, item.op_str, pair)

    # 表地址来自指令操作数，表数据直接读当前 PE；不依赖 IDA 的 case 注释。
    index_insn, jump_insn = instruction(0x70ABF6), instruction(0x70ABFD)
    assert index_insn.operands[1].type == jump_insn.operands[0].type == CS_OP_MEM
    index_va, jump_va = index_insn.operands[1].mem.disp, jump_insn.operands[0].mem.disp
    assert (index_va, jump_va) == (0x70B033, 0x70B017)
    indices = disk(index_va, 26)
    jump_bytes = disk(jump_va, 4 * (max(indices) + 1))
    jumps = struct.unpack('<' + 'I' * (max(indices) + 1), jump_bytes)
    cases = {i + 1: jumps[index] for i, index in enumerate(indices)}
    assert cases == {i: {1: 0x70AC2A, 2: 0x70AC9E, 3: 0x70AD12, 4: 0x70AD86,
                         10: 0x70AC04}.get(i, 0x70AF41 if 21 <= i <= 26 else 0x70AFD8)
                     for i in range(1, 27)}

    payload = (HERE / 'reused_raw.json').read_bytes()
    reused = json.loads(payload)
    results, source_hashes, current_bridges = [], {}, {}
    for row in reused['records']:
        source = row['source']
        path = (HERE / source['path']).resolve()
        assert path.is_relative_to((ROOT / 'docs/逆向资料').resolve())
        original_bytes = path.read_bytes()
        assert hashlib.sha256(original_bytes).hexdigest() == source['sha256']
        value = json.loads(original_bytes)
        for token in source['pointer'].split('/')[1:]:
            token = token.replace('~1', '/').replace('~0', '~')
            value = value[int(token)] if isinstance(value, list) else value[token]
        assert value == row['original_record'] and value['va'] == row['va']
        source_hashes[source['path']] = source['sha256']
        ranges = value.get('chunk_byte_ranges', value.get('byte_ranges', value.get('chunks', [])))
        assembly = value.get('assembly', value.get('instructions', []))
        heads, byte_count = [], 0
        for block in ranges:
            va = int(block['va'], 16)
            current = disk(va, block['size'])
            assert current.hex() == block['idb_hex'] == block['disk_hex']
            cursor = va
            for item in cs.disasm(current, va):
                assert item.address == cursor
                heads.append(cursor)
                cursor += item.size
            assert cursor == va + len(current)
            byte_count += len(current)
        if ranges:
            assert heads == [int(r['va'], 16) for r in assembly]
        else:
            assert row['va'] == '0x7b9ca0'
            # 历史 assembly 无逐指令 bytes：只验证所列头能在当前 PE 解码，
            # 保存当前字节，绝不把它伪装为旧快照字节一致或完整声明块。
            heads = [int(r['ea'], 16) for r in assembly]
            assert len(heads) == len(set(heads))
            decoded = [instruction(va) for va in heads]
            byte_count = sum(item.size for item in decoded)
        for call in value.get('calls', value.get('outgoing', [])):
            item = instruction(int(call['site'], 16))
            assert item.mnemonic in ('call', 'jmp') and item.operands[0].type == CS_OP_IMM
            target = item.operands[0].imm & 0xFFFFFFFF
            assert target == int(call['target'], 16)
            for bridge in call.get('thunks', call.get('chain', [])):
                va = int(bridge, 16)
                assert target == va
                bridge_bytes = disk(va, 5)
                assert bridge_bytes[0] == 0xE9
                target = va + 5 + struct.unpack_from('<i', bridge_bytes, 1)[0]
                current_bridges[hex(va)] = dict(target_va=hex(target), disk_hex=bridge_bytes.hex())
            assert target == int(call['implementation'], 16)
        results.append(dict(va=row['va'], source=source, bytes=byte_count, heads=len(heads),
                            scope='旧原始字节范围核验' if ranges else '旧汇编地址当前PE解码；无旧原始字节对照'))

    result = dict(schema='richonline-independent-goldcharge-semantics-1', status='PASS',
                  disk_sha256=EXPECTED, reused_raw_sha256=hashlib.sha256(payload).hexdigest(),
                  source_sha256=source_hashes, reused=results, reused_call_bridges_current_pe=current_bridges,
                  semantic_anchors=[dict(va=hex(va), mnemonic=p[0], operands=p[1]) for va, p in anchors.items()],
                  switch_data=[dict(va=hex(index_va), size=len(indices), disk_hex=indices.hex()),
                               dict(va=hex(jump_va), size=len(jump_bytes), disk_hex=jump_bytes.hex())],
                  switch_cases={str(k): hex(v) for k, v in cases.items()},
                  boundary='switch表为离线PE数据复核，不计函数；旧证据复用不计新增完成')
    (HERE / 'independent_semantics_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status='PASS', anchors=len(anchors), reused=len(results), switch_cases=len(cases))


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
