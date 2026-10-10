"""文本光标独审：只读当前PE及已落盘证据，不访问IDA。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import capstone

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs/逆向资料'
HERE = Path(__file__).resolve().parent
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
NEW = {0x8FC6A0, 0x8FC830, 0x8FCCD0}
REUSED = {0x90CE80, 0x90D120, 0x90D310, 0x8FAE70}


def audit(final=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(va, size):
        matches = [(rva, off) for _, rva, count, off in sections
                   if rva <= va - base and va - base + size <= rva + count]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        payload = image[off + va - base - rva:off + va - base - rva + size]
        assert len(payload) == size
        return payload

    def resolve(va):
        payload = read(va, 5)
        assert payload[0] == 0xE9
        return va + 5 + struct.unpack_from('<i', payload, 1)[0]

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    transcript = ['// 当前PE独立重解码；旧范围重核与语义完成分开；调用窗不登记owner完成。']
    checked = 0

    def walk(node):
        nonlocal checked
        if isinstance(node, dict):
            payload_hex = node.get('idb_hex', node.get('ida_hex'))
            if payload_hex is not None and node.get('disk_hex') is not None:
                va = int(node.get('start_va', node.get('va')), 16)
                payload = bytes.fromhex(payload_hex)
                assert len(payload) == node['size']
                assert payload == bytes.fromhex(node['disk_hex']) == read(va, len(payload))
                assert node.get('matching', node.get('equal')) is True
                if node.get('sha256'):
                    assert hashlib.sha256(payload).hexdigest() == node['sha256']
                checked += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    def decode(payload, va, label):
        instructions = list(decoder.disasm(payload, va))
        assert sum(i.size for i in instructions) == len(payload)
        transcript.append('// ' + label)
        transcript.extend('// %08X %s %s %s' % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
                          for i in instructions)
        return instructions

    raw_path = HERE / 'bounded_raw.json'
    raw = json.loads(raw_path.read_text(encoding='utf-8'))
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['disk_sha256'] == EXPECTED
    assert {int(s['seed_va'], 16) for s in raw['seeds']} == NEW | REUSED
    assert {int(f['seed_va'], 16) for f in raw['functions']} == NEW
    walk(raw)
    direct, indirect, slot_calls, subjects, decoded = {}, [], {}, [], {}
    for row in raw['current_chunk_audits']:
        va = int(row['seed_va'], 16)
        instructions = []
        for block in row['chunk_byte_ranges']:
            instructions.extend(decode(bytes.fromhex(block['idb_hex']), int(block['start_va'], 16),
                                       '当前主体 ' + hex(va)))
        addresses = {i.address for i in instructions}
        assert len(addresses) == len(instructions)
        decoded[va] = instructions
        original = next((f for f in raw['functions'] if int(f['seed_va'], 16) == va), None)
        if original:
            assert original['chunk_byte_ranges'] == row['chunk_byte_ranges']
            assert addresses == {int(i['site_va'], 16) for i in original['assembly'] if i['is_code']}
        for instruction in instructions:
            if instruction.mnemonic == 'call':
                if instruction.operands[0].type == capstone.x86.X86_OP_IMM:
                    direct[(va, instruction.address)] = instruction.operands[0].imm
                else:
                    indirect.append(dict(seed_va=hex(va), site_va=hex(instruction.address),
                                         operand=instruction.op_str, bytes=instruction.bytes.hex()))
                    operand = instruction.operands[0]
                    if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == operand.mem.index == 0:
                        slot_calls[(va, instruction.address)] = operand.mem.disp
        subjects.append(dict(va=hex(va), bytes=sum(b['size'] for b in row['chunk_byte_ranges']),
                             instructions=len(instructions), chunks=len(row['chunk_byte_ranges']),
                             origin='新主体' if va in NEW else '旧指定范围重核'))
    assert set(decoded) == NEW | REUSED
    assert direct | slot_calls == {(int(c['seed_va'], 16), int(c['site_va'], 16)):int(c['target_va'], 16)
                      for c in raw['calls']}
    assert len(direct) + len(slot_calls) == len(raw['calls'])
    for call in raw['calls']:
        target = int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert target == int(bridge, 16)
            target = resolve(target)
        assert target == int(call['implementation_va'], 16)
    for bridge in raw['verified_direct_bridges']:
        assert bridge['size'] == 5
        assert resolve(int(bridge['start_va'], 16)) == int(bridge['target_va'], 16)
    reused = []
    for relative, vas in (
        ('专题/文本宽度到字符位置/证据/width_position.json', {0x90CE80, 0x90D120, 0x90D310}),
        ('专题/727F控件状态接口/证据/text_dependencies.json', {0x8FAE70}),
    ):
        source_path = DOCS / relative
        data = json.loads(source_path.read_text(encoding='utf-8'))
        for va in sorted(vas):
            index, function = next((i,f) for i,f in enumerate(data['functions']) if int(f['va'],16) == va)
            blocks = function.get('chunk_byte_ranges', function.get('chunks'))
            walk(blocks)
            old_addresses = set()
            for block in blocks:
                payload = bytes.fromhex(block.get('idb_hex', block.get('ida_hex')))
                old_addresses.update(i.address for i in decoder.disasm(payload, int(block['va'],16)))
            assert old_addresses == {i.address for i in decoded[va]}
            assert old_addresses == {int(i['va'],16) for i in function.get('assembly', function.get('instructions'))}
            reused.append(dict(va=hex(va), path=relative, json_pointer='/functions/'+str(index),
                               sha256=hashlib.sha256(source_path.read_bytes()).hexdigest()))
    for source in raw['reuse_sources']:
        path = (DOCS / source['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
    result = dict(status='字节初核；人工语义及终稿尚未完成', disk_sha256=EXPECTED,
                  raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(), subjects=subjects,
                  static_calls=len(direct), indirect_calls=indirect, reuse=reused,
                  byte_records=checked, bridges=len(raw['verified_direct_bridges']))
    if final:
        raise AssertionError('终稿与清单绑定尚未实现，不能宣告PASS')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--final', action='store_true')
    args = parser.parse_args()
    result = audit(args.final)
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True, indent=2))
