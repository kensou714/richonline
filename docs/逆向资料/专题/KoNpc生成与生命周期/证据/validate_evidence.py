"""用当前 PE 独立核对新原证、复用范围、跳板、窗口及正文格式。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

ROOT = Path(__file__).resolve().parents[5]
DOCS = ROOT / 'docs/逆向资料'
BASE = Path(__file__).resolve().parent
TOPIC = BASE.parent


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional_size + index * 40
        sections.append(struct.unpack_from('<III', blob, at + 12))

    def disk(va, length):
        ea = int(va, 16)
        for rva, size, offset in sections:
            relative = ea - image_base - rva
            if 0 <= relative and relative + length <= size:
                return blob[offset + relative:offset + relative + length]
        raise AssertionError('原证超出磁盘节：' + va)

    functions, ranges, bridges = {}, 0, {}
    files = ['generation_raw.json', 'lifecycle_dependencies_raw.json', 'lifecycle_leaves_raw.json']
    for filename in files:
        value = json.loads((BASE / filename).read_text('utf-8'))
        assert value['disk_sha256'] == digest
        for record in value['functions']:
            functions[record['va']] = record
        for bridge in value.get('thunks', []):
            bridges[bridge['va']] = bridge
    fresh_count = len(functions)
    reused = json.loads((BASE / 'reused_evidence.json').read_text('utf-8'))
    for source, source_digest in reused['source_hashes'].items():
        assert hashlib.sha256((DOCS / source).read_bytes()).hexdigest() == source_digest
    for row in reused['reused']:
        record = row['record']
        assert row['va'] == record['va']
        assert record['va'] not in functions
        functions[record['va']] = record
    for bridge in reused['thunks']:
        bridges[bridge['va']] = bridge
    for record in functions.values():
        assert record['byte_ranges']
        for key in ('byte_ranges', 'chunk_byte_ranges'):
            for row in record.get(key, []):
                raw = bytes.fromhex(row['idb_hex'])
                assert len(raw) == row['size']
                current = disk(row['va'], row['size'])
                assert raw == current, (record['va'], key, row['va'])
                if row.get('disk_hex') is not None:
                    assert bytes.fromhex(row['disk_hex']) == current
                ranges += 1
    extra = json.loads((BASE / 'window_bridges.json').read_text('utf-8'))
    audited_window_bridges = []
    for row in extra['bridges']:
        bridges[row['va']] = row
        current = disk(row['va'], row['size'])
        audited_window_bridges.append(dict(row, disk_hex=current.hex(),
                                          matching=current == bytes.fromhex(row['idb_hex'])))
    for row in bridges.values():
        raw = bytes.fromhex(row['idb_hex'])
        assert raw == disk(row['va'], row['size'])
        assert row['size'] == 5 and raw[0] == 0xE9
        target = int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True)
        assert target == int(row['target'], 16)
    window = json.loads((BASE / 'unowned_npc_window.json').read_text('utf-8'))
    raw = bytes.fromhex(window['idb_hex'])
    assert raw == bytes.fromhex(window['disk_hex']) == disk(window['start_va'], len(raw))
    assert len(raw) == int(window['end_va'], 16) - int(window['start_va'], 16)
    assert all(row['owner'] is None for row in window['assembly'])
    instructions = {row['va']: row['text'] for row in window['assembly']}
    assert '[ecx+224h]' in instructions['0x8075d4']
    assert '[ecx+21Eh]' in instructions['0x80759e']
    assert '[eax+21Ch]' in instructions['0x8075aa']
    assert '[edx+21Dh]' in instructions['0x8075b6']
    assert '[ecx+21Fh]' in instructions['0x8075c2']
    expected = {'0x60d3f8': '0x807830', '0x5ff843': '0x807860',
                '0x609fe1': '0x807890', '0x6059aa': '0x8078c0', '0x603ddf': '0x807560'}
    assert all(bridges[va]['target'] == target for va, target in expected.items())
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded = {instruction.address: instruction for instruction in
               decoder.disasm(disk('0x807560', 0x80772E - 0x807560), 0x807560)}
    assert decoded[0x8075D4].mnemonic == 'idiv'
    assert decoded[0x8075D4].operands[0].type == X86_OP_MEM
    assert decoded[0x8075D4].operands[0].mem.disp == 0x224
    assert decoded[0x807643].mnemonic == 'jge'
    assert decoded[0x80763F].operands[1].type == X86_OP_IMM
    assert decoded[0x80763F].operands[1].imm == 20
    assert decoded[0x80772B].mnemonic == 'ret' and decoded[0x80772B].operands[0].imm == 4
    for site, target in ((0x8076AB, 0x60D3F8), (0x8076C5, 0x5FF843),
                         (0x8076DF, 0x609FE1), (0x8076F9, 0x6059AA)):
        assert decoded[site].mnemonic == 'call' and decoded[site].operands[0].imm == target
    (BASE / 'window_bridges_disk_audit.json').write_text(json.dumps(
        dict(disk_sha256=digest, bridges=audited_window_bridges), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    false_hit = disk('0x9dae3e', 6)
    assert false_hit[:2] == b'\x0f\x8c'
    assert disk('0x9dae3f', 4) == struct.pack('<I', 0x1478C)
    manifests = json.loads((TOPIC / '函数审阅清单.json').read_text('utf-8'))
    assert len(manifests['functions']) == len(functions)
    assert {row['va'] for row in manifests['functions']} == set(functions)
    for row in manifests['functions']:
        assert all(key in row for key in ('va', 'status', 'conclusion', 'unknown', 'evidence'))
        assert isinstance(row['unknown'], str) and row['unknown'].strip()
        assert row.get('ranges')
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    output = dict(result='PASS', disk_sha256=digest, new_functions=fresh_count,
                  reused_functions=len(reused['reused']), unique_functions=len(functions),
                  function_range_records=ranges, unique_bridges=len(bridges),
                  unowned_window_bytes=len(raw), unowned_window_instruction_items=len(window['assembly']),
                  capstone_window_code_instructions=len(decoded),
                  caveat='范围和桥重叠不累加；未声明窗口不计函数覆盖；局部一致不是整个 IDB 一致')
    (BASE / 'validation.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output, ensure_ascii=True))


if __name__ == '__main__':
    main()
