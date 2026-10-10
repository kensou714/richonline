"""独立核当前PE、原证块与桥；不导入作者验证器、不连接IDA。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def review():
    pe = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(pe) == SHA
    nt = struct.unpack_from('<I', pe, 60)[0]
    assert pe[:2] == b'MZ' and pe[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', pe, nt + 24)[0] == 0x10b
    base = struct.unpack_from('<I', pe, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', pe, nt + 20)[0]
    sections = [struct.unpack_from('<IIII', pe, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', pe, nt + 6)[0])]

    def disk(va, size):
        offsets = [raw + va - base - rva for _, rva, count, raw in sections
                   if rva <= va - base and va - base + size <= rva + count]
        assert len(offsets) == 1 and offsets[0] + size <= len(pe)
        return offsets[0], pe[offsets[0]:offsets[0] + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    sources, instructions, ranges, bridges, functions, assembly = {}, {}, {}, {}, [], []

    def load(name):
        content = (HERE / name).read_bytes()
        sources[name] = digest(content)
        return json.loads(content)

    def block(row):
        va, size = int(row['va'], 16), row['size']
        offset, actual = disk(va, size)
        assert row['matching'] is True
        assert actual.hex() == row['idb_hex'] == row['disk_hex']
        decoded = list(decoder.disasm(actual, va))
        assert sum(ins.size for ins in decoded) == size
        for ins in decoded:
            assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        ranges[va, size] = dict(va=hex(va), size=size, disk_offset=hex(offset), sha256=digest(actual))
        return decoded

    raw = load('functions_raw.json')
    assert raw['disk_sha256'] == SHA
    for thunk in raw['thunks']:
        rows = block(thunk)
        assert len(rows) == 1 and rows[0].mnemonic == 'jmp' and rows[0].size == 5
        target = int(rows[0].op_str, 16)
        assert target == int(thunk['target'], 16)
        bridges[int(thunk['va'], 16)] = target

    reused = load('reused_raw.json')
    selected = {f['va']: f for f in reused['functions']}
    for source in reused['provenance']:
        content = (ROOT / source['source']).read_bytes()
        assert digest(content) == source['source_sha256']
        sources[source['source']] = digest(content)
        originals = {f['va']: f for f in json.loads(content)['functions']}
        for va in source['functions']:
            assert originals[va] == selected[va]

    supplement = load('supplement_raw.json')
    assert supplement['disk_sha256'] == SHA
    source_constructor = load('source_constructor_raw.json')
    assert source_constructor['disk_sha256'] == SHA
    for label, group in (('本批主体', raw['functions']), ('复用全块字节', reused['functions']),
                         ('补证主体及桥函数', supplement['functions']),
                         ('源槽构造补证及桥函数', source_constructor['functions'])):
        for function in group:
            chunks = function.get('chunk_byte_ranges', function['byte_ranges'])
            if 'declared_chunks' in function:
                assert {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in function['declared_chunks']} == {
                    (int(c['va'], 16), int(c['va'], 16) + c['size']) for c in chunks}
            else:
                assert len(chunks) == 1 and int(chunks[0]['va'], 16) == int(function['va'], 16)
                assert int(chunks[0]['va'], 16) + chunks[0]['size'] == int(function['end_va'], 16)
            addresses = set()
            for chunk in chunks:
                addresses.update(ins.address for ins in block(chunk))
            assert addresses == {int(row['va'], 16) for row in function['assembly']}
            reported = set()
            for chunk in function['byte_ranges']:
                reported.update(ins.address for ins in block(chunk))
            assert reported == addresses
            calls = {va for va in addresses if instructions[va].mnemonic == 'call' and instructions[va].op_str.startswith('0x')}
            assert calls == {int(row['site'], 16) for row in function['calls']}
            for call in function['calls']:
                site, target = int(call['site'], 16), int(call['target'], 16)
                assert instructions[site].op_str == hex(target)
                for bridge_va in call['thunks']:
                    assert target == int(bridge_va, 16)
                    offset, encoded = disk(target, 5)
                    assert encoded[0] == 0xe9
                    destination = target + 5 + struct.unpack_from('<i', encoded, 1)[0]
                    if target in bridges:
                        assert destination == bridges[target]
                    bridges[target] = destination
                    target = destination
                assert target == int(call['implementation'], 16)
            functions.append(dict(va=function['va'], instructions=len(addresses), chunks=len(chunks), scope=label))
            if function['va'] in ('0x8009a0', '0x800bf0', '0x8012a0', '0x8015b0', '0x800fd0',
                                  '0x805380', '0x7fea30', '0x7febf0', '0x609695', '0x7fea80',
                                  '0x819660', '0x8198e0', '0x819a20', '0x7d5bd0', '0x6009e1', '0x8052e0',
                                  '0x8191d0', '0x819250', '0x819470'):
                assembly.extend(['// ' + label + ' ' + function['va']] +
                                ['// ' + hex(va) + ' ' + instructions[va].bytes.hex() + ' ' +
                                 instructions[va].mnemonic + ' ' + instructions[va].op_str for va in sorted(addresses)])

    constants = load('constants_raw.json')
    assert constants['disk_sha256'] == SHA
    strings = []
    for row in constants['constant_windows']:
        va, size = int(row['va'], 16), row['size']
        offset, actual = disk(va, size)
        assert actual.hex() == row['idb_hex'] == row['disk_hex'] and row['matching'] is True
        if 0xa2e0f8 <= va <= 0xa2e148:
            content = actual.split(b'\0', 1)[0]
            assert content and all(32 <= b <= 126 for b in content)
            strings.append(dict(va=hex(va), hex=content.hex(), ascii=content.decode('ascii'),
                                boundary='128B有界窗口首NUL，不宣称IDA item边界', disk_offset=hex(offset)))
    offset, encoded = disk(0x609695, 5)
    assert encoded[0] == 0xe9
    assert 0x60969a + struct.unpack_from('<i', encoded, 1)[0] == 0x7fea30
    bridges[0x609695] = 0x7fea30
    offset, encoded = disk(0x6009e1, 5)
    assert encoded[0] == 0xe9
    assert 0x6009e6 + struct.unpack_from('<i', encoded, 1)[0] == 0x7d5bd0
    bridges[0x6009e1] = 0x7d5bd0
    expected = {
        0x8009d0: ('cmp', 'edx, dword ptr [ecx + 4]'),
        0x8009d3: ('jge', '0x800a32'),
        0x8009eb: ('imul', 'edx, edx, 0x468'),
        0x800a04: ('fld', 'qword ptr [ecx + edx + 0x2c]'),
        0x800a08: ('fstp', 'qword ptr [esi + eax + 0x1c]'),
        0x800a28: ('fld', 'qword ptr [eax + ecx + 0x34]'),
        0x800a2c: ('fstp', 'qword ptr [esi + edx + 0x24]'),
        0x805391: ('imul', 'eax, eax, 0x468'),
        0x80539e: ('cmp', 'dword ptr [eax + edx], -1'),
        0x8053a2: ('setne', 'cl'),
        0x8052f1: ('and', 'eax, 2'),
        0x8052fe: ('mov', 'edx, dword ptr [ecx - 4]'),
        0x805302: ('push', '0x468'),
        0x80530b: ('call', '0x601747'),
        0x805313: ('and', 'ecx, 1'),
        0x80531b: ('sub', 'edx, 4'),
        0x800ca3: ('mov', 'dword ptr [ecx + 0xc], 0'),
        0x800cd6: ('jne', '0x800cfb'),
        0x800d0d: ('imul', 'edx, edx, 0x3c'),
        0x800d2c: ('push', '0x609695'),
        0x800d38: ('push', '0x3c'),
        0x800d77: ('mov', 'dword ptr [ecx + 8], edx'),
        0x800db3: ('cmp', 'dword ptr [ebp - 0x38], 8'),
        0x800deb: ('jmp', '0x800e76'),
        0x800df0: ('push', '0x2c'),
        0x800df2: ('push', '0x80'),
        0x800dfe: ('push', '0'),
        0x800e3e: ('push', '1'),
        0x800e2c: ('mov', 'word ptr [ecx + edx], ax'),
        0x800e6c: ('mov', 'word ptr [edx + ecx + 2], ax'),
        0x800e85: ('mov', 'dword ptr [ecx + edx + 0x30], eax'),
        0x800ecb: ('mov', 'dword ptr [edx + ecx + 0x34], eax'),
        0x800f1b: ('mov', 'byte ptr [ecx + edx + 0x38], al'),
        0x800f28: ('jmp', '0x800d89'),
        0x80134c: ('mov', 'dword ptr [ecx + 0x94], 0'),
        0x801396: ('jne', '0x8013bb'),
        0x8013c4: ('shl', 'edx, 3'),
        0x8013df: ('mov', 'dword ptr [eax + 0x98], ecx'),
        0x80143d: ('mov', 'dword ptr [ecx + 0x90], eax'),
        0x801467: ('cmp', 'ecx, dword ptr [eax + 0x94]'),
        0x80146d: ('jge', '0x801519'),
        0x8014c8: ('mov', 'dword ptr [edx + ecx*8], eax'),
        0x801510: ('mov', 'dword ptr [edx + ecx*8 + 4], eax'),
        0x8015df: ('cmp', 'edx, dword ptr [ecx + 0x94]'),
        0x8015e5: ('jge', '0x801601'),
        0x8015f3: ('mov', 'eax, dword ptr [ecx + edx*8]'),
        0x8015f6: ('cmp', 'eax, dword ptr [ebp + 8]'),
        0x8015fb: ('mov', 'al, 1'),
        0x801601: ('xor', 'al, al'),
        0x800ff4: ('mov', 'byte ptr [ebp - 0x31], 0'),
        0x801047: ('movzx', 'ecx, byte ptr [eax + ecx + 0x38]'),
        0x801087: ('cmp', 'edx, dword ptr [eax + ecx + 0x30]'),
        0x8010aa: ('cmp', 'dword ptr [ebp - 0x28], 8'),
        0x8010b9: ('movsx', 'eax, word ptr [edx + ecx]'),
        0x8010d1: ('movsx', 'edx, word ptr [edx + ecx]'),
        0x8010dc: ('add', 'eax, 1'),
        0x8010e5: ('mov', 'byte ptr [ebp + ecx - 0x18], 1'),
        0x8010fe: ('movsx', 'eax, word ptr [ecx + edx + 2]'),
        0x801120: ('movsx', 'edx, word ptr [eax + ecx + 2]'),
        0x80114d: ('mov', 'ecx, dword ptr [eax + ecx + 0x34]'),
        0x801155: ('call', '0x60cfe3'),
        0x801165: ('mov', 'dword ptr [ebp - 0x28], 7'),
        0x801171: ('sub', 'eax, 1'),
        0x801192: ('mov', 'word ptr [ecx + eax], 0xffff'),
        0x8011a1: ('mov', 'word ptr [eax + edx + 2], 0'),
        0x8011a8: ('mov', 'byte ptr [ebp - 0x31], 1'),
        0x8011af: ('mov', 'dword ptr [ebp - 0x30], ecx'),
        0x8011b4: ('cmp', 'byte ptr [ebp - 0x31], 0'),
        0x8011bf: ('call', '0x6104db'),
        0x8011dc: ('mov', 'cx, word ptr [ecx + edx + 0x34]'),
        0x8011e1: ('mov', 'word ptr [esi + eax], cx'),
        0x8011e5: ('cmp', 'byte ptr [ebp - 0x31], 0'),
        0x8011f0: ('call', '0x6104db'),
        0x801201: ('mov', 'word ptr [eax + edx + 2], 1'),
        0x801249: ('jmp', '0x801023'),
        0x80124e: ('mov', 'al, byte ptr [ebp - 0xa]'),
        0x7fea3e: ('push', '0x6009e1'),
        0x7fea43: ('push', '8'),
        0x7fea45: ('push', '6'),
        0x7fea53: ('mov', 'dword ptr [ecx + 0x30], 0'),
        0x7fea5d: ('mov', 'dword ptr [edx + 0x34], 0xffffffff'),
        0x7fea67: ('mov', 'byte ptr [eax + 0x38], 0'),
        0x7d5be1: ('mov', 'word ptr [eax], 0xffff'),
        0x7d5be9: ('mov', 'word ptr [ecx + 2], 0'),
        0x7d5bf2: ('mov', 'byte ptr [edx + 4], 0'),
        0x7d5bf9: ('mov', 'byte ptr [eax + 5], 0xff'),
        0x7feaae: ('mov', 'dword ptr [eax + 0x94], 0'),
        0x7feabb: ('mov', 'dword ptr [ecx + 0x98], 0'),
        0x7fec0e: ('cmp', 'dword ptr [eax + 0x98], 0'),
        0x7fec32: ('mov', 'dword ptr [ecx + 0x98], 0'),
        0x7ff093: ('mov', 'dword ptr [edx + 8], 0'),
        0x7ff0b6: ('push', '3'),
        0x7ff0bb: ('call', '0x60ca48'),
        0x7ff0cf: ('mov', 'dword ptr [ecx], 0'),
        0x8193b0: ('mov', 'dword ptr [eax + 0x8c], edx'),
        0x8193bf: ('mov', 'dword ptr [eax + 0x94], edx'),
        0x81949f: ('cmp', 'edx, dword ptr [eax + 0x88]'),
        0x8194ef: ('cmp', 'eax, 0xa'),
        0x819576: ('cmp', 'ecx, 0x5d'),
        0x8195db: ('call', '0x61038c'),
        0x8195f3: ('mov', 'dword ptr [ecx + 0x90], eax'),
        0x81968c: ('mov', 'dword ptr [eax + 0x90], edx'),
        0x819739: ('jne', '0x819740'),
        0x8198c6: ('xor', 'eax, eax'),
        0x819988: ('mov', 'byte ptr [edx], 0'),
        0x8199f4: ('cmp', 'edx, dword ptr [ebp + 0xc]'),
        0x819adb: ('mov', 'byte ptr [eax], 0'),
        0x819ade: ('xor', 'eax, eax'),
        0x819b72: ('mov', 'byte ptr [eax], 0'),
        0x819be7: ('cmp', 'ecx, dword ptr [ebp + 0x10]'),
        0x623d58: ('call', '0x60d5ab'),
        0x623d69: ('call', '0x603d2b'),
        0x623d8b: ('call', '0x60e37a'),
        0x742c05: ('call', '0x611124'),
        0x742c0f: ('je', '0x742c41'),
        0x742c2f: ('mov', 'dword ptr [ecx + edx*4], eax'),
        0x742fff: ('call', '0x611124'),
        0x743009: ('je', '0x743046'),
    }
    anchors = []
    for va, (mnemonic, operand) in expected.items():
        ins = instructions[va]
        assert ins.mnemonic == mnemonic and ins.op_str == operand, hex(va)
        anchors.append(dict(va=hex(va), hex=ins.bytes.hex(), mnemonic=mnemonic, operand=operand))
    result = dict(status='字节预核通过，语义与终稿待审', pe_sha256=SHA, sources=sources,
                  functions=functions, unique_ranges=list(ranges.values()), bridge_count=len(bridges),
                  bridges={hex(va): hex(target) for va, target in sorted(bridges.items())}, strings=strings,
                  semantic_anchors=anchors,
                  boundary='复用全块重核不代表新增完整语义；未运行游戏')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    result = review()
    print(result['status'], 'functions', len(result['functions']), 'bridges', result['bridge_count'])
