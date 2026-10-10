"""独立核回调转接、装载器补原块和两次块外数据采证。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

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

    def audit(block):
        va = int(block.get('va', block.get('start_va')), 16)
        mappings = [(rva, offset) for _, rva, length, offset in sections
                    if 0 <= va - base - rva and va - base - rva + block['size'] <= length]
        assert len(mappings) == 1
        rva, offset = mappings[0]
        result = image[offset + va - base - rva:offset + va - base - rva + block['size']]
        assert len(result) == block['size']
        assert result.hex() == block['idb_hex'] == block['disk_hex'] and block['matching'] is True
        if 'sha256' in block:
            assert hashlib.sha256(result).hexdigest() == block['sha256']
        return va, result

    payload = (HERE / 'display_loader_raw.json').read_bytes()
    raw = json.loads(payload)
    assert raw['disk_sha256'] == EXPECTED
    assert {int(f['va'], 16) for f in raw['functions']} == {
        0x5FFD89, 0x601F7B, 0x604FB9, 0x6EEBD0, 0x6EEC20, 0x6EEC70, 0x7B9CA0}
    by_site, results = {}, []
    for function in raw['functions']:
        heads, size = [], 0
        assert function['bytes_match_disk'] is True
        assert len(function['declared_chunks']) == len(function['chunk_byte_ranges'])
        for declaration, chunk in zip(function['declared_chunks'], function['chunk_byte_ranges']):
            va, disk = audit(chunk)
            assert declaration == dict(start_va=chunk['va'], end_va=hex(va + len(disk)),
                                       is_main=chunk['va'] == function['va'])
            cursor = va
            for item in cs.disasm(disk, va):
                assert cursor == item.address and item.address not in by_site
                by_site[item.address] = item
                heads.append(item.address)
                cursor += item.size
            assert cursor == va + len(disk)
            size += len(disk)
        assert heads == [int(row['va'], 16) for row in function['assembly']]
        # 独立核另一份指令范围，不将其重复加到声明块字节数。
        for block in function['byte_ranges']:
            audit(block)
        results.append(dict(va=function['va'], bytes=size, instructions=len(heads),
                            declared_chunks=len(function['declared_chunks'])))
    thunks = {}
    for thunk in raw['thunks']:
        va, disk = audit(thunk)
        assert len(disk) == 5 and disk[0] == 0xE9
        target = va + 5 + struct.unpack_from('<i', disk, 1)[0]
        assert target == int(thunk['target'], 16)
        thunks[va] = target
    for function in raw['functions']:
        for call in function['calls']:
            item = by_site[int(call['site'], 16)]
            assert item.mnemonic in ('call', 'jmp') and item.operands[0].type == CS_OP_IMM
            target = item.operands[0].imm & 0xFFFFFFFF
            assert target == int(call['target'], 16)
            for bridge in call['thunks']:
                assert target == int(bridge, 16)
                target = thunks[target]
            assert target == int(call['implementation'], 16)
    expected = {
        0x5FFD89: ('jmp', '0x6eec70'), 0x601F7B: ('jmp', '0x6eec20'),
        0x604FB9: ('jmp', '0x6eebd0'),
        0x6EEBDC: ('push', '1'), 0x6EEBFB: ('call', 'dword ptr [edx + 0x64]'),
        0x6EEC2C: ('push', '1'), 0x6EEC4B: ('call', 'dword ptr [edx + 0x6c]'),
        0x6EEC7C: ('push', '1'), 0x6EEC9B: ('call', 'dword ptr [edx + 0x90]'),
        0x7B9D6E: ('push', '0x80'), 0x7B9DA7: ('push', '0x80'),
        0x7B9DD0: ('mov', 'dword ptr [ecx*4 + 0xa87480], eax'),
        0x7B9DD7: ('jmp', '0x7b9d4a'),
        0xA14FF3: ('jmp', '0x602575'), 0xA14FFE: ('jmp', '0x60ba26'),
    }
    assert all((by_site[va].mnemonic, by_site[va].op_str) == pair for va, pair in expected.items())
    tables = []
    for path, expected_va, expected_size in [
            ('table_supplement/bounded_raw.json', 0x70B01B, 50),
            ('table_head_supplement/bounded_raw.json', 0x70B017, 4)]:
        content = (HERE / path).read_bytes()
        data = json.loads(content)
        assert data['disk_sha256'] == EXPECTED
        assert not data['functions'] and not data['seeds'] and not data['reused_seeds']
        block, = data['data_windows']
        va, disk = audit(block)
        assert va == expected_va and len(disk) == expected_size
        tables.append(dict(path=path, sha256=hashlib.sha256(content).hexdigest(),
                           va=hex(va), size=len(disk), disk_hex=disk.hex()))
    assert int(tables[1]['va'], 16) + tables[1]['size'] == int(tables[0]['va'], 16)
    merged = bytes.fromhex(tables[1]['disk_hex'] + tables[0]['disk_hex'])
    assert len(merged) == 54
    result = dict(schema='richonline-independent-goldcharge-supplement-1', status='PASS',
                  disk_sha256=EXPECTED, source_sha256=hashlib.sha256(payload).hexdigest(),
                  functions=results, bytes=sum(f['bytes'] for f in results),
                  instructions=len(by_site), thunks=len(thunks), table_windows=tables,
                  semantic_anchors=[dict(va=hex(va), mnemonic=p[0], operands=p[1]) for va, p in expected.items()],
                  boundary='三路仅转虚接口；未证明实际显示消费；7B9CA0补证不算新函数；数据表不计函数')
    (HERE / 'independent_supplement_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {k: result[k] for k in ('status', 'bytes', 'instructions')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
