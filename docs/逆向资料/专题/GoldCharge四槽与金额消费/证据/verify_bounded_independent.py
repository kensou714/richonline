"""独立核本批声明块、调用边、引用、导航与虚拟区快照。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True

    def audit(row, virtual=False):
        va, size = int(row['start_va'], 16), row['size']
        assert 0 < size <= 1048576
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(matches) <= 1
        if not matches:
            assert virtual and row['disk_hex'] is None and row['matching'] is None
            assert sum(0 <= va - base - rva and va - base - rva + size <= length
                       for length, rva, _, _ in sections) == 1
            if row['idb_hex'] is not None:
                raw = bytes.fromhex(row['idb_hex'])
                assert len(raw) == size and hashlib.sha256(raw).hexdigest() == row['sha256']
            return None
        rva, offset = matches[0]
        raw = image[offset + va - base - rva:offset + va - base - rva + size]
        assert len(raw) == size and raw.hex() == row['disk_hex'] == row['idb_hex']
        assert row['matching'] is True and hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw

    def decode(row):
        va = int(row['start_va'], 16)
        raw = audit(row)
        decoded, cursor = list(cs.disasm(raw, va)), va
        for item in decoded:
            assert item.address == cursor
            cursor += item.size
        assert cursor == va + len(raw)
        return decoded

    source_bytes = (HERE / 'bounded_raw.json').read_bytes()
    data = json.loads(source_bytes)
    assert data['disk_sha256'] == EXPECTED
    core = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
    assert hashlib.sha256(core.read_bytes()).hexdigest() == data['exporter_sha256']
    seeds = {int(row['seed_va'], 16) for row in data['seeds']}
    assert seeds == {0x709E50, 0x70A7E0, 0x70ABA0, 0x70B050, 0x727CC0}
    current = {row['seed_va']: row['chunk_byte_ranges'] for row in data['current_chunk_audits']}
    functions, by_site, ranges = [], {}, []
    for function in data['functions']:
        assert function['chunk_byte_ranges'] == current[function['seed_va']]
        decoded = []
        for chunk in function['chunk_byte_ranges']:
            decoded.extend(decode(chunk))
            ranges.append((int(chunk['start_va'], 16), chunk['size']))
        assert [int(row['site_va'], 16) for row in function['assembly']] == [item.address for item in decoded]
        assert all(row['is_code'] for row in function['assembly'])
        for item in decoded:
            assert item.address not in by_site
            by_site[item.address] = item
        functions.append(dict(seed_va=function['seed_va'], chunks=len(function['chunk_byte_ranges']),
                              bytes=sum(row['size'] for row in function['chunk_byte_ranges']),
                              instructions=len(decoded)))
    assert len(functions) == len(seeds) and not data['reused_seeds']
    for left, right in zip(sorted(ranges), sorted(ranges)[1:]):
        assert left[0] + left[1] <= right[0]
    bridges = {int(row['start_va'], 16): row for row in data['verified_direct_bridges']}
    for va, row in bridges.items():
        raw = audit(row)
        assert len(raw) == 5 and raw[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target_va'], 16)
    for call in data['calls']:
        item = by_site[int(call['site_va'], 16)]
        assert item.mnemonic in ('call', 'jmp') and item.operands[0].type == CS_OP_IMM
        target = item.operands[0].imm & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        visited = set()
        for bridge in call['bridges']:
            va = int(bridge, 16)
            assert va == target and va not in visited
            visited.add(va)
            target = int(bridges[va]['target_va'], 16)
        assert target == int(call['implementation_va'], 16)
    for ref in data['data_references']:
        item, target = by_site[int(ref['site_va'], 16)], int(ref['target_va'], 16)
        assert any((operand.type == CS_OP_IMM and operand.imm & 0xFFFFFFFF == target) or
                   (operand.type == CS_OP_MEM and operand.mem.disp & 0xFFFFFFFF == target)
                   for operand in item.operands)
    for row in data['strings']:
        raw, width = audit(row['byte_audit']), row['unit_width']
        assert width in (1, 2) and len(raw) % width == 0
        assert raw == bytes.fromhex(row['payload_hex'] + row['nul_hex'])
        assert raw[-width:] == bytes(width) and len(raw) - width <= 4096
        assert all(raw[i:i + width] != bytes(width) for i in range(0, len(raw) - width, width))
    windows = data['explicit_owner_windows'] + [row['owner_window'] for rows in data['incoming'].values()
                                               for row in rows if 'owner_window' in row]
    window_count = 0
    for window in windows:
        assert len(window['assembly']) <= 11
        addresses = []
        for row in window['assembly']:
            item, = decode(row['bytes'])
            assert item.address == int(row['site_va'], 16)
            addresses.append(item.address)
            window_count += 1
        assert addresses == sorted(set(addresses))
        assert not addresses or int(window['site_va'], 16) in addresses
    for source in data['reuse_sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
    assert {(int(row['start_va'], 16), row['size']) for row in data['data_windows']} == {
        (0xA87480, 4), (0xA87484, 4), (0xA87488, 4), (0xA8748C, 4)}
    for row in data['data_windows']:
        audit(row, virtual=True)
    result = dict(schema='richonline-independent-goldcharge-bounded-1', status='PASS',
                  disk_sha256=EXPECTED, raw_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  functions=functions, chunks=len(ranges), bytes=sum(size for _, size in ranges),
                  instructions=len(by_site), direct_calls=len(data['calls']), bridges=len(bridges),
                  data_references=len(data['data_references']), strings=len(data['strings']),
                  navigation_window_items=window_count,
                  virtual_windows=[row['start_va'] for row in data['data_windows'] if row['disk_hex'] is None],
                  boundary='原证机械核验；不证明资格门是扣款、运行时可达或资源已装载')
    (HERE / 'independent_bounded_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: result[key] for key in ('status', 'chunks', 'bytes', 'instructions')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
