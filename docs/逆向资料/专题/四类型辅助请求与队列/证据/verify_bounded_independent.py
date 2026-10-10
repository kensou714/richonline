"""独立解码有限采证；区分完整声明块、导航窗口、虚拟区快照。"""
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
        at = offset + va - base - rva
        raw = image[at:at + size]
        assert len(raw) == size and raw.hex() == row['disk_hex'] == row['idb_hex']
        assert row['matching'] is True and hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw

    def decode(row):
        va = int(row['start_va'], 16)
        raw = audit(row)
        decoded = list(cs.disasm(raw, va))
        cursor = va
        for item in decoded:
            assert item.address == cursor
            cursor += item.size
        assert cursor == va + len(raw)
        return decoded

    path = HERE / 'bounded_raw.json'
    source_bytes = path.read_bytes()
    data = json.loads(source_bytes)
    assert data['disk_sha256'] == EXPECTED
    assert hashlib.sha256((HERE / 'export_preparation_core.py').read_bytes()).hexdigest() == data['exporter_sha256']
    seeds = {int(row['seed_va'], 16) for row in data['seeds']}
    assert seeds == {0x859A80, 0x85A1E0, 0x85A4E0, 0x85A7A0, 0x85AA60, 0x85AD70}
    functions, decoded_by_site, ranges = [], {}, []
    current = {row['seed_va']: row['chunk_byte_ranges'] for row in data['current_chunk_audits']}
    for function in data['functions']:
        assert function['chunk_byte_ranges'] == current[function['seed_va']]
        decoded = []
        for chunk in function['chunk_byte_ranges']:
            items = decode(chunk)
            decoded.extend(items)
            ranges.append((int(chunk['start_va'], 16), chunk['size']))
        heads = [int(row['site_va'], 16) for row in function['assembly']]
        assert heads == [item.address for item in decoded]
        assert all(row['is_code'] for row in function['assembly'])
        for item in decoded:
            assert item.address not in decoded_by_site
            decoded_by_site[item.address] = item
        functions.append(dict(seed_va=function['seed_va'], chunks=len(function['chunk_byte_ranges']),
                              bytes=sum(chunk['size'] for chunk in function['chunk_byte_ranges']),
                              instructions=len(decoded)))
    assert len(functions) == len(seeds) and not data['reused_seeds']
    for first, second in zip(sorted(ranges), sorted(ranges)[1:]):
        assert first[0] + first[1] <= second[0]
    bridges = {int(row['start_va'], 16): row for row in data['verified_direct_bridges']}
    for va, bridge in bridges.items():
        raw = audit(bridge)
        assert len(raw) == 5 and raw[0] == 0xE9
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == int(bridge['target_va'], 16)
        item, = decode(bridge)
        assert item.mnemonic == 'jmp' and item.operands[0].imm == target
    for call in data['calls']:
        item = decoded_by_site[int(call['site_va'], 16)]
        assert item.mnemonic in ('call', 'jmp') and item.operands[0].type == CS_OP_IMM
        target = item.operands[0].imm & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        visited = []
        for bridge in call['bridges']:
            va = int(bridge, 16)
            assert va == target and va not in visited
            visited.append(va)
            target = int(bridges[va]['target_va'], 16)
        assert target == int(call['implementation_va'], 16)
    for reference in data['data_references']:
        item = decoded_by_site[int(reference['site_va'], 16)]
        target = int(reference['target_va'], 16)
        assert any((operand.type == CS_OP_IMM and operand.imm & 0xFFFFFFFF == target) or
                   (operand.type == CS_OP_MEM and operand.mem.disp & 0xFFFFFFFF == target)
                   for operand in item.operands), (reference, item.op_str)
    for string in data['strings']:
        raw = audit(string['byte_audit'])
        width = string['unit_width']
        assert width in (1, 2) and len(raw) % width == 0
        assert raw == bytes.fromhex(string['payload_hex'] + string['nul_hex'])
        assert raw[-width:] == bytes(width) and len(raw) - width <= 4096
        assert all(raw[i:i + width] != bytes(width) for i in range(0, len(raw) - width, width))
    windows = data['explicit_owner_windows'] + [row['owner_window'] for entries in data['incoming'].values()
                                                for row in entries if 'owner_window' in row]
    window_items = 0
    for window in windows:
        assert len(window['assembly']) <= 11
        addresses = []
        for row in window['assembly']:
            item, = decode(row['bytes'])
            assert item.address == int(row['site_va'], 16)
            addresses.append(item.address)
            window_items += 1
        assert addresses == sorted(set(addresses))
        if addresses:
            assert int(window['site_va'], 16) in addresses
    for source in data['reuse_sources']:
        source_path = DOCS / source['path']
        assert source_path.resolve().is_relative_to(DOCS.resolve())
        assert hashlib.sha256(source_path.read_bytes()).hexdigest() == source['source_sha256']
    for row in data['data_windows']:
        raw = audit(row, virtual=True)
        if int(row['start_va'], 16) == 0xA2F7D0:
            assert raw is not None and struct.unpack('<4I', raw) == (33, 36, 36, 4)
    result = dict(schema='richonline-independent-bounded-1', status='PASS',
                  scope='六主体逐声明块字节、逐指令和导航证据；语义终审待有限依赖',
                  disk_sha256=EXPECTED, raw_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  functions=functions, chunks=len(ranges), bytes=sum(size for _, size in ranges),
                  instructions=len(decoded_by_site), direct_calls=len(data['calls']), bridges=len(bridges),
                  data_references=len(data['data_references']), strings=len(data['strings']),
                  navigation_window_items=window_items,
                  virtual_windows=[row['start_va'] for row in data['data_windows'] if row['disk_hex'] is None],
                  pending=['五header构造器type与body长度', '连接与buffer生产和销毁',
                           '861190读取DWORD ABI', '队列与本地列表删除责任', '下一请求真实泵上层'])
    (HERE / 'independent_bounded_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: result[key] for key in ('status', 'scope', 'chunks', 'bytes', 'instructions')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
