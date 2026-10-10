"""独立核验IDA导出块、别名入边和未声明代码候选。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
RAW = HERE / '82bbe0_raw.json'
OUT = HERE / 'validation.json'
EXPECTED_SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    evidence = json.loads(RAW.read_text(encoding='utf-8'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA256 == evidence['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk_bytes(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    blocks = []
    instruction_count = 0

    def check_block(block):
        ea, size = int(block['va'], 16), block['size']
        raw = disk_bytes(ea, size)
        assert int(block['end'], 16) == ea + size
        assert raw.hex() == block['disk_hex'] == block['ida_hex']
        assert hashlib.sha256(raw).hexdigest() == block['sha256']
        assert block['equal'] is True
        blocks.append((ea, ea + size))

    def check_instructions(rows, block_list):
        nonlocal instruction_count
        for row in rows:
            ea, size = int(row['va'], 16), row['size']
            assert any(int(block['va'], 16) <= ea
                       and ea + size <= int(block['end'], 16) for block in block_list)
            assert disk_bytes(ea, size).hex() == row['hex']
            instruction_count += 1

    assert evidence['subject'] == '0x82bbe0'
    assert evidence['entries'] == ['0x60bfda', '0x82bbe0']
    assert [f['va'] for f in evidence['functions']] == [
        '0x82bbe0', '0x82edd0', '0x840230', '0x846ab0']
    for func in evidence['functions']:
        for block in func['chunks']:
            check_block(block)
        check_instructions(func['instructions'], func['chunks'])
    main_func = evidence['functions'][0]
    assert len(main_func['instructions']) == 21
    assert sum(row['hex'] == '8b4010' for row in main_func['instructions']) == 1
    assert main_func['instructions'][-1]['hex'] == 'c3'

    thunks = evidence['thunks']
    assert list(thunks) == ['0x60bfda']
    thunk = thunks['0x60bfda']
    check_block(thunk)
    assert thunk['target'] == '0x82bbe0'
    assert disk_bytes(0x60BFDA, 1) == b'\xe9'
    assert 0x60BFDA + 5 + struct.unpack('<i', disk_bytes(0x60BFDB, 4))[0] == 0x82BBE0

    incoming = evidence['incoming']
    assert len(incoming) == 63
    assert sum(row['entry'] == '0x60bfda' for row in incoming) == 62
    assert sum(row['entry'] == '0x82bbe0' for row in incoming) == 1
    assert len(evidence['windows']) == 61
    assert len({row['owner'] for row in evidence['windows']}) == 48
    sites = set()
    for window in evidence['windows']:
        check_block(window['block'])
        check_instructions(window['instructions'], [window['block']])
        site = int(window['site'], 16)
        assert window['site'] not in sites
        sites.add(window['site'])
        assert disk_bytes(site, 1) == b'\xe8'
        assert site + 5 + struct.unpack('<i', disk_bytes(site + 1, 4))[0] == 0x60BFDA
    assert set(evidence['selected_callers']) == {'0x82edd0', '0x840230', '0x846ab0'}

    unowned = [row for row in incoming if row['owner'] is None]
    assert len(unowned) == 1 and unowned[0]['site'] == '0x82d864'
    assert len(evidence['undeclared']) == 1
    gap = evidence['undeclared'][0]
    check_block(gap['block'])
    check_instructions(gap['instructions'], [gap['block']])
    assert len(gap['instructions']) == 46
    assert gap['block']['va'] == '0x82d820' and gap['block']['end'] == '0x82d8b9'
    assert disk_bytes(0x82D820, 3) == bytes.fromhex('558bec')
    assert disk_bytes(0x82D8B6, 3) == bytes.fromhex('c20400')
    assert disk_bytes(0x82D864, 1) == b'\xe8'
    assert 0x82D869 + struct.unpack('<i', disk_bytes(0x82D865, 4))[0] == 0x60BFDA
    assert {row['site'] for row in incoming} - sites == {'0x82d864', '0x60bfda'}

    merged = []
    for start, end in sorted(blocks):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    result = dict(status='PASS', source_sha256=digest, complete_functions=4,
                  function_chunks=sum(len(f['chunks']) for f in evidence['functions']),
                  entry_count=2, incoming_count=63, owned_call_windows=61,
                  owned_callers=48, undeclared_candidates=1,
                  verified_blocks=len(blocks), verified_instructions=instruction_count,
                  unique_interval_count=len(merged),
                  unique_disk_bytes=sum(end - start for start, end in merged),
                  semantic_boundary='仅静态PE与IDA证据；无运行时可达性或对象有效性保证')
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
