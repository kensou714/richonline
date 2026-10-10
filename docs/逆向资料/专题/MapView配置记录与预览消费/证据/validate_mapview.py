"""独立读取当前 PE 原字节与 Capstone，核原证、资源及文档格式。"""
from pathlib import Path
import hashlib
import json
import struct
from collections import Counter
import capstone

ROOT = Path('F:/大富翁online/Richonline')
BASE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((base + rva, size, offset))

    def read(va, size):
        for start, count, offset in sections:
            if start <= va and va + size <= start + count:
                return blob[offset + va - start:offset + va - start + size]
        raise ValueError('原字节无磁盘映射：' + hex(va))

    audits = []
    sources = []
    raw_paths = [BASE / name for name in ('functions_raw.json', 'reused_raw.json', 'closure_raw.json',
                                         'leaf_raw.json', 'lifetime_raw.json')]
    old = ROOT / 'docs/逆向资料/专题/录像文件与执行链/证据/io_and_parser_navigation.json'
    for path in raw_paths + [old]:
        data = path.read_bytes()
        source = json.loads(data.decode('utf-8'))
        assert source['disk_sha256'] == SHA
        funcs = source['functions'] if path != old else [f for f in source['functions'] if f['va'] == '0x7e72a0']
        for function in funcs:
            for key in ('byte_ranges', 'chunk_byte_ranges'):
                for item in function[key]:
                    expected = bytes.fromhex(item['disk_hex'])
                    assert read(int(item['va'], 16), item['size']) == expected
            audits.append(dict(va=function['va'], source=str(path.relative_to(ROOT)).replace('\\', '/'),
                               instruction_ranges=len(function['byte_ranges']),
                               declared_chunks=len(function['chunk_byte_ranges'])))
        sources.append(dict(path=str(path.relative_to(ROOT)).replace('\\', '/'), sha256=hashlib.sha256(data).hexdigest()))

    navigation_checks = 0

    def walk(value):
        nonlocal navigation_checks
        if isinstance(value, dict):
            if all(key in value for key in ('va', 'size', 'disk_hex')) and value['disk_hex'] is not None:
                assert read(int(value['va'], 16), value['size']) == bytes.fromhex(value['disk_hex'])
                navigation_checks += 1
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for name in ('navigation_raw.json', 'closure_navigation.json'):
        walk(json.loads((BASE / name).read_text('utf-8')))

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    assertions = {0x7E9045: ('mov', '[ecx], edx'),
                  0x7E90DD: ('mov', '[edx + ecx + 0x100], eax'),
                  0x7E912C: ('mov', '[ecx + edx + 0x104], eax'),
                  0x7E9177: ('mov', '[edx + ecx + 0x108], eax'),
                  0x7E918C: ('mov', '[edx + eax + 0x110], 0'),
                  0x7E91FB: ('mov', '[ecx + edx + 0x10c], 0xffffffff'),
                  0x622D61: ('mov', 'ecx, dword ptr [ebp + 8]'),
                  0x7E94F1: ('mov', '[edx + eax + 0x10c]'),
                  0x7E9571: ('mov', '[edx + eax + 0x100]'),
                  0x7E95F1: ('mov', '[edx + eax + 0x104]'),
                  0x7E96F1: ('mov', 'al, byte ptr [edx + eax + 0x110]')}
    critical = []
    for va, (mnemonic, operands) in assertions.items():
        ins = next(decoder.disasm(read(va, 15), va, count=1))
        assert ins.mnemonic == mnemonic and operands in ins.op_str, (hex(va), ins.mnemonic, ins.op_str)
        critical.append(dict(va=hex(va), text=ins.mnemonic + ' ' + ins.op_str))

    resource = json.loads((BASE / 'resource.json').read_text('utf-8'))
    assert hashlib.sha256((ROOT / resource['source']).read_bytes()).hexdigest() == resource['source_sha256']
    plain = (BASE / 'MapView.kpd.decoded.bin').read_bytes()
    assert hashlib.sha256(plain).hexdigest() == resource['decoded_sha256']
    records = resource['records']
    assert len(records) == 74 and all(r['name'] == 'ITEM' for r in records)
    required = ('map', 'pic_enb', 'pic_dis', 'channel')
    assert all(all(key in r['fields'] for key in required) for r in records)
    assert max(r['field_byte_lengths'][key] for r in records for key in required) < 128
    review = json.loads((BASE.parent / '函数审阅清单.json').read_text('utf-8'))
    raw_addresses = {item['va'] for item in audits}
    assert all(r['va'] in raw_addresses and all(k in r for k in ('status', 'conclusion', 'unknown', 'evidence')) for r in review['functions'])
    for path in BASE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines()), path
    result = dict(disk_sha256=SHA, function_checks=audits, sources=sources,
                  navigation_byte_records=navigation_checks, capstone_checks=critical,
                  resource=dict(item_records=len(records),
                                channels=dict(Counter(r['fields']['channel'] for r in records)),
                                new_values=dict(Counter(r['fields'].get('new', '<缺项>') for r in records)),
                                missing_maps=[r['fields']['map'] for r in records if not r['file_disk']['exists']]),
                  scope='作者离线字节与字段契约检查；没有实机 UI、分配失败或重复加载动态验证',
                  passed=True)
    (BASE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k in ('passed', 'resource', 'navigation_byte_records')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
