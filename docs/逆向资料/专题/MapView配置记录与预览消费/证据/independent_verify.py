"""MapView 独审：独立 PE 映射、Capstone 及 KPD 解包，不启动客户端。"""
from pathlib import Path
import hashlib
import json
import struct
from collections import Counter

import capstone
import lzokay
from capstone.x86 import X86_OP_IMM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    assert struct.unpack_from('<H', blob, opt)[0] == 0x10B
    base = struct.unpack_from('<I', blob, opt + 28)[0]
    table = opt + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def read(ea, size):
        choices = [(rva, offset) for _, rva, raw, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(choices) == 1, hex(ea)
        rva, offset = choices[0]
        at = offset + ea - base - rva
        return blob[at:at + size]

    def compare(record):
        raw = read(int(record['va'], 16), record['size'])
        assert raw.hex() == record['disk_hex']
        assert raw.hex() == record['idb_hex'] and record['matching']
        return raw

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True

    def decode(ea):
        ins = next(decoder.disasm(read(ea, 16), ea, count=1), None)
        assert ins is not None, hex(ea)
        return ins

    bundles = [json.loads((HERE / name).read_text('utf-8')) for name in
               ('functions_raw.json', 'closure_raw.json', 'leaf_raw.json', 'lifetime_raw.json', 'reused_raw.json')]
    old_path = ROOT / 'docs/逆向资料/专题/录像文件与执行链/证据/io_and_parser_navigation.json'
    old = json.loads(old_path.read_text('utf-8'))
    functions = [f for bundle in bundles for f in bundle['functions']]
    functions += [f for f in old['functions'] if f['va'] == '0x7e72a0']
    assert len(functions) == len({f['va'] for f in functions})
    for source in bundles[-1]['sources']:
        assert hashlib.sha256((ROOT / source['path']).read_bytes()).hexdigest() == source['sha256']
    checked_ranges = declared_bytes = direct_calls = instructions = 0
    assembly = []
    for function in functions:
        assembly.append('// 函数 ' + function['va'])
        for span in function['chunk_byte_ranges']:
            declared_bytes += len(compare(span))
            checked_ranges += 1
        for span in function['byte_ranges']:
            compare(span)
            checked_ranges += 1
        for record in function['assembly']:
            ea = int(record['va'], 16)
            ins = decode(ea)
            assembly.append('// %08X %s %s %s' % (ea, ins.bytes.hex(), ins.mnemonic, ins.op_str))
            instructions += 1
        for call in function['calls']:
            ins = decode(int(call['site'], 16))
            assert ins.mnemonic == 'call'
            if call['target'] is not None:
                assert ins.operands[0].type == X86_OP_IMM
                assert ins.operands[0].imm == int(call['target'], 16)
                direct_calls += 1
    bridges = {t['va']: t for bundle in bundles for t in bundle.get('thunks', [])}
    for bridge in bridges.values():
        raw = compare(bridge)
        ins = decode(int(bridge['va'], 16))
        assert ins.mnemonic == 'jmp' and ins.operands[0].type == X86_OP_IMM
        assert len(raw) == ins.size == 5 and raw[0] == 0xE9
        assert ins.operands[0].imm == int(bridge['target'], 16)
    navigation_records = 0

    def walk(value):
        nonlocal navigation_records
        if isinstance(value, dict):
            if all(k in value for k in ('va', 'size', 'disk_hex')) and value['disk_hex'] is not None:
                compare(value)
                navigation_records += 1
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for name in ('navigation_raw.json', 'closure_navigation.json'):
        walk(json.loads((HERE / name).read_text('utf-8')))

    anchors = {
        0x7E8E51: ('mov', 'dword ptr [eax], 0'),
        0x7E8E7A: ('cmp', 'dword ptr [eax], 0'),
        0x7E8E8B: ('call', '0x601cd3'),
        0x7E8E96: ('mov', 'dword ptr [ecx], 0'),
        0x6293F1: ('call', '0x611976'),
        0x6293F9: ('and', 'eax, 1'),
        0x629402: ('call', '0x604cfd'),
        0x6244F8: ('mov', 'dword ptr [0xa76704], 0'),
        0x7ECD31: ('mov', 'byte ptr [eax + 0x80], 0'),
        0x7ECD3B: ('mov', 'byte ptr [ecx], 0'),
        0x7E8F7B: ('mov', 'dword ptr [ecx + 4], 0'),
        0x7E8F8D: ('call', '0x608335'),
        0x7E8FAE: ('jle', '0x7e92da'),
        0x7E8FBE: ('call', '0x60d524'),
        0x7E8FD5: ('imul', 'edx, edx, 0x114'),
        0x7E8FF7: ('push', '0x612c5e'),
        0x7E9003: ('push', '0x114'),
        0x7E900F: ('call', '0x607e5d'),
        0x7E9045: ('mov', 'dword ptr [ecx], edx'),
        0x7E9059: ('call', '0x608335'),
        0x7E90DD: ('mov', 'dword ptr [edx + ecx + 0x100], eax'),
        0x7E912C: ('mov', 'dword ptr [ecx + edx + 0x104], eax'),
        0x7E9177: ('mov', 'dword ptr [edx + ecx + 0x108], eax'),
        0x7E918C: ('mov', 'byte ptr [edx + eax + 0x110], 0'),
        0x7E91E6: ('mov', 'byte ptr [ecx + edx + 0x110], al'),
        0x7E91FB: ('mov', 'dword ptr [ecx + edx + 0x10c], 0xffffffff'),
        0x7E9252: ('mov', 'dword ptr [edx + ecx + 0x10c], eax'),
        0x7E94F1: ('mov', 'eax, dword ptr [edx + eax + 0x10c]'),
        0x7E9571: ('mov', 'eax, dword ptr [edx + eax + 0x100]'),
        0x7E95F1: ('mov', 'eax, dword ptr [edx + eax + 0x104]'),
        0x7E9671: ('mov', 'eax, dword ptr [edx + eax + 0x108]'),
        0x7E96F1: ('mov', 'al, byte ptr [edx + eax + 0x110]'),
        0x71E1E1: ('call', '0x605dc4'),
        0x71E1E9: ('mov', 'dword ptr [ecx + 0x50], eax'),
        0x71E1F5: ('push', '1'),
        0x71E21D: ('mov', 'dword ptr [edx + 0x4c], 6'),
        0x73F54D: ('and', 'eax, 2'),
        0x73F550: ('je', '0x73f8b6'),
        0x73F69B: ('cmp', 'dword ptr [ebp - 0x18], 0x1e'),
        0x73F76E: ('call', '0x6028a9'),
        0x73F77F: ('call', '0x604faa'),
        0x73F822: ('call', '0x6121c8'),
        0x73F837: ('call', '0x6001e9'),
        0x73F844: ('add', 'eax, 3'),
        0x73F864: ('call', 'dword ptr [edx + 0xc8]'),
        0x73FE7C: ('call', '0x6034d9'),
        0x73FE93: ('jmp', 'dword ptr [edx*4 + 0x73ff0f]'),
        0x7E7330: ('push', '0x64'),
        0x7E7335: ('add', 'edx, 0x520'),
        0x7E733C: ('call', '0x5ff1ea'),
        0x7E7348: ('call', '0x60fe5a'),
    }
    for ea, expected in anchors.items():
        ins = decode(ea)
        assert (ins.mnemonic, ins.op_str) == expected, (hex(ea), ins.mnemonic, ins.op_str)
    channels = struct.unpack('<4I', read(0xA67568, 16))
    assert [read(ea, 6).split(b'\0')[0] for ea in channels] == [b'CHU', b'ZHONG', b'GAO', b'XIN']
    channel_targets = struct.unpack('<4I', read(0x73FF0F, 16))
    assert channel_targets == (0x73FEB3, 0x73FECC, 0x73FEE5, 0x73FE9A)
    assert [decode(ea + 2).operands[0].imm for ea in channel_targets] == [36, 37, 38, 33]

    resource = json.loads((HERE / 'resource.json').read_text('utf-8'))
    packed_blob = (ROOT / resource['source']).read_bytes()
    assert hashlib.sha256(packed_blob).hexdigest() == resource['source_sha256']
    key = packed_blob[0]
    size, packed = struct.unpack('<II', bytes((b - key) & 255 for b in packed_blob[1:9]))
    plain = lzokay.decompress(bytes((b - key) & 255 for b in packed_blob[9:9 + packed]), size)
    assert key == resource['key'] and len(plain) == resource['decoded_size'] == size
    assert hashlib.sha256(plain).hexdigest() == resource['decoded_sha256']
    assert plain == (HERE / 'MapView.kpd.decoded.bin').read_bytes()
    records = []
    for line in plain.decode('latin1').splitlines():
        line = line.strip()
        if not line or line.startswith((';', '#', '//')):
            continue
        if line.startswith('[') and line.endswith(']'):
            records.append(dict(name=line[1:-1], fields={}))
        elif '=' in line:
            name, value = line.split('=', 1)
            assert records
            records[-1]['fields'][name.strip()] = value.strip()
    assert [(r['name'], r['fields']) for r in records] == [(r['name'], r['fields']) for r in resource['records']]
    assert len(records) == 74 and all(r['name'] == 'ITEM' for r in records)
    for record in resource['records']:
        path = ROOT / record['file_disk']['path']
        assert path.is_file() == record['file_disk']['exists']
        if path.is_file():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == record['file_disk']['sha256']
    manifest = HERE.parent / '函数审阅清单.json'
    if manifest.is_file():
        review = json.loads(manifest.read_text('utf-8'))['functions']
        assert {f['va'] for f in functions} == {f['va'] for f in review}
        assert all(r['status'] and r['conclusion'] and r['evidence'] for r in review)
        assert all((HERE.parent / source).is_file() for r in review for source in r['evidence'])
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status='PASS' if manifest.is_file() else 'PRELIMINARY', disk_sha256=SHA,
                  capstone_version=capstone.__version__, functions=len(functions), checked_ranges=checked_ranges,
                  declared_bytes=declared_bytes, instructions=instructions, direct_calls=direct_calls,
                  bridges=len(bridges), navigation_records=navigation_records,
                  semantic_anchors=len(anchors), channel_pointer_bytes=16, channel_jump_bytes=16,
                  resources=dict(records=len(records), channels=dict(Counter(r['fields']['channel'] for r in records)),
                                 new=dict(Counter(r['fields'].get('new', '<缺项>') for r in records)),
                                 missing_maps=[r['fields']['map'] for r in resource['records'] if not r['file_disk']['exists']]),
                  scope='独立离线字节、调用目标与资源核验；语义结论另见独立审阅，未运行游戏')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
