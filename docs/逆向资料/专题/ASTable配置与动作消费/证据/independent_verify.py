"""ASTable 独审：独立 PE/Capstone、历史原证与 KPD 解包核验。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct

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
        assert raw.hex() == record['disk_hex'], record['va']
        if 'idb_hex' in record:
            assert raw.hex() == record['idb_hex'] and record['matching'], record['va']
        return raw

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True

    def decode(ea):
        ins = next(decoder.disasm(read(ea, 16), ea, count=1), None)
        assert ins is not None, hex(ea)
        return ins

    raw = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    assert raw['disk_sha256'] == SHA
    closure = json.loads((HERE / 'closure_raw.json').read_text('utf-8'))
    assert closure['disk_sha256'] == SHA
    lifetime = json.loads((HERE / 'lifetime_raw.json').read_text('utf-8'))
    assert lifetime['disk_sha256'] == SHA
    fields = json.loads((HERE / 'fields_raw.json').read_text('utf-8'))
    assert fields['disk_sha256'] == SHA
    fields_reused = json.loads((HERE / 'fields_reused.json').read_text('utf-8'))
    field_source = (ROOT / fields_reused['source']).read_bytes()
    assert hashlib.sha256(field_source).hexdigest() == fields_reused['source_sha256']
    prior_fields = json.loads(field_source)['functions']
    assert all(f == next(old for old in prior_fields if old['va'] == f['va']) for f in fields_reused['functions'])
    functions = raw['functions'] + closure['functions'] + lifetime['functions'] + fields['functions'] + fields_reused['functions']
    assert len(functions) == len({f['va'] for f in functions}) == 19
    checked_ranges = declared_bytes = direct_calls = instruction_count = 0
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
            ins = decode(int(record['va'], 16))
            assembly.append('// %08X %s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
            instruction_count += 1
        for call in function['calls']:
            ins = decode(int(call['site'], 16))
            assert ins.mnemonic == 'call'
            if call['target'] is not None:
                assert ins.operands[0].type == X86_OP_IMM
                assert ins.operands[0].imm == int(call['target'], 16)
                direct_calls += 1
    bridges = raw['thunks'] + closure['thunks'] + lifetime['thunks'] + fields['thunks']
    for bridge in bridges:
        value = compare(bridge)
        ins = decode(int(bridge['va'], 16))
        assert len(value) == ins.size == 5 and value[0] == 0xE9
        assert ins.mnemonic == 'jmp' and ins.operands[0].type == X86_OP_IMM
        assert ins.operands[0].imm == int(bridge['target'], 16)

    navigation = json.loads((HERE / 'navigation_raw.json').read_text('utf-8'))
    closure_navigation = json.loads((HERE / 'closure_navigation.json').read_text('utf-8'))
    assert closure_navigation['disk_sha256'] == SHA
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

    walk(navigation)
    walk(closure_navigation)
    for callback, target in zip(closure_navigation['callbacks'], [0x646480, 0x646450]):
        ins = decode(int(callback['va'], 16))
        assert ins.mnemonic == 'jmp' and ins.operands[0].imm == target
    for string in navigation['strings']:
        assert compare(string['bytes']) == string['ascii'].encode('ascii') + b'\0'
    for window in navigation['windows'] + closure_navigation['windows']:
        assembly.append('// 局部导航 ' + window['start_va'])
        records = window['assembly']
        for index, record in enumerate(records):
            span = record['bytes']
            if index + 1 < len(records) and int(records[index + 1]['va'], 16) < int(record['va'], 16) + span['size']:
                assembly.append('// %s 边缘字节片段 %s；与下一真实指令重叠，不恢复语义' % (record['va'], span['disk_hex']))
                continue
            ins = decode(int(record['va'], 16))
            assert ins.size == span['size'] and ins.bytes == compare(span), record['va']
            assembly.append('// %08X %s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

    consumer = json.loads((HERE / 'consumer_reused.json').read_text('utf-8'))
    source = (ROOT / consumer['source']).read_bytes()
    assert hashlib.sha256(source).hexdigest() == consumer['source_sha256']
    old = next(f for f in json.loads(source)['functions'] if f['address'] == consumer['function'])
    old_chunks = []
    for chunk in old['chunks']:
        value = read(int(chunk['start'], 16), len(bytes.fromhex(chunk['bytes_hex'])))
        assert value.hex() == chunk['bytes_hex'].lower()
        assert hashlib.sha256(value).hexdigest() == chunk['sha256'].lower()
        old_chunks.append((chunk['start'], chunk['end'], hashlib.sha256(value).hexdigest()))
    assert old_chunks == [(c['start_va'], c['end_va'], c['sha256']) for c in consumer['full_chunk_audit']]
    assembly.append('// 历史局部消费者 ' + consumer['function'])
    for record in consumer['assembly']:
        compare(record)
        ins = decode(int(record['va'], 16))
        assembly.append('// %08X %s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        if 'target' in record:
            assert ins.mnemonic == 'call' and ins.operands[0].imm == int(record['target'], 16)
        if 'bridge' in record:
            bridge = record['bridge']
            compare(bridge)
            target = decode(int(bridge['va'], 16))
            assert target.mnemonic == 'jmp' and target.operands[0].imm == int(bridge['target'], 16)

    size_reused = json.loads((HERE / 'size_reused.json').read_text('utf-8'))
    size_source = (ROOT / size_reused['source']).read_bytes()
    assert hashlib.sha256(size_source).hexdigest() == size_reused['source_sha256']
    size_old = next(f for f in json.loads(size_source)['functions'] if f['address'] == size_reused['function'])
    assert size_old['chunks'] == size_reused['chunks']
    assembly.append('// 历史完整计数入口 ' + size_reused['function'])
    size_instructions = 0
    for chunk in size_old['chunks']:
        value = read(int(chunk['start'], 16), len(bytes.fromhex(chunk['bytes_hex'])))
        assert value.hex() == chunk['bytes_hex'].lower()
        assert hashlib.sha256(value).hexdigest() == chunk['sha256'].lower()
        for ins in decoder.disasm(value, int(chunk['start'], 16)):
            assembly.append('// %08X %s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
            size_instructions += 1

    resource = json.loads((HERE / 'resource.json').read_text('utf-8'))
    packed_blob = (ROOT / resource['source']).read_bytes()
    assert hashlib.sha256(packed_blob).hexdigest() == resource['source_sha256']
    key = packed_blob[0]
    size, packed = struct.unpack('<II', bytes((b - key) & 255 for b in packed_blob[1:9]))
    plain = lzokay.decompress(bytes((b - key) & 255 for b in packed_blob[9:9 + packed]), size)
    assert key == resource['key'] and size == len(plain) == resource['decoded_size']
    assert packed == resource['packed_size'] and len(packed_blob) - 9 - packed == resource['tail_size']
    assert hashlib.sha256(plain).hexdigest() == resource['decoded_sha256']
    assert plain == (HERE / 'ASTable.kpd.decoded.bin').read_bytes()
    groups = []
    seen_fields = set()
    for number, line in enumerate(plain.decode('latin1').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith((';', '#', '//')):
            continue
        if line.startswith('[') and line.endswith(']'):
            groups.append(dict(name=line[1:-1], line=number, fields={}))
            seen_fields = set()
        elif '=' in line and groups:
            name, value = line.split('=', 1)
            assert name.strip() not in seen_fields, (groups[-1]['name'], number, name)
            seen_fields.add(name.strip())
            groups[-1]['fields'][name.strip()] = value.strip()
    assert [(g['name'], g['line'], g['fields']) for g in groups] == [(g['name'], g['line'], g['fields']) for g in resource['sections']]
    for group in resource['sections']:
        assert group['field_byte_lengths'] == {k: len(v.encode('latin1')) for k, v in group['fields'].items()}
    assert dict(Counter(g['name'] for g in groups)) == resource['section_counts']
    by_name = {g['name']: g['fields'] for g in groups}
    assert len(by_name) == len(groups)
    domains = {}
    for name, count in [('DICE', 28), ('MOVE', 9), ('BACK', 100), ('DENG', 1)]:
        assert int(by_name[name]['num']) == count
        records = [by_name[name.lower() + str(i)] for i in range(count)]
        props = [int(r['prop']) for r in records]
        duplicates = [key for key, value in Counter(props).items() if value > 1]
        assert not duplicates
        domains[name] = dict(count=count, prop_min=min(props), prop_max=max(props),
                             prop_values=props, duplicate_props=duplicates)
    assert set(by_name) == {n for n in domains} | {n.lower() + str(i) for n, d in domains.items() for i in range(d['count'])}
    for i in range(28):
        record = by_name['dice' + str(i)]
        assert set(record) == {'prop', 'geng', 'luo'} | {'comm' + str(j) for j in range(8)}
        assert all(record['comm' + str(j)] != 'NULL' for j in range(8))
    for i in range(9):
        assert set(by_name['move' + str(i)]) == {'prop'} | {'dir' + str(j) for j in range(4)}
    assert by_name['deng0'] == {'prop': '1132', 'wait': 'other_20_0', 'anim': '34'}
    actual_strings = {int(s['bytes']['va'], 16): s['ascii'] for s in navigation['strings']}
    for ea in [0xA22758, 0xA227A0, 0xA227C4, 0xA227E8]:
        assert actual_strings[ea] == 'prop'
    assert actual_strings[0xA22770] == 'geng' and actual_strings[0xA22780] == 'luo'
    anchors = {
        0x640111: 'c7400400000000', 0x64011B: 'c7410c00000000',
        0x640125: 'c7421400000000', 0x64012F: 'c7401c00000000',
        0x640332: '8901', 0x640345: '6bc91c', 0x640348: '83c104',
        0x640499: '85c0', 0x64049D: 'eb6b', 0x6404CA: '85c0',
        0x6404CE: 'eb3a', 0x6404DE: 'e84d01fcff', 0x640500: 'e8a1eefcff',
        0x640648: '894108', 0x640651: '6bc014', 0x640711: '837dc804',
        0x640715: '7d69', 0x640920: '6bc90c', 0x640A5A: '89440a08',
        0x640B9F: '3b5108', 0x640BA7: '6bc014', 0x640BB3: '3b4508',
        0x640BC8: '33c0', 0x640BFF: '3b5110', 0x640C0D: '8b04d1',
        0x640C10: '3b4508', 0x640C25: '33c0', 0x640C5F: '3b5118',
        0x640C67: '6bc00c', 0x640C73: '3b4508', 0x640C88: '33c0',
        0x7FB1DE: 'e8719ee0ff', 0x7FB1E3: '8b4008',
        0x64295A: '8b5004', 0x64295D: '8991f0010000',
        0x64299C: '8981f4010000', 0x6429DB: '8b4004',
        0x6429DE: '8982f8010000', 0x7C105D: '668945be',
        0x7D7AA1: '8b809c000000', 0x7D7AA7: '25ff0f0000',
        0x646461: '83c104', 0x646491: '83c104',
        0x646783: '731d', 0x64679D: '894108',
        0x62465C: 'c705f066a70000000000',
        0x629539: '83e001', 0x64681A: '83780400',
        0x64682F: '8b410c', 0x646832: '2b4204', 0x646835: 'c1f802',
        0x63F89F: '8b4108', 0x63F8A2: '2b4204', 0x63F8A5: 'c1f802',
        0x64019A: 'c7410400000000', 0x6401C2: 'c7400c00000000',
        0x6401EA: 'c7421400000000', 0x640212: 'c7411c00000000',
        0x646A6F: 'c7410400000000', 0x646A79: 'c7420800000000',
        0x646A83: 'c7400c00000000', 0x646971: 'c7400400000000',
        0x64697B: 'c7410800000000', 0x646985: 'c7420c00000000',
        0x64698C: '837d0800', 0x6469C8: '894a08', 0x6469DA: '89500c',
    }
    for ea, value in anchors.items():
        assert read(ea, len(bytes.fromhex(value))).hex() == value, hex(ea)
    transcript = (HERE.parent / '04_资源配置只读转录.txt').read_text('utf-8').splitlines()[2:]
    assert transcript == ['// ' + (line.decode('ascii') if line.isascii() else '原始字节：' + line.hex())
                          for line in plain.rstrip(b'\0').splitlines()]
    manifest = HERE.parent / '函数审阅清单.json'
    if manifest.is_file():
        manifest_data = json.loads(manifest.read_text('utf-8'))
        assert manifest_data['pe_sha256'] == SHA
        reviews = manifest_data['functions']
        assert len(reviews) == len({r['va'] for r in reviews}) == 21
        assert {f['va'] for f in functions} | {consumer['function'], size_reused['function']} == {r['va'] for r in reviews}
        assert dict(Counter(r['status'] for r in reviews)) == manifest_data['status_counts']
        assert all(r['status'] and r['conclusion'] and r['unknown'] and r['evidence'] for r in reviews)
        assert all((HERE.parent / source).is_file() for r in reviews for source in r['evidence'])
        for review in reviews:
            assert (HERE.parent / review['document']).is_file()
            if 'evidence_pointer' not in review:
                continue
            evidence = json.loads((HERE.parent / review['evidence'][0]).read_text('utf-8'))
            assert review['evidence_pointer'].startswith('/functions/')
            entry = evidence['functions'][int(review['evidence_pointer'].split('/')[-1])]
            assert entry['va'] == review['va'] and entry['end_va'] == review['end_va']
            assert entry['chunk_byte_ranges'] == review['chunks']
            assert len(entry['assembly']) == review['instructions']
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status='PASS' if manifest.is_file() else 'PRELIMINARY', disk_sha256=SHA,
                  capstone_version=capstone.__version__, functions=len(functions), new_functions=18,
                  current_reused_functions=len(fields_reused['functions']), checked_ranges=checked_ranges,
                  declared_bytes=declared_bytes, instructions=instruction_count, direct_calls=direct_calls,
                  bridges=len(bridges), unique_bridges=len({b['va'] for b in bridges}), navigation_records=navigation_records,
                  strings=len(navigation['strings']), historical_chunks=len(old_chunks) + len(size_old['chunks']),
                  historical_size_instructions=size_instructions,
                  historical_window_instructions=len(consumer['assembly']), semantic_anchors=len(anchors),
                  manifest_entries=len(reviews) if manifest.is_file() else 0,
                  resources=dict(sections=len(groups), decoded_size=size, domains=domains),
                  scope='独立离线字节、调用、资源和清单核验；语义另见独立审阅，未运行游戏')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', 'utf-8')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
