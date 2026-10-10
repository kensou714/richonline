"""Avatar独审：独立磁盘反汇编、历史块与资源词法核验。"""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct

import capstone
import lzokay
from capstone.x86 import X86_OP_IMM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--final', action='store_true', help='正文稳定后执行清单与作者终稿哈希核验')
    args = parser.parse_args()
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(blob) == SHA
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    assert struct.unpack_from('<H', blob, opt)[0] == 0x10b
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

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    transcript, source_hashes = [], {}

    def load(path):
        source = path.read_bytes()
        source_hashes[path.relative_to(ROOT).as_posix()] = digest(source)
        return json.loads(source)

    def decode(ea):
        ins = next(decoder.disasm(read(ea, 16), ea, count=1), None)
        assert ins is not None, hex(ea)
        return ins

    def append(ins):
        transcript.append('// %08X %s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

    def compare(record, hex_key='disk_hex', address_key='va'):
        value = read(int(record[address_key], 16), record['size'])
        assert value.hex() == record[hex_key].lower(), record.get(address_key)
        if 'idb_hex' in record:
            assert value.hex() == record['idb_hex'].lower()
        if 'matching' in record:
            assert record['matching']
        return value

    raw = load(HERE / 'avatar_raw.json')
    supplement = load(HERE / 'supplement_raw.json')
    constructor = load(HERE / 'coordinate_constructor_raw.json')
    assert {f['va'] for f in raw['functions']} == {hex(ea) for ea in
            (0x641650, 0x6416B0, 0x6416E0, 0x641750, 0x642320, 0x6464F0)}
    assert {f['va'] for f in supplement['functions']} == {'0x641590', '0x646590', '0x6294d0'}
    assert {f['va'] for f in constructor['functions']} == {'0x641550'}
    exports = (raw, supplement, constructor)
    functions = [f for source in exports for f in source['functions']]
    bridges = [b for source in exports for b in source['thunks']]
    assert all(source['disk_sha256'] == SHA for source in exports)
    declared_bytes = ranges = instructions = direct_calls = 0
    for function in functions:
        transcript.append('// 当前函数 ' + function['va'])
        independent_instructions = []
        for span in function['chunk_byte_ranges']:
            declared_bytes += len(compare(span))
            ranges += 1
        for span in function['byte_ranges']:
            value = compare(span)
            decoded = list(decoder.disasm(value, int(span['va'], 16)))
            assert sum(ins.size for ins in decoded) == len(value)
            independent_instructions.extend(decoded)
            ranges += 1
        assert [ins.address for ins in independent_instructions] == [int(row['va'], 16)
                                                                   for row in function['assembly']]
        assert [ins.address for ins in independent_instructions if ins.mnemonic == 'call'] == [
            int(call['site'], 16) for call in function['calls']]
        for record in function['assembly']:
            append(decode(int(record['va'], 16)))
            instructions += 1
        for call in function['calls']:
            ins = decode(int(call['site'], 16))
            assert ins.mnemonic == 'call'
            if call['target'] is not None:
                assert ins.operands[0].type == X86_OP_IMM
                assert ins.operands[0].imm == int(call['target'], 16)
                direct_calls += 1
    for bridge in bridges:
        value = compare(bridge)
        ins = decode(int(bridge['va'], 16))
        assert value[0] == 0xE9 and ins.size == len(value) == 5
        assert ins.mnemonic == 'jmp' and ins.operands[0].imm == int(bridge['target'], 16)

    context = load(HERE / 'avatar_context.json')
    verified = load(HERE / 'avatar_context_verified.json')
    assert verified['source_sha256'] == source_hashes[(HERE / 'avatar_context.json').relative_to(ROOT).as_posix()]
    assert verified['disk_sha256'] == SHA
    literals, context_instructions = {}, 0
    for string in context['literals']:
        value = compare(string, 'hex', 'target')
        content = bytes.fromhex(string['content_hex'])
        assert string['string_type'] == 0 and string['strict_c_string']
        assert value == content + b'\0' and content and all(32 <= b <= 126 for b in content)
        literals[string['target']] = content.decode('ascii')
    for probe in context['data']:
        value = compare(probe, 'hex')
        assert probe['first_nul'] == value.find(b'\0')
        if probe['ascii_candidate_hex'] is not None:
            assert value[:probe['first_nul']].hex() == probe['ascii_candidate_hex']
    for window in context['windows'] + context['incoming']:
        transcript.append('// 导航 ' + window['site'])
        for row in window['context']:
            value = compare(row, 'hex')
            ins = decode(int(row['va'], 16))
            assert ins.size == len(value) and ins.bytes == value
            append(ins)
            context_instructions += 1

    supplement_context = load(HERE / 'supplement_context.json')
    for bridge in supplement_context['data']:
        value = compare(bridge, 'hex')
        ins = decode(int(bridge['va'], 16))
        assert value[0] == 0xE9 and ins.size == len(value) == 5
        assert ins.mnemonic == 'jmp' and ins.operands[0].imm == int(bridge['target'], 16)
        bridges.append(bridge)
    for window in supplement_context['windows'] + supplement_context['incoming']:
        transcript.append('// 补充导航 ' + window['site'])
        for row in window['context']:
            value = compare(row, 'hex')
            ins = decode(int(row['va'], 16))
            assert ins.size == len(value) and ins.bytes == value
            append(ins)
            context_instructions += 1

    historical = []
    for relative, address, mode in (
        ('TeachMode对象与消费者/证据/teachmode_raw.json', 0x627E70, 'chunks'),
        ('MapView配置记录与预览消费/证据/functions_raw.json', 0x622D50, 'chunk_byte_ranges'),
        ('游戏时间与计时调度/证据/functions.json', 0x641EE0, 'chunk_byte_ranges'),
        ('图像运行时接口/证据/draw_mapping_dependencies.json', 0x6DAA10, 'chunk_byte_ranges'),
        ('文本段键解析与预处理/证据/functions_raw.json', 0x819250, 'chunk_byte_ranges'),
        ('文本段键解析与预处理/证据/functions_raw.json', 0x819470, 'chunk_byte_ranges'),
        ('文本段键解析与预处理/证据/functions_raw.json', 0x819660, 'chunk_byte_ranges'),
        ('角色与精灵动画/证据/角色精灵_IDA原始导出.json', 0x642740, 'legacy')):
        source = load(ROOT / 'docs/逆向资料/专题' / relative)
        function = next(f for f in source['functions'] if int(f.get('va', f.get('address')), 16) == address)
        spans = function['chunks'] if mode == 'legacy' else function[mode]
        transcript.append('// 历史复用 ' + hex(address))
        summary = dict(va=hex(address), source='docs/逆向资料/专题/' + relative, chunks=[], instructions=0)
        for span in spans:
            if mode == 'legacy':
                ea = int(span['start'], 16)
                value = read(ea, len(bytes.fromhex(span['bytes_hex'])))
                assert value.hex() == span['bytes_hex'].lower()
                assert digest(value) == span['sha256'].lower()
            else:
                ea = int(span['va'], 16)
                value = compare(span)
            decoded = list(decoder.disasm(value, ea))
            assert sum(ins.size for ins in decoded) == len(value)
            summary['chunks'].append(dict(va=hex(ea), size=len(value), sha256=digest(value)))
            summary['instructions'] += len(decoded)
            for ins in decoded:
                append(ins)
        historical.append(summary)

    resources = load(HERE / 'resources.json')
    folder_files = {path.relative_to(ROOT).as_posix() for path in (ROOT / 'Avatar').iterdir()
                    if path.is_file() and path.suffix.lower() in ('.avt', '.kpd')}
    assert folder_files == {row['path'] for row in resources['files']}
    resource_summary = []
    frame_counts, avatar_prop_counts = Counter(), Counter()
    avatar_names, direction_names, sparse_props = [], [], []
    section_gaps, nonstrict_coordinates, positive_props = [], [], []
    avatar_image_values, coord_values = [], []
    for row in resources['files']:
        packed_blob = (ROOT / row['path']).read_bytes()
        assert digest(packed_blob) == row['source_sha256'] and len(packed_blob) == row['source_size']
        assert packed_blob.hex() == row['source_hex']
        key = packed_blob[0]
        packed = bytes((b - key) & 255 for b in packed_blob[1:])
        size, compressed = struct.unpack_from('<II', packed)
        assert compressed == len(packed) - 8 and 0 < size <= 16 * 1024 * 1024
        plain = lzokay.decompress(packed[8:], size)
        lexical = row['lexical']
        assert key == row['key'] and len(packed) == row['packed_size'] and compressed == row['compressed_size']
        assert digest(packed) == row['packed_sha256'] and digest(packed[8:]) == row['compressed_sha256']
        assert len(plain) == size == lexical['decoded_size']
        assert digest(plain) == lexical['decoded_sha256'] and plain.hex() == lexical['decoded_hex']
        cursor, lines, sections_out, entries = 0, [], [], []
        section_index, section = -1, None
        for number, line in enumerate(plain.splitlines(keepends=True), 1):
            lines.append(dict(number=number, offset=cursor, size=len(line), hex=line.hex()))
            content = line.rstrip(b'\r\n')
            stripped = content.strip(b' \t')
            if stripped.startswith(b'[') and stripped.endswith(b']'):
                section_index += 1
                section = stripped[1:-1]
                sections_out.append(dict(index=section_index, line=number, offset=cursor,
                                         hex=section.hex(), ascii=section.decode('ascii') if section.isascii() else None))
            elif b'=' in content:
                field, value = content.split(b'=', 1)
                field_clean = field.strip(b' \t')
                entries.append(dict(line=number, line_offset=cursor, section_index=section_index,
                                    section_hex=section.hex() if section is not None else None,
                                    key_hex=field.hex(), key_ascii=field_clean.decode('ascii') if field_clean.isascii() else None,
                                    value_offset=cursor + len(field) + 1, value_hex=value.hex()))
            cursor += len(line)
        assert cursor == len(plain) and lines == lexical['lines'] and sections_out == lexical['sections']
        assert len(entries) == len(lexical['entries'])
        for independent, original in zip(entries, lexical['entries']):
            assert all(original[k] == v for k, v in independent.items())
            clean_value = bytes.fromhex(independent['value_hex']).strip(b' \t')
            assert ('decimal_literal' in original) == bool(re.fullmatch(rb'[+-]?[0-9]+', clean_value))
            if 'decimal_literal' in original:
                assert original['decimal_literal'] == int(clean_value)
            for codec, candidate in original['decoding_candidates'].items():
                raw_value = bytes.fromhex(independent['value_hex']).lstrip(b' \t')
                try:
                    decoded = raw_value.decode(codec)
                    assert candidate['text'] == decoded and candidate['roundtrip'] == (decoded.encode(codec) == raw_value)
                except UnicodeError:
                    assert candidate == {'roundtrip': False}
        duplicate_lines = {}
        for entry in entries:
            duplicate_lines.setdefault((entry['section_index'], entry['key_hex']), []).append(entry['line'])
        duplicates = [dict(section_index=s, key_hex=k, lines=v)
                      for (s, k), v in duplicate_lines.items() if len(v) > 1]
        assert duplicates == lexical['duplicate_keys']
        if row['path'].endswith('.avt'):
            frames = [int(bytes.fromhex(entry['value_hex']).strip()) for entry in entries
                      if entry['key_ascii'] == 'frame']
            frame_counts.update(frames)
            names = [section_row['ascii'] for section_row in sections_out]
            expected_names = {'DIR_%d_PIC_%d' % (direction, pic)
                              for direction in range(4) for pic in range(26)}
            missing = sorted(expected_names - set(names))
            duplicated = {name: count for name, count in Counter(names).items() if count > 1}
            if missing or duplicated:
                section_gaps.append(dict(path=row['path'], missing=missing, duplicated=duplicated))
            for entry in entries:
                if re.fullmatch(r'pos[0-9]+', entry['key_ascii']):
                    value = bytes.fromhex(entry['value_hex']).strip(b' \t')
                    if not re.fullmatch(rb'[+-]?[0-9]+[ \t]*,[ \t]*[+-]?[0-9]+', value):
                        nonstrict_coordinates.append(dict(path=row['path'], line=entry['line'],
                                                          hex=value.hex()))
        else:
            assert row['path'] == 'Avatar/AvatList.kpd'
            for section_row in sections_out:
                name = section_row['ascii']
                if re.fullmatch(r'AVATAR_[0-9]+', name):
                    avatar_names.append(name)
                    coord_values.extend(bytes.fromhex(entry['value_hex']).strip(b' \t').decode('ascii')
                                        for entry in entries if entry['section_index'] == section_row['index']
                                        and entry['key_ascii'] == 'coord')
                    props = [entry['key_ascii'] for entry in entries
                             if entry['section_index'] == section_row['index']
                             and re.fullmatch(r'prop[0-9]+', entry['key_ascii'])]
                    if props != ['prop%d' % i for i in range(len(props))]:
                        sparse_props.append(dict(section=name, keys=props))
                    avatar_prop_counts[len(props)] += 1
                    for entry in entries:
                        if (entry['section_index'] == section_row['index']
                                and re.fullmatch(r'prop[0-9]+', entry['key_ascii'])):
                            value = int(bytes.fromhex(entry['value_hex']).strip())
                            if value > 0:
                                positive_props.append(value)
                elif re.fullmatch(r'AVAT_[0-9]+_DIR_[0-9]+', name):
                    direction_names.append(name)
                    images = [bytes.fromhex(entry['value_hex']).strip(b' \t').decode('ascii')
                              for entry in entries if entry['section_index'] == section_row['index']
                              and entry['key_ascii'] in ('normal', 'black', 'dogbite', 'frost')]
                    assert len(images) == 4
                    avatar_image_values.extend(images)
        resource_summary.append(dict(path=row['path'], decoded_size=size, sections=len(sections_out),
                                     entries=len(entries), duplicate_keys=duplicates))

    assert avatar_names == ['AVATAR_%d' % i for i in range(157)]
    assert set(direction_names) == {'AVAT_%d_DIR_%d' % (i, j) for i in range(157) for j in range(4)}
    assert len(avatar_image_values) == 2512 and len(set(avatar_image_values)) == 2344
    assert all(value.startswith('other_') for value in avatar_image_values)
    assert set(coord_values) == {'zb%03d' % i for i in range(5)}

    anchor_specs = {
        0x6415C5: 'c7048affffffff', 0x64163B: 'c7800001000000000000',
        0x6465A1: '8b00', 0x64155E: '68c0090000', 0x641569: 'e86deafcff',
        0x6419DC: '898884000000', 0x641B31: 'eb58', 0x641B74: '890491',
        0x642370: '837df410', 0x64238E: '3b4d08', 0x6423AB: '33c0',
        0x64201A: 'eba0', 0x642067: '837dd004', 0x642083: '837dcc1a',
        0x64211E: '3b55d4', 0x642190: '69f6c0090000', 0x6421A2: '69c970020000',
        0x6421AD: '6bc918', 0x6421B5: '8904ca', 0x64221C: '8944d104',
        0x642A05: '7e1c', 0x642A44: '7e1c', 0x642A83: '7e1c',
        0x642AC2: '7e1c', 0x642B01: '7e1c', 0x642A1D: '8981fc010000',
        0x642A5C: '898200020000', 0x642A9B: '898104020000',
        0x642ADA: '898208020000', 0x642B19: '89810c020000',
        0x6294E1: 'e8e562fdff', 0x6294F2: 'e806b8fdff',
        0x6245F2: 'e8beaefdff', 0x624609: 'c705f466a70000000000',
        0x64208D: '6a00', 0x64208F: '6a00', 0x642097: 'e888b4fcff',
        0x6420C5: 'e86b62fcff', 0x64214C: 'e8d773fcff',
    }
    semantic_anchors = []
    for ea, expected in anchor_specs.items():
        ins = decode(ea)
        assert ins.bytes.hex() == expected
        semantic_anchors.append(dict(site_va=hex(ea), hex=expected,
                                     text=ins.mnemonic + ' ' + ins.op_str))
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    author_document_hashes, manifest_records = {}, []
    if args.final:
        manifest = load(HERE.parent / '函数审阅清单.json')
        assert manifest['pe_sha256'] == SHA
        assert {int(row['va'], 16) for row in manifest['functions']} == {
            0x641650, 0x6416B0, 0x6416E0, 0x641750, 0x642320, 0x6464F0,
            0x6294D0, 0x641590, 0x646590, 0x641550,
            0x627E70, 0x642740, 0x641EE0, 0x6DAA10, 0x622D50}
        assert manifest['status_counts'] == dict(Counter(row['status'] for row in manifest['functions']))
        for row in manifest['functions']:
            assert (HERE.parent / row['document']).is_file()
            pointer = row['evidence_pointer']
            candidates = []
            for relative in row['evidence']:
                candidate_path = (HERE.parent / relative).resolve()
                if candidate_path.suffix == '.json':
                    source = load(candidate_path)
                    value = source
                    try:
                        for segment in pointer.split('/')[1:]:
                            value = value[int(segment)] if isinstance(value, list) else value[segment]
                    except (KeyError, IndexError, ValueError):
                        continue
                    if int(value.get('va', value.get('address', '0')), 16) == int(row['va'], 16):
                        candidates.append(value)
            assert len(candidates) == 1, row['va']
            source_function = candidates[0]
            source_chunks = source_function.get('chunk_byte_ranges', source_function.get('chunks'))
            assert row['chunks'] == source_chunks, row['va']
            if 'assembly' in source_function:
                assert row['instructions'] == len(source_function['assembly']), row['va']
            manifest_records.append(dict(va=row['va'], status=row['status'], evidence_pointer=pointer))
        assert len({row['va'] for row in manifest_records}) == len(manifest_records)
        for path in HERE.parent.glob('*.txt'):
            if path.name != '06_独立审阅.txt':
                author_document_hashes[path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())
    result = dict(status='PASS' if args.final else 'PRELIMINARY', pe_sha256=SHA, capstone_version=capstone.__version__,
                  new_functions=len(functions), declared_bytes=declared_bytes, checked_ranges=ranges,
                  instructions=instructions, direct_calls=direct_calls, bridges=len(bridges),
                  literals=literals, context_instructions=context_instructions, historical=historical,
                  resource_files=len(resource_summary), resources=resource_summary, source_hashes=source_hashes,
                  frame_counts=dict(frame_counts), avatar_prop_counts=dict(avatar_prop_counts),
                  avatar_names=avatar_names, direction_names=direction_names,
                  sparse_props=sparse_props,
                  avatar_image_entries=len(avatar_image_values), unique_avatar_images=len(set(avatar_image_values)),
                  coord_values=sorted(set(coord_values)),
                  section_gaps=section_gaps, nonstrict_coordinates=nonstrict_coordinates,
                  positive_prop_entries=len(positive_props),
                  duplicated_positive_props={str(value): count for value, count in Counter(positive_props).items()
                                             if count > 1},
                  semantic_anchors=semantic_anchors,
                  manifest_records=manifest_records, author_document_hashes=author_document_hashes,
                  scope='独立离线逐块/逐指令/资源原字节核验；语义另审，不启动游戏')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript) + '\n', 'utf-8')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps({k: result[k] for k in ('status', 'new_functions', 'declared_bytes', 'checked_ranges', 'instructions',
                                           'direct_calls', 'bridges', 'context_instructions', 'resource_files')}))


if __name__ == '__main__':
    main()
