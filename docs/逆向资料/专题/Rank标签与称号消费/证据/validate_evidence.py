"""以磁盘PE复核主体与导航；虚拟全局和IAT差异单列，不混为主体失败。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
EXPORTS = ('rank_core_raw.json', 'rank_supplement_raw.json', 'rank_leaves_raw.json')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    errors, navigation_differences, source_reports = [], [], []
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != EXPECTED_SHA:
        errors.append('当前EXE摘要不符')
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    if blob[:2] != b'MZ' or blob[pe:pe + 4] != b'PE\0\0':
        raise ValueError('目标不是PE')
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count, optional = struct.unpack_from('<H', blob, pe + 6)[0], struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional + index * 40
        _, rva, size, offset = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((base + rva, size, offset))

    def disk(ea, size):
        for start, length, offset in sections:
            if 0 <= ea - start and ea - start + size <= length:
                return blob[offset + ea - start:offset + ea - start + size]
        return None

    ranges, bridges, calls = [], [], []
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True

    def check_range(row, label):
        actual = disk(int(row['va'], 16), row['size'])
        if (actual is None or row['matching'] is not True or
                row['idb_hex'] != actual.hex() or row['disk_hex'] != actual.hex()):
            errors.append(label + ': 主体字节不一致')
        ranges.append((row['va'], row['size']))
        return actual

    def check_bridge(row, label):
        raw = check_range(row, label)
        if raw is None or len(raw) != 5 or raw[0] != 0xE9:
            errors.append(label + ': 桥不是E9')
        elif int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True) != int(row['target'], 16):
            errors.append(label + ': 桥目标不符')
        bridges.append(row['va'])

    def check_call(row, label):
        site, target = int(row['site'], 16), int(row['target'], 16)
        raw = disk(site, 15)
        insn = next(decoder.disasm(raw, site, count=1), None) if raw else None
        op = insn.operands[0] if insn and insn.operands else None
        direct = op and op.type == X86_OP_IMM and op.imm == target
        iat = op and op.type == X86_OP_MEM and op.mem.base == op.mem.index == 0 and op.mem.disp == target
        if not insn or insn.mnemonic != 'call' or not (direct or iat):
            errors.append(label + ': 调用地址不符')
        final, chain = target, []
        while final not in chain and len(chain) < 16:
            raw = disk(final, 5)
            if raw is None or raw[0] != 0xE9:
                break
            chain.append(final)
            final += 5 + int.from_bytes(raw[1:], 'little', signed=True)
        if final != int(row['implementation'], 16) or [hex(x) for x in chain] != row['thunks']:
            errors.append(label + ': 桥链不符')
        calls.append(row['site'])

    def check_functions(data, label, selected=None):
        if data['disk_sha256'] != digest:
            errors.append(label + ': 版本摘要不符')
        functions = data['functions']
        if selected is not None:
            functions = [f for f in functions if f['va'] in selected]
        for f in functions:
            prefix = label + '/' + f['va']
            for kind in ('byte_ranges', 'chunk_byte_ranges'):
                for row in f[kind]:
                    check_range(row, prefix + '/' + kind)
            if len(f['declared_chunks']) != len(f['chunk_byte_ranges']):
                errors.append(prefix + ': 声明块数量不符')
            for chunk, row in zip(f['declared_chunks'], f['chunk_byte_ranges']):
                if row['va'] != chunk['start_va'] or row['size'] != int(chunk['end_va'], 16) - int(chunk['start_va'], 16):
                    errors.append(prefix + ': 声明块边界不符')
            for call in f['calls']:
                check_call(call, prefix)
        for row in data['thunks']:
            check_bridge(row, label)
        source_reports.append(dict(source=label, functions=len(functions),
                                   declared_bytes=sum(r['size'] for f in functions for r in f['chunk_byte_ranges']),
                                   instruction_ranges_bytes=sum(r['size'] for f in functions for r in f['byte_ranges'])))

    for name in EXPORTS:
        check_functions(load(HERE / name), name)
    navigation = load(HERE / 'rank_navigation_raw.json')
    if navigation['disk_sha256'] != digest:
        errors.append('导航版本摘要不符')
    for bridge in navigation['bridges']:
        check_bridge(bridge, '导航桥')
    window_reports = []
    for window in navigation['windows']:
        check_range(window['raw_range'], '窗口')
        cursor, end = int(window['start_va'], 16), int(window['end_va'], 16)
        noncode = []
        for row in window['items']:
            raw = check_range(row, '窗口item')
            ea = int(row['va'], 16)
            if ea != cursor or ea + row['size'] > end or row['declared_owner'] != window['expected_owner']:
                errors.append('窗口item连续性或owner不符')
            cursor = ea + row['size']
            if row['is_code'] and raw:
                instructions = list(decoder.disasm(raw, ea))
                if len(instructions) != 1 or instructions[0].size != len(raw):
                    errors.append('窗口CPU解码长度不符')
            else:
                noncode.append(row['va'])
        if cursor != end:
            errors.append('窗口item未覆盖末尾')
        for call in window['calls']:
            check_call(call, '窗口调用')
        window_reports.append(dict(start_va=window['start_va'], end_va=window['end_va'],
                                   items=len(window['items']), noncode=noncode))
    confirmed_strings = []
    for row in navigation['data_refs']:
        raw = row['raw']
        actual = disk(int(raw['va'], 16), raw['size'])
        if raw['disk_hex'] != (actual.hex() if actual is not None else None):
            errors.append('导航磁盘字节不符')
        if row['confirmed_c_string']:
            check_range(raw, '确认字串')
            if row['string_type'] != 0 or raw['idb_hex'] != row['string_hex'] + '00':
                errors.append('确认字串门不符')
            confirmed_strings.append(row['target'])
        elif actual is None or raw['idb_hex'] != actual.hex():
            navigation_differences.append(dict(site=row['site'], target=row['target'],
                                               kind='无磁盘映射' if actual is None else 'IDB与磁盘导航不同'))
    for row in navigation['global_slots']:
        actual = disk(int(row['va'], 16), row['size'])
        if row['disk_hex'] != (actual.hex() if actual is not None else None):
            errors.append('全局导航磁盘字节不符')
        if actual is None or row['idb_hex'] != actual.hex():
            navigation_differences.append(dict(target=row['va'], kind='全局四字节导航无匹配磁盘'))
    reuse = load(HERE / 'rank_reuse_and_num_raw.json')
    if reuse['num_idb_hex'] != disk(0xA2A9D8, 4).hex() or reuse['num_idb_hex'] != '6e756d00':
        errors.append('num原字节不符')
    if reuse['consumer_idb_hex'] != disk(0x755B92, 5).hex() or disk(0x755B92, 5) != b'\x68\xd8\xa9\xa2\x00':
        errors.append('num直接push现场不符')
    for row in navigation['reused_sources'] + reuse['reused_sources']:
        if hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() != row['sha256']:
            errors.append('复用原证哈希变化:' + row['path'])
    parser_path = ROOT / 'docs/逆向资料/专题/文本段键解析与预处理/证据/functions_raw.json'
    check_functions(load(parser_path), '复用段键解析', {'0x8191d0', '0x819220', '0x819250', '0x819470', '0x819660'})
    resource, independent = load(HERE / 'rank_resource_raw.json'), load(HERE / 'independent_resource.json')
    if independent['status'] != 'PASS':
        errors.append('资源独审未通过')
    for key in ('source_sha256', 'source_size', 'decoded_hex', 'decoded_sha256', 'decoded_size', 'tail_size'):
        if resource[key] != independent[key]:
            errors.append('资源独立解包不符:' + key)
    source = (ROOT / resource['source']).read_bytes()
    if hashlib.sha256(source).hexdigest() != resource['source_sha256']:
        errors.append('资源磁盘摘要不符')
    plain = bytes.fromhex(resource['decoded_hex'])
    if hashlib.sha256(plain).hexdigest() != resource['decoded_sha256'] or len(plain) != resource['decoded_size']:
        errors.append('明文字节摘要不符')
    if b''.join(bytes.fromhex(r['raw_hex']) for r in resource['rows']) != plain:
        errors.append('逐行原字节不连续')
    expected = [name for i in range(1, 6) for name in (f'RANK{i}', 'TITLE0', 'TITLE1', 'TITLE2')] + ['MORE', 'RULE']
    if [r['name_ascii'] for r in resource['segments']] != expected:
        errors.append('资源段序不符')
    manifest = load(HERE.parent / '函数审阅清单.json')
    for group in ('functions', 'rechecked_sources', 'code_windows', 'reused_producers'):
        for row in manifest[group]:
            if any(not row.get(k) for k in ('va', 'status', 'conclusion', 'unknown', 'evidence')):
                errors.append('清单字段缺失:' + row.get('va', '?'))
            path, _, pointer = row['evidence'].partition('#')
            selected = load(HERE.parent / path)
            for token in pointer.strip('/').split('/'):
                selected = selected[int(token)] if isinstance(selected, list) else selected[token]
            if group == 'code_windows':
                if (selected['expected_owner'] != row['va'] or
                        selected['start_va'] != row.get('start_va') or
                        selected['end_va'] != row.get('end_va') or
                        row['status'] != '大型UI限定字段窗口'):
                    errors.append('清单窗口所属入口或局部范围不符:' + row['va'])
            elif selected.get('va') != row['va']:
                errors.append('清单证据指针地址不符:' + row['va'])
            if not (HERE.parent / row['document']).is_file():
                errors.append('清单正文不存在')
    for path in HERE.parent.glob('*.txt'):
        if any(line.strip() and not line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines()):
            errors.append('正文注释排版不符:' + path.name)
    report = dict(success=not errors, disk_sha256=digest, errors=errors, sources=source_reports,
                  manifest_sha256=hashlib.sha256((HERE.parent / '函数审阅清单.json').read_bytes()).hexdigest(),
                  manifest_windows=[{k: row[k] for k in ('va', 'start_va', 'end_va', 'status')}
                                    for row in manifest['code_windows']],
                  author_document_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                          for path in sorted(HERE.parent.glob('[0-9][0-9]_*.txt'))},
                  range_records=len(ranges), unique_ranges=len(set(ranges)),
                  bridge_records=len(bridges), unique_bridges=len(set(bridges)),
                  call_records=len(calls), unique_call_sites=len(set(calls)), windows=window_reports,
                  confirmed_c_strings=len(set(confirmed_strings)), additional_confirmed_num=True,
                  navigation_differences=navigation_differences, resource_rows=len(resource['rows']),
                  resource_segments=len(resource['segments']),
                  resource_fields=sum(len(s['fields']) for s in resource['segments']))
    (HERE / 'validation_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('success', 'range_records', 'unique_bridges', 'unique_call_sites', 'errors')}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == '__main__':
    raise SystemExit(main())
