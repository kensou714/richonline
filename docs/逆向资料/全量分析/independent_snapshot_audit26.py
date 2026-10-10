"""第二十六批中央独审：原证适配、资源数据、固定终稿与归档增量独立核验。"""
import argparse
import hashlib
import importlib.util
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent
BASE_PATH = HERE / 'independent_snapshot_audit25.py'
assert hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() == '2accda1486c95b5c853c90e8cb96a968c56477e0902e74eee522b0df7445c8e3'
SPEC = importlib.util.spec_from_file_location('frozen_audit25', BASE_PATH)
PREVIOUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREVIOUS)
BASE = PREVIOUS.BASE
load, digest, pointer, walk, va = BASE.load, BASE.digest, BASE.pointer, BASE.walk, BASE.va
Image, PE_SHA = BASE.Image, BASE.PE_SHA
READY = True
BUILD = 'Build配置与建筑资料消费'
MAP = '地图地产候选筛选'
MOUSE = 'SysRes鼠标资源加载'
ROLE = '角色文本选择与控件消费'
TOPICS = {BUILD: {'fresh': 6, 'reused': 2}, MAP: {'fresh': 5, 'reused': 0},
          MOUSE: {'fresh': 2, 'reused': 0}, ROLE: {'fresh': 2, 'reused': 2}}
BASE.TOPICS = TOPICS
FRESH = {BUILD: ['0x7e8a20', '0x7e8a40', '0x7e8a90', '0x629610', '0x71ed30', '0x693ee0'],
         MAP: ['0x7e4660', '0x7e4750', '0x7e4830', '0x7e4930', '0x7e4a30'],
         MOUSE: ['0x6bab70', '0x6db9d0'], ROLE: ['0x6f4db0', '0x7014a0']}
BUILD_EXTRA = ['0x7eccf0', '0x63f330', '0x7acba0']
MAP_BRIDGES = ['0x60be04', '0x60a752', '0x606b52', '0x60da1a', '0x601e27', '0x5ff0be',
               '0x60b576', '0x605027', '0x5ff0eb', '0x602755', '0x60f194', '0x60a324', '0x60b21f', '0x60a02c']
MOUSE_OLD = ['0x627760', '0x6278f0', '0x6baac0', '0x6bad80', '0x6bab00', '0x629890',
             '0x629ed0', '0x91f6d0', '0x9206d0', '0x91fbb0']
ROLE_OLD = ['0x756460', '0x762e10', '0x627c20', '0x6dba40', '0x6276a0', '0x627760',
            '0x646610', '0x6fa7f0', '0x646590', '0x8e1c70']
REVIEWED_VAS = {BUILD: FRESH[BUILD] + ['0x628900', '0x694b30'] + BUILD_EXTRA,
                MAP: FRESH[MAP] + MAP_BRIDGES, MOUSE: FRESH[MOUSE] + MOUSE_OLD,
                ROLE: FRESH[ROLE] + ROLE_OLD}
FINAL_FILES = {BUILD: ('函数审阅清单.json', 'independent_validation.json'),
               MAP: ('函数审阅清单.json', 'independent_validation.json'),
               MOUSE: ('函数审阅清单.json', 'independent_review_validation.json'),
               ROLE: ('函数审阅清单.json', 'independent_validation.json')}
MAP_WINDOWS = [(0x7c66d2, 0x7c673f), (0x7c67df, 0x7c6800), (0x7c8bac, 0x7c8bc9),
               (0x7c8da2, 0x7c8e6c), (0x7c8f5e, 0x7c9259), (0x7ca1aa, 0x7ca249), (0x7ca8cb, 0x7cab3c)]


def check_original_bytes(record, image):
    count = 0
    for row, _ in walk(record):
        if ('idb_hex' in row or 'ida_hex' in row) and 'disk_hex' in row:
            if 'idb_hex' in row and 'matching' in row and ('sha256' in row or row['disk_hex'] is None):
                image.check(row, row.get('start_va', row.get('va', row.get('address'))))
            else:
                BASE.byte_record_check(row, image)
            count += 1
        elif all(k in row for k in ('va', 'hex', 'size')):
            assert image.read(row['va'], row['size']).hex() == row['hex']
            count += 1
    return count


def build_adapter(raw, sha, source):
    rows = []
    for i, old in enumerate(raw['functions']):
        chunks = [dict(c, va=c['start_va']) for c in old['chunk_byte_ranges']]
        rows.append(dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'],
            status='仅导出；语义分级另见清单', assembly=[dict(x, va=x['site_va']) for x in old['assembly']],
            pseudocode=old['pseudocode'], decompile_error=old['decompile_error'], byte_ranges=chunks,
            bytes_match_disk=True, declared_chunks=[dict(start_va=c['start_va'],
                end_va=hex(va(c['start_va']) + c['size']), is_main=c['start_va'] == old['seed_va']) for c in chunks],
            source=source, source_sha256=sha, json_pointer=f'/functions/{i}'))
    return dict(schema='richonline-formal-functions-1', disk_sha256=PE_SHA, source_sha256=sha,
        functions=rows, scope='无损机械适配；完整汇编/原类型伪码/全部声明块保留',
        thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']])


def build_check(directory, image):
    for name, expected in [('bounded_raw.json', FRESH[BUILD]), ('dependency/bounded_raw.json', BUILD_EXTRA)]:
        path = directory / '证据' / name
        raw = load(path)
        assert [r['seed_va'] for r in raw['functions']] == expected and raw['disk_sha256'] == PE_SHA
        formal = load(path.with_name('formal_functions.json'))
        assert formal == build_adapter(raw, digest(path)[1], '证据/' + name)
        check_original_bytes(raw, image)
    audit = load(directory / '证据/reused_audit.json')
    assert audit['disk_sha256'] == PE_SHA and len(audit['references']) == 39
    expected_vas = {'0x628900', '0x629c90', '0x6fa7f0', '0x8e15b0', '0x8e2c10', '0x694b30',
        '0x622d50', '0x63e100', '0x629e10', '0x63e210', '0x63e990', '0x63f300', '0x7f85c0',
        '0x8054a0', '0x627760', '0x6dba40', '0x6fa840', '0x6fa890', '0x6fa8e0', '0x8e1c70',
        '0x8191d0', '0x819220', '0x819250', '0x819470', '0x819660', '0x8198e0', '0x81ad50',
        '0x81ad80', '0x81b7f0', '0x627160', '0x64f000', '0x8190b0', '0x81b4c0', '0x627120',
        '0x627140', '0x81ad10', '0x91bd80', '0x91bd30', '0x91f7e0'}
    assert {r['owner_va'] for r in audit['references']} == expected_vas
    for row in audit['references']:
        path = ROOT / row['source']
        assert digest(path)[1] == row['source_sha256']
        old = pointer(load(path), row['json_pointer'])
        assert old.get('va', old.get('address')) == row['owner_va']
        chunks = old.get('chunk_byte_ranges', old.get('byte_ranges', old.get('chunks')))
        wanted = []
        for c in chunks:
            start = c.get('start_va', c.get('va'))
            data = image.read(start, c['size'])
            assert data.hex() == c['disk_hex']
            wanted.append(dict(start_va=start, end_va=hex(va(start) + c['size']), size=c['size'],
                               sha256=hashlib.sha256(data).hexdigest()))
        assert row['chunks'] == wanted
        check_original_bytes(old, image)
        assert not PREVIOUS.is_review(row)
    assert len(audit['supplemental']) == 3
    for index, row in enumerate(audit['supplemental']):
        source = directory / '证据' / row['source']
        assert row['source'] == 'dependency/bounded_raw.json' and row['source_sha256'] == digest(source)[1]
        assert row['json_pointer'] == f'/functions/{index}'
        old = pointer(load(source), row['json_pointer'])
        assert old['seed_va'] == row['owner_va'] == BUILD_EXTRA[index]
        assert row['chunks'] == [dict(start_va=c['start_va'], end_va=hex(va(c['start_va']) + c['size']),
            size=c['size'], sha256=c['sha256']) for c in old['chunk_byte_ranges']]
    return dict(fresh=6, dependencies=3, historical_contracts=39)


def bound_source(directory, row):
    source = row['source']
    path = (directory if source['base'] == 'topic' else ROOT) / source['path']
    assert digest(path)[1] == source['sha256']
    return pointer(load(path), source['json_pointer'])


def map_check(directory, image):
    path = directory / '证据/bounded_raw.json'
    raw, sha = load(path), digest(path)[1]
    formal = load(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and formal['raw_sha256'] == sha
    assert len(formal['functions']) == len(raw['functions']) == 5
    for index, (old, new) in enumerate(zip(raw['functions'], formal['functions'])):
        assert new == dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'],
            source=dict(base='topic', path='证据/bounded_raw.json', sha256=sha, json_pointer=f'/functions/{index}'),
            source_record=old, pseudocode=old['pseudocode'], decompile_error=old['decompile_error'],
            assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in old['assembly']],
            chunk_byte_ranges=old['chunk_byte_ranges'], coverage_origin='本批新增完整主体',
            status='原证无损适配；语义级别见清单')
    assert len(formal['dependency_contracts']) == 18
    assert [r['va'] for r in formal['dependency_contracts']] == [
        '0x695010', '0x695040', '0x63e290', '0x63e2d0', '0x6bc0d0', '0x63f500', '0x63f5b0',
        '0x63e960', '0x63e3e0', '0x63e410', '0x63ec30', '0x692940', '0x692b00', '0x693da0',
        '0x63f2d0', '0x7e3f30', '0x7e4020', '0x91f6d0']
    for row in formal['dependency_contracts']:
        original = bound_source(directory, row)
        assert row['source_record'] == original and row['va'] == original['va']
        assert not PREVIOUS.is_review(row)
        check_original_bytes(original, image)
    windows = formal['caller_windows']
    assert [(va(r['start_va']), va(r['end_va'])) for r in windows] == MAP_WINDOWS
    for row in windows:
        old = bound_source(directory, row)
        assert row['source']['path'] == '专题/回合等待与自动选择/证据/pending_functions.json'
        assert row['source']['json_pointer'] == '/functions/0x7c6640'
        assert row['owner_va'] == old['address'] == '0x7c6640'
        lo, hi = va(row['start_va']), va(row['end_va'])
        start, end = row['source_assembly_start'], row['source_assembly_end_exclusive']
        selected = old['assembly'][start:end]
        assert va(selected[0][0]) == lo and va(old['assembly'][end][0]) == hi
        assert row['source_rows'] == selected and row['assembly'] == [dict(va=a, text=t) for a, t in selected]
        assert row['source_byte_offset'] == lo - va(old['address'])
        previous_bytes = bytes.fromhex(old['bytes'])[row['source_byte_offset']:row['source_byte_offset'] + hi - lo]
        assert image.check(row['byte_audit']) == 'disk'
        assert previous_bytes == image.read(lo, hi - lo) == bytes.fromhex(row['byte_audit']['idb_hex'])
        assert not PREVIOUS.is_review(row)
    bridges = formal['caller_navigation_bridges']
    assert {r['va'] for r in bridges} == {'0x60ffd1', '0x6066cf', '0x60c62e', '0x608452', '0x60c43a',
                                       '0x6114d0', '0x60244e', '0x60579d', '0x60cbce'}
    for row in bridges:
        code = image.read(row['va'], 5)
        assert row['size'] == 5 and row['disk_hex'] == code.hex() and row['sha256'] == hashlib.sha256(code).hexdigest()
        assert code[0] == 0xe9 and va(row['target_va']) == va(row['va']) + 5 + struct.unpack_from('<i', code, 1)[0]
        assert 'idb_hex' not in row and not PREVIOUS.is_review(row)
    return dict(fresh=5, historical_contracts=18, caller_slices=7, offline_navigation_bridges=9)


def normalized_check(directory, image):
    fresh_scope = '本批新本体无损适配' if directory.name == MOUSE else '本批新主体完整原证；语义分级见函数审阅清单'
    path = directory / '证据/bounded_raw.json'
    raw, sha = load(path), digest(path)[1]
    formal = load(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA
    assert formal['adapter_helper_sha256'] == digest(ROOT / '专题/地图选择字段与列表消费/证据/adapt_sources.py')[1]
    assert len(formal['functions']) == len(raw['functions']) == 2
    for index, (old, new) in enumerate(zip(raw['functions'], formal['functions'])):
        assert new == PREVIOUS.normalized_record(old, path.relative_to(ROOT).as_posix(), f'/functions/{index}', sha, fresh_scope)
    reused = load(directory / '证据/reused_functions.json')
    assert reused['disk_sha256'] == PE_SHA and len(reused['functions']) == 10
    assert [r['va'] for r in reused['functions']] == (MOUSE_OLD if directory.name == MOUSE else ROLE_OLD)
    for row in reused['functions']:
        path = ROOT / row['source_path']
        assert digest(path)[1] == row['source_sha256']
        original = pointer(load(path), row['source_pointer'])
        wanted = PREVIOUS.normalized_record(original, row['source_path'], row['source_pointer'],
            row['source_sha256'], row['adaptation_scope'])
        if directory.name == MOUSE:
            for item in wanted['normalized_assembly']:
                item['normalized_item_kind'] = 'data' if item['text'].lstrip().split()[0].lower() in ('db', 'dw', 'dd', 'dq') else 'code'
        assert row == wanted
        check_original_bytes(original, image)
    return dict(fresh=2, historical_records=10)


def fixed_data_check(image):
    directory = ROOT / '专题' / MOUSE / '证据'
    rtc = load(directory / 'rtc_buffer_raw.json')
    assert rtc['disk_sha256'] == PE_SHA and rtc['schema'] == 'richonline-rtc-buffer-evidence-26-1'
    assert rtc['exporter_sha256'] == digest(directory / 'export_rtc_buffer.py')[1]
    for key, address, size in [('frame_descriptor', '0x6bad03', 8), ('variable_descriptor', '0x6bad0b', 12), ('variable_name', '0x6bad17', 6)]:
        assert rtc[key]['start_va'] == address and rtc[key]['size'] == size and image.check(rtc[key]) == 'disk'
    assert struct.unpack('<II', image.read(0x6bad03, 8)) == (1, 0x6bad0b)
    assert struct.unpack('<iII', image.read(0x6bad0b, 12)) == (-148, 128, 0x6bad17)
    assert image.read(0x6bad17, 6) == b'szTmp\0'
    assert (rtc['declared_variable_count'], rtc['ebp_relative_offset'], rtc['declared_buffer_size']) == (1, -148, 128)
    table = load(ROOT / '专题' / ROLE / '证据/switch_table/bounded_raw.json')
    assert table['disk_sha256'] == PE_SHA and not table['functions'] and not table['seeds']
    assert len(table['data_windows']) == 1
    record = table['data_windows'][0]
    assert record['start_va'] == '0x6dbdb4' and record['size'] == 48 and image.check(record) == 'disk'
    destinations = struct.unpack('<12I', image.read(0x6dbdb4, 48))
    assert destinations == (0x6dbb01, 0x6dbb45, 0x6dbb74, 0x6dbbb5, 0x6dbc0f, 0x6dbc69,
                            0x6dbcc6, 0x6dbd0a, 0x6dbd36, 0x6dba7b, 0x6dbabd, 0x6dbd77)
    return dict(rtc_bytes=26, rtc_buffer_capacity=128, image_switch_bytes=48, image_switch_entries=12)


def resource_check(image):
    audit = load(ROOT / '专题' / MOUSE / '证据/resource_audit.json')
    assert audit['status'] == 'PASS' and audit['disk_sha256'] == PE_SHA
    paths = sorted((PROJECT / 'SysRes').glob('04_*.ms'))
    assert len(paths) == audit['resource_count'] == len(audit['resources']) == 39
    for path, row in zip(paths, audit['resources']):
        data = path.read_bytes()
        assert row['path'] == path.relative_to(PROJECT).as_posix()
        assert (len(data), hashlib.sha256(data).hexdigest()) == (row['size'], row['sha256'])
        reserved, kind, count = struct.unpack_from('<3H', data)
        assert reserved == 0 and kind == row['cursor_type'] == 2 and count == len(row['entries'])
        assert row['filename_index'] == int(path.stem[3:]) and row['header_hex'] == data[:22].hex()
        for index, entry in enumerate(row['entries']):
            width, height, colors, pad, hot_x, hot_y, size, offset = struct.unpack_from('<4B2H2I', data, 6 + 16 * index)
            width, height = width or 256, height or 256
            assert pad == 0 and hot_x < width and hot_y < height
            assert offset >= 6 + count * 16 and offset + size <= len(data)
            header, dib_w, dib_h, planes, bits, compression, _, _, _, used, _ = struct.unpack_from('<IiiHHIIiiII', data, offset)
            assert header == 40 and dib_w == width and dib_h == height * 2 and planes == 1
            assert compression == 0 and bits in (1, 4, 8, 24, 32)
            palette = (used or (1 << bits)) if bits <= 8 else 0
            xor_size = ((width * bits + 31) // 32) * 4 * height
            and_size = ((width + 31) // 32) * 4 * height
            assert header + palette * 4 + xor_size + and_size == size
            assert entry == dict(width=width, height=height, hotspot=[hot_x, hot_y], resource_size=size,
                resource_offset=offset, dib_header_size=header, dib_height=dib_h, bits_per_pixel=bits,
                compression=compression, palette_entries=palette, xor_bytes=xor_size, and_bytes=and_size)
        assert max(e['resource_offset'] + e['resource_size'] for e in row['entries']) == len(data)
    imports = {r['va']: r for r in image.imports()}
    wanted = {'0xad3f38': ('USER32.dll', 'LoadImageA'), '0xad3f3c': ('USER32.dll', 'LoadCursorA'),
              '0xad3f88': ('USER32.dll', 'SetCursor'), '0xad3f8c': ('USER32.dll', 'MessageBoxA'),
              '0xad3acc': ('GDI32.dll', 'DeleteObject')}
    assert len(audit['imports']) == len(wanted)
    for row in audit['imports']:
        assert (row['dll'], row['symbol']) == wanted[row['iat_va']]
        assert (imports[row['iat_va']]['module'], imports[row['iat_va']]['name']) == wanted[row['iat_va']]
        assert image.read(row['iat_va'], 4).hex() == row['disk_iat_hex']
    build = load(ROOT / '专题' / BUILD / '证据/resource_audit.json')
    assert build['status'] == 'PASS' and build['source'] == 'Data/Build.kpd'
    data = (PROJECT / build['source']).read_bytes()
    assert (len(data), hashlib.sha256(data).hexdigest()) == (build['file_bytes'], build['source_sha256'])
    key = data[0]
    raw_size, packed_size = struct.unpack('<II', bytes((value - key) & 255 for value in data[1:9]))
    assert key == build['key'] and raw_size == build['raw_size'] and packed_size == build['packed_size']
    assert len(data) == packed_size + 9
    import lzokay
    plain = lzokay.decompress(bytes((value - key) & 255 for value in data[9:]), raw_size)
    assert len(plain) == raw_size and hashlib.sha256(plain).hexdigest() == build['plain_sha256']
    assert plain.decode('cp950').encode('cp950') == plain
    assert [r['name'] for r in build['sections']] == ['ALL'] + ['BUILD'] * 21
    for section in build['sections']:
        line = plain.splitlines()[section['source_line'] - 1]
        assert bytes.fromhex(section['raw_line_hex']) == line
        assert plain[section['source_offset']:section['source_offset'] + len(line)] == line
        for entry in section['entries']:
            payload = bytes.fromhex(entry['value_hex'])
            assert payload.decode('cp950') == entry['value']
            assert plain[entry['value_offset']:entry['value_offset'] + len(payload)] == payload
            assert plain.splitlines()[entry['source_line'] - 1] == bytes.fromhex(entry['raw_line_hex'])
    assert build['build_section_count'] == build['array_count'] == len(build['records']) == 21
    assert build['array_bytes'] == 21 * 388
    assert [r['index'] for r in build['records']] == list(range(21))
    assert [r['index'] for r in build['records'] if r['desc_present']] == list(range(11, 21))
    return dict(cursor_files=39, import_identities=5, build_sections=21, build_plain_bytes=raw_size)


def precheck():
    image = Image()
    result = {}
    for topic in TOPICS:
        directory = ROOT / '专题' / topic
        raw = load(directory / '证据/bounded_raw.json')
        assert [r['seed_va'] for r in raw['functions']] == FRESH[topic]
        ranges, owners, instructions = BASE.bounded_check(directory / '证据/bounded_raw.json', image)
        adapted = build_check(directory, image) if topic == BUILD else map_check(directory, image) if topic == MAP else normalized_check(directory, image)
        result[topic] = dict(adaptations=adapted, data_ranges=dict(ranges),
                            finite_owner_windows=owners, finite_owner_instructions=instructions)
    result[MOUSE]['fixed_metadata'] = fixed_data_check(image)
    result[BUILD]['resources'] = resource_check(image)
    return result


def final_bindings(directory):
    PREVIOUS.FINAL_FILES = FINAL_FILES
    PREVIOUS.SUPPLEMENTS = {}
    checked_count = PREVIOUS.final_bindings(directory)
    _, filename = FINAL_FILES[directory.name]
    report = load(directory / '证据' / filename)
    if directory.name == BUILD:
        for key, name in [('independent_report_sha256', '独立审阅.txt'), ('verifier_sha256', 'verify_independent.py')]:
            assert report[key] == digest(directory / '证据' / name)[1]
    # 额外正式证据必须直接出现在独审终稿或固定来源哈希中。
    pairs = {}
    for row, _ in walk(report):
        for name, value in row.items():
            if isinstance(value, str) and len(value) == 64 and Path(name).suffix in ('.json', '.txt', '.py'):
                name = name.replace('\\', '/')
                base = PROJECT if name.startswith('docs/') else ROOT if name.startswith('专题/') else directory
                target = base / name
                if not target.is_file():
                    target = directory / '证据' / name
                if target.is_file():
                    pairs.setdefault(target.resolve(), set()).add(value)
    required = {BUILD: ['证据/dependency/bounded_raw.json', '证据/dependency/formal_functions.json', '证据/resource_audit.json'],
                MAP: [], MOUSE: ['证据/rtc_buffer_raw.json', '证据/resource_audit.json'],
                ROLE: ['证据/switch_table/bounded_raw.json']}[directory.name]
    for name in required:
        path = directory / name
        values = pairs.get(path.resolve(), set())
        assert values == {digest(path)[1]}, (directory.name, name)
    return checked_count


def central_topic(directory, central, records, evidence):
    path = directory / FINAL_FILES[directory.name][0]
    manifest = load(path)
    source = path.relative_to(ROOT).as_posix()
    expected = [(row, ref) for row, ref in walk(manifest) if PREVIOUS.is_review(row)]
    addresses = [PREVIOUS.address_of(row) for row, _ in expected]
    assert len(addresses) == len(set(addresses)) and set(addresses) == set(REVIEWED_VAS[directory.name])
    for row, ref in expected:
        found = [item for item in central[PREVIOUS.address_of(row)] if item['source'] == source and item['json_pointer'] == ref]
        assert len(found) == 1 and all(found[0][key] == row[key] for key in ('status', 'conclusion'))
    prefix = directory.relative_to(ROOT).as_posix() + '/'
    assert {(row['source'], row['json_pointer']) for row in records if row['source'].startswith(prefix)} == {(source, ref) for _, ref in expected}
    forbidden_names = ('bounded_raw.json', 'dependency/bounded_raw.json', 'switch_table/bounded_raw.json', 'rtc_buffer_raw.json')
    for name in forbidden_names:
        forbidden = prefix + '证据/' + name
        assert not any(row['source'] == forbidden for row in records)
        assert not any(forbidden in row['evidence'] for row in evidence['functions'] + evidence['unrecognized_code_ranges'])
    return dict(manifest_reviews=len(expected), bound_files=final_bindings(directory))


def main():
    assert READY, '第二十六批准备阶段；四专题终稿绑定尚未冻结'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十六批推进快照.json')
    args = parser.parse_args()
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十五批推进快照.json')
    sources = {}
    for row in snapshot['source_fingerprints']:
        path = HERE / row['path']
        assert digest(path) == (row['bytes'], row['sha256'])
        assert path.name not in sources
        sources[path.name] = load(path)
    assert set(sources) == {'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json', '结构覆盖口径.json', 'archive_validation.json'}
    evidence, review, archive = (sources[name] for name in ('evidence_coverage.json', 'review_coverage.json', 'archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts'] and snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions'] == evidence['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions'] == review['unique_functions_with_explicit_reviews']
    assert len({r['va'] for r in evidence['functions']}) == len(evidence['functions'])
    assert len({r['va'] for r in review['functions']}) == len(review['functions'])
    central = {r['va']: r['reviews'] for r in review['functions']}
    records = [dict(item, function_va=r['va']) for r in review['functions'] for item in r['reviews']]
    states = Counter(item['status'] for item in records)
    assert sum(states.values()) == review['review_record_count'] == snapshot['review_record_count']
    assert dict(states) == review['raw_status_counts'] == snapshot['raw_status_counts']
    assert snapshot['structural_groups'] == sources['结构覆盖口径.json']['groups']
    assert snapshot['instruction_observation_count'] == evidence['instruction_observation_count'] == prior['instruction_observation_count']
    assert snapshot['unrecognized_code_ranges'] == evidence['unrecognized_code_ranges'] == prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows'] == evidence['navigation_windows']
    navigation = {(va(r['start_va']), va(r['end_va'])) for r in snapshot['navigation_windows']}
    assert len(navigation) == len(snapshot['navigation_windows']) == evidence['navigation_window_count']
    assert {(va(r['start_va']), va(r['end_va'])) for r in prior['navigation_windows']} <= navigation
    results = precheck()
    for topic in TOPICS:
        results[topic].update(central_topic(ROOT / '专题' / topic, central, records, evidence))
    captured = set()
    for row in archive['files']:
        assert not row['errors'] and digest(ROOT / row['path']) == (row['bytes'], row['sha256'])
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(name).suffix for name in captured)) == archive['counts']
    assert {'全量分析/independent_snapshot_audit26.py', '全量分析/independent_snapshot_audit25.py', '全量分析/independent_snapshot_audit24.py'} <= captured
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exports = [r for r in evidence['functions'] if all(s.startswith(prefixes) for s in r['evidence'])]
    reviews = [r for r in review['functions'] if all(i['source'].startswith(prefixes) for i in r['reviews'])]
    new_records = [r for r in records if r['source'].startswith(prefixes)]
    derived = dict(zip(keys, (len(exports), len(reviews), len(new_records))))
    assert changes == derived, (changes, derived)
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot, counts={k: snapshot[k] for k in keys},
        changes=changes, source_fingerprints=len(sources), captured_archive_files=len(captured),
        topics=results, navigation_windows=len(navigation), scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
