"""第二十七批中央独审：区分历史补计、当次采证与显式语义登记。"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import struct
from collections import Counter
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent


def module(name, filename, expected=None):
    path = HERE / filename
    if expected:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PREVIOUS = module('audit26_frozen', 'independent_snapshot_audit26.py',
    '4fe756b1b817bdb00f1fe048f01db16a663a5d89c9ec339942e60a18e985ab2c')
BASE, OLD = PREVIOUS.BASE, PREVIOUS.PREVIOUS
load, digest, pointer, walk, va = BASE.load, BASE.digest, BASE.pointer, BASE.walk, BASE.va
Image, PE_SHA = BASE.Image, BASE.PE_SHA
READY = True
BUILD = '建筑选择界面与许可证门'
GROUP = '资源配置分组记录生产'
PROP = '道具类别与角色适用标记生产'
LAND = '地产候选容器生产与生命周期'
TOPICS = {BUILD: {'fresh': 5, 'reused': 0}, GROUP: {'fresh': 4, 'reused': 2},
          PROP: {'fresh': 4, 'reused': 0}, LAND: {'fresh': 2, 'reused': 0}}
SEEDS = {BUILD: ['0x712980', '0x71f130', '0x71f230', '0x7cef00', '0x6a3a00'],
         GROUP: ['0x6dfa10', '0x6d76c0', '0x6d7c00', '0x6d7c30'],
         PROP: ['0x7fe7d0', '0x7fe9e0', '0x7ff1d0', '0x7ff240'], LAND: ['0x7ecd50', '0x7ecd80']}
REVIEW_COUNTS = {BUILD: 5, GROUP: 11, PROP: 4, LAND: 6}
REPORTS = {BUILD: 'independent_final_audit.json', GROUP: 'independent_validation.json',
           PROP: 'independent_validation.json', LAND: 'independent_validation27.json'}
FINAL_HASHES = {
    BUILD: ('30770d873d3e24e814b0176e30fb1789422a8445e95d8ac523c95c9361dadde2', 'verify_independent.py', '98b5b29a29e91ae2c600ef36048759e78d7acc212bf762237462e7e7e8cef0c0'),
    GROUP: ('e1421dd7cef0486463b5ccfcc8aa46ea3f48702a1ea7a688d10482013de9dc79', 'independent_review.py', '8ee25c246288d5ab43715a608bc6b6e1b69ce8d82ce0930e5ad89e75b7169680'),
    PROP: ('ae74387e1754ae28c3915f3bcd0fb790b0bc14fd890c542249fe897e43c5b1de', 'independent_verify.py', '5bf9a8d44027bafd7e0d9051c11b5fbf35369342535e83be45d32e60de252b39'),
    LAND: ('0d3ec0f67e20d125c92f0ab30879546571889f4a167aebab56f5997d8786bc0b', 'independent_review27.py', 'cbd2183fb2af869d73adc9696e58fd286027eb6334f5b23d150ca4928b990376'),
}
CLEANUP = ['异常尾块与清理契约/cleanup_targets_full.json', '异常尾块与清理契约/unwind_runtime.json']


def all_bytes(record, image):
    count = PREVIOUS.check_original_bytes(record, image)
    for row, _ in walk(record):
        if '字节核验' in row:
            item = row['字节核验']
            if item.get('IDB字节'):
                data = bytes.fromhex(item['IDB字节'])
                assert image.read(row['地址'], len(data)) == data
                count += 1
        if all(k in row for k in ('address', 'bytes')) and isinstance(row['bytes'], str):
            data = bytes.fromhex(row['bytes'])
            assert image.read(row['address'], len(data)) == data
            count += 1
    return count


def bound_original(directory, source):
    path = (directory if source['base'] == 'topic' else ROOT) / source['path']
    assert digest(path)[1] == source['sha256']
    return pointer(load(path), source['json_pointer'])


def normalized(directory, raw, image):
    path = directory / '证据/bounded_raw.json'
    formal = load(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA
    scope = '本批新本体完整局部分析' if directory.name == GROUP else '四个新主体原字段完整保留；语义分级只见本题清单'
    assert formal['functions'] == [OLD.normalized_record(row, path.relative_to(ROOT).as_posix(),
        f'/functions/{i}', digest(path)[1], scope) for i, row in enumerate(raw['functions'])]
    reused = load(directory / '证据/reused_functions.json')
    assert reused['disk_sha256'] == PE_SHA
    assert len(reused['functions']) == (7 if directory.name == GROUP else 9)
    for row in reused['functions']:
        origin = ROOT / row['source_path']
        assert digest(origin)[1] == row['source_sha256']
        original = pointer(load(origin), row['source_pointer'])
        enriched = dict(original)
        if directory.name == GROUP and row['va'] in ('0x6d7660', '0x6dfd10'):
            matches = [(i, x) for i, x in enumerate(raw['current_chunk_audits']) if x['seed_va'] == row['va']]
            assert len(matches) == 1
            index, audit = matches[0]
            enriched['chunk_byte_ranges'] = audit['chunk_byte_ranges']
            enriched['current_bytes_source'] = dict(source_path=path.relative_to(ROOT).as_posix(),
                source_pointer=f'/current_chunk_audits/{index}', source_sha256=digest(path)[1])
        wanted = OLD.normalized_record(enriched, row['source_path'], row['source_pointer'], row['source_sha256'], row['adaptation_scope'])
        if directory.name == GROUP:
            wanted['source_field_pointers'] = {k: row['source_pointer'] + '/' + k for k in original}
            for item in wanted['normalized_assembly']:
                item['normalized_item_kind'] = 'data' if item['text'].lstrip().split()[0].lower() in ('db', 'dw', 'dd', 'dq') else 'code'
        assert row == wanted, (directory.name, row['va'])
        all_bytes(enriched, image)
    return len(reused['functions'])


def build_adaptation(directory, raw, image):
    formal = load(directory / '证据/formal_functions.json')
    expected = PREVIOUS.build_adapter(raw, digest(directory / '证据/bounded_raw.json')[1], '证据/bounded_raw.json')
    for row in expected['functions']:
        row['status'] = '仅导出；分级另见审阅清单'
    expected['scope'] = '无损机械适配保留完整汇编、字符串型伪码、全部声明块；语义另见清单'
    assert formal == expected
    reused = load(directory / '证据/reused_audit.json')
    assert reused['disk_sha256'] == PE_SHA
    assert len(reused['references']) == 12 and len(reused['legacy_ranges']) == 4
    for row in reused['references'] + reused['legacy_ranges']:
        path = ROOT / row['source']
        assert digest(path)[1] == row['source_sha256']
        original = pointer(load(path), row['json_pointer'])
        assert original.get('va', original.get('address', original.get('seed_va'))) == row['owner_va']
        if 'original_record' in row:
            assert row['original_record'] == original
        all_bytes(original, image)
        all_bytes(row, image)
        for item, _ in walk(row):
            if all(k in item for k in ('start_va', 'size', 'sha256')):
                assert hashlib.sha256(image.read(item['start_va'], item['size'])).hexdigest() == item['sha256']
    return 16


def land_adaptation(directory, raw, image):
    formal = load(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and formal['raw_sha256'] == digest(directory / '证据/bounded_raw.json')[1]
    assert len(formal['functions']) == 2
    for i, (old, row) in enumerate(zip(raw['functions'], formal['functions'])):
        assert bound_original(directory, row['source']) == old == row['source_record']
        assert row == dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'], source=row['source'],
            source_record=old, pseudocode=old['pseudocode'], decompile_error=old['decompile_error'],
            assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in old['assembly']],
            chunk_byte_ranges=old['chunk_byte_ranges'], coverage_origin='本批新原证入口' if i == 0 else '旧完整原证本批重采；不计新增原证入口')
    assert len(formal['legacy_reused_functions']) == 4 and len(formal['historical_dependencies']) == 2
    for row in formal['legacy_reused_functions'] + formal['historical_dependencies']:
        old = bound_original(directory, row['source'])
        if 'source_record_json' in row:
            assert json.loads(row['source_record_json']) == old and 'source_record' not in row
        else:
            assert row['source_record'] == old
        all_bytes(old, image)
    assert len(formal['caller_windows']) == 10
    for row in formal['caller_windows']:
        owner = bound_original(directory, row['source'])
        assert row['owner_va'] == owner['地址']
        selected = [owner['完整汇编'][i] for i in row['source_indices']]
        assert selected == row['source_rows']
        assert row['assembly'] == [dict(va=x['地址'], text=x['汇编']) for x in selected]
        data = b''.join(bytes.fromhex(x['字节核验']['IDB字节']) for x in selected)
        assert len(data) == va(row['end_va']) - va(row['start_va'])
        assert data == image.read(row['start_va'], len(data))
        assert image.check(row['byte_audit']) == 'disk'
        assert not OLD.is_review(row)
    assert len(formal['offline_navigation_bridges']) == 8
    for row in formal['offline_navigation_bridges']:
        data = image.read(row['va'], 5)
        assert data.hex() == row['disk_hex'] and data[0] == 0xe9
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        assert va(row['target_va']) == va(row['va']) + 5 + struct.unpack_from('<i', data, 1)[0]
    return 6


def supplements(image):
    prop = ROOT / '专题' / PROP / '证据/dependency_data/bounded_raw.json'
    build = ROOT / '专题' / BUILD / '证据/callback_slots/bounded_raw.json'
    for path in (prop, build):
        raw = load(path)
        assert raw['disk_sha256'] == PE_SHA and not raw['functions'] and not raw['seeds']
        all_bytes(raw, image)
    assert [(r['start_va'], r['size']) for r in load(prop)['data_windows']] == [
        ('0x5ff6ea', 5), ('0x606a5d', 5), ('0x60bda5', 5), ('0xa2b480', 8)]
    assert image.read(0xa2b480, 8) == bytes(8)
    expected = [(0xa24cf4, 0x60a71b, 0x712980), (0xa263b4, 0x60a96e, 0x71f130), (0xa263c8, 0x60ce17, 0x71f230)]
    assert len(load(build)['data_windows']) == len(expected)
    for row, (slot, bridge, target) in zip(load(build)['data_windows'], expected):
        assert va(row['start_va']) == slot and row['size'] == 4
        assert struct.unpack('<I', image.read(slot, 4))[0] == bridge
        data = image.read(bridge, 5)
        assert data[0] == 0xe9 and bridge + 5 + struct.unpack_from('<i', data, 1)[0] == target
    return dict(prop_supplement_bytes=23, code_pointer_slots=3)


def resource_check(topic):
    import lzokay
    report = load(ROOT / '专题' / topic / '证据/resource_audit.json')
    data = (PROJECT / report['source']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == report['source_sha256']
    decoded = bytes((value - data[0]) & 255 for value in data[1:])
    plain_size, packed_size = struct.unpack_from('<II', decoded)
    assert len(data) == packed_size + 9
    plain = lzokay.decompress(decoded[8:], plain_size)
    assert len(plain) == plain_size and hashlib.sha256(plain).hexdigest() == report['plain_sha256']
    assert plain.decode('cp950').encode('cp950') == plain
    parsed, active, offset = [], None, 0
    for number, physical in enumerate(plain.splitlines(keepends=True), 1):
        line = physical.rstrip(b'\r\n')
        clean = line.strip()
        if clean.startswith(b'[') and clean.endswith(b']'):
            if topic == GROUP:
                active = dict(name=clean[1:-1].decode('ascii'), line=number, offset=offset, raw_hex=line.hex(), entries=[])
            else:
                active = dict(name=clean[1:-1].decode('ascii'), source_line=number, source_offset=offset, raw_line_hex=line.hex(), entries=[])
            parsed.append(active)
        elif active is not None and b'=' in clean and not clean.startswith((b'//', b';', b'#')):
            key, value = line.split(b'=', 1)
            key, value = key.strip().decode('ascii'), value.strip()
            if topic == GROUP:
                active['entries'].append(dict(key=key, value=value.decode('cp950'), line=number, offset=offset, raw_hex=line.hex()))
            elif key in ('indx', 'part') or re.fullmatch(r'ROLE\d+', key):
                active['entries'].append(dict(key=key, value=value.decode('cp950'), value_hex=value.hex(),
                    source_line=number, source_offset=offset, raw_line_hex=line.hex()))
        offset += len(physical)
    assert parsed == report['sections']
    if topic == GROUP:
        sections = {r['name']: r for r in parsed}
        assert len(parsed) == len(sections) == 6651
        wanted = []
        for group in range(76):
            indices = sorted(int(m.group(1)) for name in sections if (m := re.fullmatch(f'O_{group}_S_([0-9]+)', name)))
            assert indices == list(range(len(indices))) and len(indices) <= 100
            items = []
            for index in indices:
                entries = {r['key']: r for r in sections[f'O_{group}_S_{index}']['entries']}
                e = entries['npid']
                items.append(dict(index=index, npid=int(e['value']), source_line=e['line'], source_offset=e['offset']))
            wanted.append(dict(group=group, loaded_prefix_count=len(indices), configured_indices=indices,
                ignored_after_gap_or_limit=[], items=items))
        assert wanted == report['groups'] and sum(len(r['items']) for r in wanted) == 6575
        assert wanted[4]['loaded_prefix_count'] == 39 and wanted[47]['loaded_prefix_count'] == 100
        assert report['group_allocation_bytes'] == 76 * 100 * 12
    else:
        assert len(parsed) == report['section_count'] == 1117
        indices = [int(next(e['value'] for e in r['entries'] if e['key'] == 'indx')) for r in parsed]
        assert indices == report['indices'] and len(indices) == len(set(indices))
        parts = Counter(e['value'] for r in parsed for e in r['entries'] if e['key'] == 'part')
        roles = Counter(e['value'] for r in parsed for e in r['entries'] if e['key'].startswith('ROLE'))
        keys = Counter(e['key'] for r in parsed for e in r['entries'] if e['key'].startswith('ROLE'))
        assert dict(parts) == report['part_histogram'] and dict(roles) == report['role_value_histogram']
        assert dict(keys) == report['role_key_histogram']
        assert [i for i, r in enumerate(parsed) if not any(e['key'] == 'part' for e in r['entries'])] == report['missing_part_sections']
    return dict(source=report['source'], plain_bytes=plain_size, sections=len(parsed))


def final_bindings(directory):
    report_sha, script, script_sha = FINAL_HASHES[directory.name]
    assert digest(directory / '证据' / REPORTS[directory.name])[1] == report_sha
    assert digest(directory / '证据' / script)[1] == script_sha
    report = load(directory / '证据' / REPORTS[directory.name])
    assert report.get('status', report.get('result')) == 'PASS'
    bound = set()
    for row, _ in walk(report):
        for name, value in row.items():
            if isinstance(value, str) and len(value) == 64 and Path(name).suffix in ('.json', '.txt', '.py'):
                base = PROJECT if name.startswith('docs/') else ROOT if name.startswith(('专题/', '全量分析/')) else directory
                path = base / name
                assert path.is_file(), name
                assert digest(path)[1] == value, name
                bound.add(path.resolve())
    required = [directory / '函数审阅清单.json', directory / '证据/formal_functions.json', directory / '证据/bounded_raw.json']
    required.extend(p for p in directory.glob('*.txt') if p.name != '独立审阅结论.txt')
    if directory.name in (GROUP, PROP):
        required.append(directory / '证据/resource_audit.json')
    if directory.name == PROP:
        required.append(directory / '证据/dependency_data/bounded_raw.json')
    if directory.name == BUILD:
        required.append(directory / '证据/callback_slots/bounded_raw.json')
    assert all(p.resolve() in bound for p in required), [str(p) for p in required if p.resolve() not in bound]
    return len(bound)


def precheck():
    image, result = Image(), {}
    BASE.TOPICS = TOPICS
    for topic in TOPICS:
        directory = ROOT / '专题' / topic
        path = directory / '证据/bounded_raw.json'
        raw = load(path)
        assert [r['seed_va'] for r in raw['functions']] == SEEDS[topic]
        ranges, windows, instructions = BASE.bounded_check(path, image)
        reused = normalized(directory, raw, image) if topic in (GROUP, PROP) else build_adaptation(directory, raw, image) if topic == BUILD else land_adaptation(directory, raw, image)
        result[topic] = dict(sampled_functions=len(raw['functions']), historical_records=reused,
            byte_ranges=dict(ranges), finite_owner_windows=windows, window_instructions=instructions,
            final_bound_files=final_bindings(directory))
    result[PROP]['supplements'] = supplements(image)
    for topic in (GROUP, PROP):
        result[topic]['resource'] = resource_check(topic)
    return result


def replay_sources(merge, pairs, chinese=True):
    outputs = []
    def capture(path, text, *args, **kwargs):
        assert path == HERE / 'evidence_coverage.json'
        outputs.append(json.loads(text))
        return len(text)
    old_gate = merge.strict_chinese_function_address
    try:
        if not chinese:
            merge.strict_chinese_function_address = lambda *args, **kwargs: None
        with patch.object(Path, 'write_text', capture), patch.object(merge, 'iter_evidence_sources', lambda: iter(pairs)), contextlib.redirect_stdout(io.StringIO()):
            merge.main()
    finally:
        merge.strict_chinese_function_address = old_gate
    assert len(outputs) == 1
    return outputs[0]


def historical_accounting(evidence, prior):
    merge = module('merge27_readonly', 'merge_evidence.py', '09d40e91296b2ca2787861069c809efd6a8537bf9141fd4ea14da729d62f2857')
    frozen = load(HERE / 'chinese_merge27_frozen_sources.json')
    assert frozen['archive_sha256'] == next(r['sha256'] for r in prior['source_fingerprints'] if r['path'] == 'archive_validation.json')
    paths = []
    for row in frozen['files']:
        if row['path'].startswith('专题/') and row['path'].endswith('.json'):
            path = ROOT / row['path']
            assert digest(path)[1] == row['sha256']
            paths.append((path, False))
    assert len(paths) == 1446
    old = replay_sources(merge, paths, False)
    chinese = replay_sources(merge, paths)
    full_old = replay_sources(merge, paths + [(HERE / p, True) for p in CLEANUP])
    old_vas, chinese_vas, corrected_vas = ({r['va'] for r in j['functions']} for j in (old, chinese, full_old))
    assert len(old_vas) == prior['unique_exported_functions'] == 6052
    assert len(chinese_vas - old_vas) == 39 and len(corrected_vas - chinese_vas) == 46
    assert len(corrected_vas) == 6137 and old_vas <= chinese_vas <= corrected_vas
    for key in ('unrecognized_code_ranges', 'instruction_observations', 'navigation_windows'):
        assert old[key] == chinese[key] == full_old[key]
    current = {r['va']: r for r in evidence['functions']}
    assert corrected_vas <= set(current)
    sampled = set(sum(SEEDS.values(), []))
    assert sampled & corrected_vas == {'0x7ecd80'}
    assert set(current) - corrected_vas == sampled - {'0x7ecd80'}, '本批新增必须来自14个真正新主体'
    relationships = lambda obj: {(r['va'], s) for r in obj['functions'] for s in r['evidence']}
    assert len(relationships(full_old) - relationships(old)) == 237
    return dict(historical_chinese_entries=39, historical_cleanup_entries=46,
        historical_source_relationships=237, current_sampled_bodies=15,
        current_resampled_body='0x7ecd80', truly_new_functions=14)


def main():
    assert READY, '中央独审准备阶段，尚未冻结'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十七批推进快照.json')
    args = parser.parse_args()
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十六批推进快照.json')
    sources = {}
    for row in snapshot['source_fingerprints']:
        path = HERE / row['path']
        assert digest(path) == (row['bytes'], row['sha256'])
        assert path.name not in sources
        sources[path.name] = load(path)
    assert set(sources) == {'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json', '结构覆盖口径.json', 'archive_validation.json'}
    evidence, review, archive = (sources[k] for k in ('evidence_coverage.json', 'review_coverage.json', 'archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts'] and snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions'] == evidence['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions'] == review['unique_functions_with_explicit_reviews']
    central = {r['va']: r['reviews'] for r in review['functions']}
    assert len(central) == len(review['functions'])
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
    assert digest(ROOT / '18_选择输入与资源生产证据索引.txt')[1] == '44ac5907aa25c0b25d81b38f78ff6b933633a5a5028a933c580902070252c74b'
    result = precheck()
    for topic in TOPICS:
        directory = ROOT / '专题' / topic
        path = directory / '函数审阅清单.json'
        source = path.relative_to(ROOT).as_posix()
        expected = [(r, ref) for r, ref in walk(load(path)) if OLD.is_review(r)]
        assert len(expected) == REVIEW_COUNTS[topic]
        assert len({OLD.address_of(r) for r, _ in expected}) == len(expected)
        for row, ref in expected:
            found = [x for x in central[OLD.address_of(row)] if x['source'] == source and x['json_pointer'] == ref]
            assert len(found) == 1 and all(found[0][k] == row[k] for k in ('status', 'conclusion'))
        prefix = directory.relative_to(ROOT).as_posix() + '/'
        assert {(r['source'], r['json_pointer']) for r in records if r['source'].startswith(prefix)} == {(source, ref) for _, ref in expected}
        result[topic]['manifest_records'] = len(expected)
    captured = set()
    for row in archive['files']:
        assert not row['errors'] and digest(ROOT / row['path']) == (row['bytes'], row['sha256'])
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(p).suffix for p in captured)) == archive['counts']
    assert '全量分析/independent_snapshot_audit27.py' in captured
    accounting = historical_accounting(evidence, prior)
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {k: snapshot[k] - prior[k] for k in keys}
    prefixes = tuple('专题/' + t + '/' for t in TOPICS)
    new_reviews = [r for r in review['functions'] if all(x['source'].startswith(prefixes) for x in r['reviews'])]
    assert changes['unique_exported_functions'] == 85 + 14
    assert changes['unique_explicit_review_functions'] == len(new_reviews)
    assert changes['review_record_count'] == len([r for r in records if r['source'].startswith(prefixes)]) == 26
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot, counts={k: snapshot[k] for k in keys},
        changes=changes, source_fingerprints=len(sources), captured_archive_files=len(captured),
        accounting=accounting, topics=result, scope='静态证据与冻结计量独审；不表示全程序语义完成、运行行为或IDB全文件等同'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
