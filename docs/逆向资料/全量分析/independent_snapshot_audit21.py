"""独立核对第二十一批冻结快照、机械适配与终审绑定；只读不写盘。"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent
EXPECTED_PE = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
TOPICS = {
    '四类型辅助请求与队列': ('function_review.json', 'independent_final_validation.json', 6),
    '三类型结果请求与容器': ('函数审阅清单.json', 'independent_review_validation.json', 6),
    '文本控制节点池与操作': ('函数审阅清单.json', 'independent_validation.json', 7),
    '高扇入界面操作辅助': ('函数审阅清单.json', 'independent_validation.json', 4),
}


def load(path):
    return json.loads(path.read_bytes().decode('utf-8-sig'))


def digest(path):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), path
    return len(raw), hashlib.sha256(raw).hexdigest()


def check_hashes(mapping, base):
    for name, sha in mapping.items():
        path = base / name.replace('\\', '/')
        assert path.is_file() and digest(path)[1] == sha.lower(), path
    return len(mapping)


def pointer(value, path):
    assert path.startswith('/')
    for part in path[1:].split('/'):
        key = part.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def va(value):
    return value if isinstance(value, int) else int(value, 16)


class Image:
    def __init__(self):
        self.raw = (PROJECT / 'RnClient.exe').read_bytes()
        assert hashlib.sha256(self.raw).hexdigest() == EXPECTED_PE
        pe = struct.unpack_from('<I', self.raw, 0x3c)[0]
        assert self.raw[:2] == b'MZ' and self.raw[pe:pe + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', self.raw, pe + 24)[0] == 0x10b
        self.base = struct.unpack_from('<I', self.raw, pe + 52)[0]
        table = pe + 24 + struct.unpack_from('<H', self.raw, pe + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.raw, table + i * 40 + 8)
                         for i in range(struct.unpack_from('<H', self.raw, pe + 6)[0])]

    def read(self, address, size):
        rva = va(address) - self.base
        for virtual_size, virtual_address, raw_size, raw_offset in self.sections:
            delta = rva - virtual_address
            if 0 <= delta and delta + size <= raw_size:
                return self.raw[raw_offset + delta:raw_offset + delta + size]
        raise AssertionError(('非磁盘映射范围', address, size))

    def check(self, row, address=None):
        address = address or row.get('start_va', row.get('va'))
        raw = bytes.fromhex(row['idb_hex'])
        assert row['matching'] is True
        assert raw == bytes.fromhex(row['disk_hex']) == self.read(address, row['size'])
        assert len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw


def formal_equivalence(topic, directory, image):
    raw_path = directory / '证据/bounded_raw.json'
    raw, formal = load(raw_path), load(directory / '证据/formal_functions.json')
    sha = digest(raw_path)[1]
    assert formal['source_sha256'] == sha
    assert raw['disk_sha256'] == formal['disk_sha256'] == EXPECTED_PE
    assert len(raw['functions']) == len(formal['functions']) == TOPICS[topic][2]
    for index, (old, new) in enumerate(zip(raw['functions'], formal['functions'])):
        assert new['va'] == old['seed_va'] and new['end_va'] == old['end_va']
        assert new['name'] == old['name'] and new['pseudocode'] == old['pseudocode']
        assert new['decompile_error'] == old['decompile_error'] and 'conclusion' not in new
        ranges = old['chunk_byte_ranges']
        for row in ranges:
            image.check(row)
        chunks = [dict(start_va=row['start_va'], end_va=hex(va(row['start_va']) + row['size']),
                       is_main=row['start_va'] == old['seed_va']) for row in ranges]
        assert new['declared_chunks'] == chunks
        ref = f'/functions/{index}'
        if topic == '三类型结果请求与容器':
            assert all(new[key] == value for key, value in old.items())
            assert new['byte_ranges'] == ranges
            assert new['source_file'] == 'bounded_raw.json' and new['source_pointer'] == ref
            assert new['source_field_pointers'] == {key: ref + '/' + key for key in old}
        elif topic == '文本控制节点池与操作':
            assert new['assembly'] == [dict(item, va=item['site_va']) for item in old['assembly']]
            assert new['byte_ranges'] == [dict(row, va=row['start_va']) for row in ranges]
            assert new['source'] == '证据/bounded_raw.json' and new['source_sha256'] == sha
            assert new['json_pointer'] == ref and new['bytes_match_disk'] is True
        else:
            assert new['assembly'] == [dict(va=item['site_va'], text=item['text'],
                                            is_code=item['is_code']) for item in old['assembly']]
            assert new['chunk_byte_ranges'] == [dict(va=row['start_va'], **{
                key: value for key, value in row.items() if key != 'start_va'}) for row in ranges]
            assert new['source'] == dict(path='证据/bounded_raw.json', sha256=sha, json_pointer=ref)
            assert new['bytes_match_disk'] == all(row['matching'] for row in ranges)
    if topic == '文本控制节点池与操作':
        assert formal['thunks'] == [dict(row, va=row['start_va'], target=row['target_va'])
                                    for row in raw['verified_direct_bridges']]
    return len(raw['functions'])


def final_bindings(topic, directory, validation):
    assert validation['status'] == 'PASS', topic
    if topic == '四类型辅助请求与队列':
        assert digest(directory / 'function_review.json')[1] == validation['review_sha256']
        assert digest(directory / '证据/formal_functions.json')[1] == validation['formal_sha256']
        count = check_hashes({row['path']: row['sha256'] for row in validation['documents']}, directory) + 2
        checks = (
            ('independent_bounded_validation.json', 'raw_sha256', 'bounded_raw.json'),
            ('independent_legacy_validation.json', 'reused_source_sha256', 'reused_network.json'),
        )
        for filename, key, source in checks:
            item = load(directory / '证据' / filename)
            assert item['status'] == 'PASS'
            count += check_hashes({source: item[key]}, directory / '证据')
        dependencies = load(directory / '证据/independent_dependency_validation.json')
        assert dependencies['status'] == 'PASS'
        count += check_hashes({row['path']: row['sha256'] for row in dependencies['sources']}, directory / '证据')
        return count
    if topic == '三类型结果请求与容器':
        return check_hashes(validation['source_sha256'], PROJECT)
    if topic == '文本控制节点池与操作':
        return (check_hashes(validation['sources'], PROJECT)
                + check_hashes(validation['reviewed_final_sha256'], directory))
    count = check_hashes(validation['author_text_sha256'], directory)
    count += check_hashes(validation['manifest_reference_sha256'], ROOT)
    mapping = {
        'raw_source_sha256': '证据/bounded_raw.json',
        'dependency_source_sha256': '证据/dependency_raw.json',
        'owner_context_source_sha256': '证据/owner_context_raw.json',
        'manifest_sha256': '函数审阅清单.json',
        'formal_source_sha256': '证据/formal_functions.json',
        'reviewer_text_sha256': '06_独立审阅.txt',
    }
    return count + check_hashes({path: validation[key] for key, path in mapping.items()}, directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十一批推进快照.json')
    args = parser.parse_args()
    assert Path(args.snapshot).name == args.snapshot
    snapshot = load(HERE / args.snapshot)
    prior = load(HERE / '第二十批复核快照.json')
    sources = {}
    for row in snapshot['source_fingerprints']:
        path = HERE / row['path']
        assert digest(path) == (row['bytes'], row['sha256']), path
        sources[path.name] = load(path)
    assert set(sources) == {'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json',
                            '结构覆盖口径.json', 'archive_validation.json'}
    evidence, review, archive = (sources[name] for name in (
        'evidence_coverage.json', 'review_coverage.json', 'archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts']
    assert snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions'] == evidence['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions'] == review['unique_functions_with_explicit_reviews']
    assert len({row['va'] for row in evidence['functions']}) == len(evidence['functions'])
    assert len({row['va'] for row in review['functions']}) == len(review['functions'])
    states = Counter(item['status'] for row in review['functions'] for item in row['reviews'])
    assert sum(states.values()) == review['review_record_count'] == snapshot['review_record_count']
    assert dict(states) == review['raw_status_counts'] == snapshot['raw_status_counts']
    assert snapshot['structural_groups'] == sources['结构覆盖口径.json']['groups']
    assert snapshot['instruction_observation_count'] == evidence['instruction_observation_count'] == prior['instruction_observation_count']
    assert snapshot['unrecognized_code_ranges'] == evidence['unrecognized_code_ranges'] == prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows'] == evidence['navigation_windows']
    navigation = {(va(row['start_va']), va(row['end_va'])): row for row in snapshot['navigation_windows']}
    assert len(navigation) == len(snapshot['navigation_windows']) == evidence['navigation_window_count']
    assert {(va(row['start_va']), va(row['end_va'])) for row in prior['navigation_windows']} <= navigation.keys()
    central = {row['va']: row['reviews'] for row in review['functions']}
    image = Image()
    counts, bindings, adapted, owner_pairs = {}, {}, {}, set()
    for topic, (manifest_name, validation_name, _) in TOPICS.items():
        directory = ROOT / '专题' / topic
        adapted[topic] = formal_equivalence(topic, directory, image)
        manifest = load(directory / manifest_name)
        validation = load(directory / '证据' / validation_name)
        bindings[topic] = final_bindings(topic, directory, validation)
        source = (directory / manifest_name).relative_to(ROOT).as_posix()
        counts[topic] = len(manifest['functions'])
        for index, item in enumerate(manifest['functions']):
            candidates = [row for row in central[hex(va(item['va']))]
                          if row['source'] == source and row['json_pointer'] == f'/functions/{index}']
            assert len(candidates) == 1, (topic, item['va'])
            assert all(candidates[0][key] == item[key] for key in ('status', 'conclusion'))
        for name in ('bounded_raw.json', 'formal_functions.json'):
            forbidden = (directory / '证据' / name).relative_to(ROOT).as_posix()
            assert not any(row['source'] == forbidden for rows in central.values() for row in rows)
        for row in evidence['functions'] + evidence['unrecognized_code_ranges']:
            assert not any(path == (directory / '证据/bounded_raw.json').relative_to(ROOT).as_posix()
                           for path in row['evidence']), (topic, row['va'])
        if topic == '文本控制节点池与操作':
            for item in manifest['windows']:
                assert 'owner_va' in item and 'va' not in item
                assert 'window_status' in item and 'status' not in item
                assert 'window_conclusion' in item and 'conclusion' not in item
            assert not any(row['source'] == source and row['json_pointer'].startswith('/windows/')
                           for rows in central.values() for row in rows)
        owner_path = directory / '证据/owner_context_raw.json'
        if owner_path.exists():
            owner_source = owner_path.relative_to(ROOT).as_posix()
            for window in load(owner_path)['windows']:
                start, end = va(window['start_va']), va(window['end_va'])
                assert end - start == window['size']
                image.check(window)
                cursor, parts = start, []
                for item in window['assembly']:
                    assert va(item['site_va']) == cursor
                    parts.append(image.check(item['bytes'], item['site_va']))
                    cursor += item['bytes']['size']
                assert cursor == end and b''.join(parts).hex() == window['disk_hex']
                assert owner_source in navigation[(start, end)]['evidence']
                owner_pairs.add((start, end))
    captured = set()
    for row in archive['files']:
        path = ROOT / row['path']
        assert not row['errors'] and digest(path) == (row['bytes'], row['sha256']), path
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(name).suffix for name in captured)) == archive['counts']
    assert '全量分析/independent_snapshot_audit21.py' in captured
    assert counts == dict(zip(TOPICS, (42, 37, 9, 21))), counts
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exclusive_exports = [row for row in evidence['functions']
                         if all(source.startswith(prefixes) for source in row['evidence'])]
    exclusive_reviews = [row for row in review['functions']
                         if all(item['source'].startswith(prefixes) for item in row['reviews'])]
    new_records = [item for row in review['functions'] for item in row['reviews']
                   if item['source'].startswith(prefixes)]
    expected_sources = {(ROOT / '专题' / name / values[0]).relative_to(ROOT).as_posix()
                        for name, values in TOPICS.items()}
    assert {item['source'] for item in new_records} == expected_sources
    derived = dict(zip(keys, (len(exclusive_exports), len(exclusive_reviews), len(new_records))))
    assert changes == derived == dict(zip(keys, (87, 96, 109))), (changes, derived)
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot,
        counts={key: snapshot[key] for key in keys}, changes=changes,
        source_fingerprints=len(sources), captured_archive_files=len(captured),
        topic_manifest_counts=counts, topic_binding_counts=bindings, adapted_functions=adapted,
        navigation_windows=len(navigation), owner_context_unique_ranges=len(owner_pairs),
        undeclared_ranges=len(snapshot['unrecognized_code_ranges']),
        scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
