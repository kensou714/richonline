"""第二十二批冻结快照独审；独立复核原证、机械适配和终稿指纹，只读不写盘。"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
TOPICS = {
    '游戏鼠标对象与业务门': ('函数审阅清单.json', 'independent_validation.json', 4),
    'A839A0状态读写与消费': ('函数审阅清单.json', 'independent_review_validation.json', 8),
    'GoldCharge四槽与金额消费': ('function_review.json', 'independent_final_validation.json', 5),
    '界面共享槽与通知消费': ('函数审阅清单.json', 'independent_validation.json', 7),
}
BODY_KEYS = ('pseudocode', 'disassembly', 'assembly', 'instructions')
ADDRESS_KEYS = ('va', 'address', 'ea', '地址')


def load(path):
    return json.loads(path.read_bytes().decode('utf-8-sig'))


def digest(path):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), path
    return len(raw), hashlib.sha256(raw).hexdigest()


def va(value):
    return value if isinstance(value, int) else int(value, 16)


def walk(value, pointer=''):
    if isinstance(value, dict):
        yield value, pointer or '/'
        for key, child in value.items():
            yield from walk(child, pointer + '/' + str(key).replace('~', '~0').replace('/', '~1'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, pointer + '/' + str(index))


class Image:
    def __init__(self):
        self.raw = (PROJECT / 'RnClient.exe').read_bytes()
        assert hashlib.sha256(self.raw).hexdigest() == PE_SHA
        pe = struct.unpack_from('<I', self.raw, 0x3c)[0]
        assert self.raw[:2] == b'MZ' and self.raw[pe:pe + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', self.raw, pe + 24)[0] == 0x10b
        self.base = struct.unpack_from('<I', self.raw, pe + 52)[0]
        table = pe + 24 + struct.unpack_from('<H', self.raw, pe + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.raw, table + i * 40 + 8)
                         for i in range(struct.unpack_from('<H', self.raw, pe + 6)[0])]

    def read(self, address, size):
        rva = va(address) - self.base
        offsets = [raw_offset + rva - virtual_address
                   for _, virtual_address, raw_size, raw_offset in self.sections
                   if 0 <= rva - virtual_address and rva - virtual_address + size <= raw_size]
        assert len(offsets) == 1, (address, size)
        return self.raw[offsets[0]:offsets[0] + size]

    def check(self, row, address=None):
        address = address or row.get('start_va', row.get('va'))
        raw = bytes.fromhex(row['idb_hex'])
        assert row['matching'] is True
        assert raw == bytes.fromhex(row['disk_hex']) == self.read(address, row['size'])
        assert len(raw) == row['size']
        assert 'sha256' not in row or hashlib.sha256(raw).hexdigest() == row['sha256']
        return raw

    def check_data(self, row):
        if row['disk_hex'] is not None:
            self.check(row)
            return 'disk'
        # IDA 在 PE 虚拟尾区保存的值只能证明数据库快照，不能称为磁盘或运行态。
        assert row['matching'] is None and '虚拟' in row['pending_status']
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        rva = va(row['start_va']) - self.base
        assert any(raw_size <= rva - virtual_address
                   and rva - virtual_address + row['size'] <= virtual_size
                   for virtual_size, virtual_address, raw_size, _ in self.sections)
        return 'virtual'


def formal_equivalence(topic, directory, image):
    raw_path = directory / '证据/bounded_raw.json'
    raw, formal = load(raw_path), load(directory / '证据/formal_functions.json')
    sha = digest(raw_path)[1]
    assert formal['source_sha256'] == sha
    assert raw['disk_sha256'] == formal['disk_sha256'] == PE_SHA
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
        if topic == 'A839A0状态读写与消费':
            assert all(new[key] == value for key, value in old.items())
            assert new['byte_ranges'] == ranges
            assert new['source_file'] == 'bounded_raw.json' and new['source_pointer'] == ref
            assert new['source_field_pointers'] == {key: ref + '/' + key for key in old}
        elif topic == '游戏鼠标对象与业务门':
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
            assert new['bytes_match_disk'] is True
    if topic == '游戏鼠标对象与业务门':
        assert formal['thunks'] == [dict(row, va=row['start_va'], target=row['target_va'])
                                    for row in raw['verified_direct_bridges']]
    return len(raw['functions'])


def check_bindings(directory, validation, manifest_name):
    """只接纳明确路径的指纹；地址/字节哈希不冒充终稿文件绑定。"""
    assert validation['status'] == 'PASS', directory.name
    checked = set()

    def check(name, sha):
        name = name.replace('\\', '/')
        if name.startswith('docs/'):
            path = PROJECT / name
        elif name.startswith('专题/') or name.startswith('全量分析/'):
            path = ROOT / name
        else:
            path = directory / name
            if not path.is_file():
                path = directory / '证据' / name
        assert path.is_file() and digest(path)[1] == sha.lower(), path
        checked.add(path.resolve())

    for key in ('sources', 'source_sha256', 'reviewed_final_sha256', 'author_text_sha256',
                'manifest_reference_sha256', 'documents', 'author_snapshots', 'evidence_snapshots',
                'document_sha256', 'input_sha256', 'source_hashes', 'final_sha256',
                'bound_files', 'final_text_sha256'):
        value = validation.get(key)
        if isinstance(value, dict):
            for name, sha in value.items():
                if isinstance(sha, str) and len(sha) == 64:
                    check(name, sha)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and 'path' in item:
                    check(item['path'], item.get('sha256', item.get('source_sha256')))
    fixed = {'manifest_sha256': manifest_name, 'review_sha256': manifest_name,
             'formal_sha256': '证据/formal_functions.json',
             'formal_source_sha256': '证据/formal_functions.json',
             'raw_source_sha256': '证据/bounded_raw.json'}
    for key, path in fixed.items():
        if key in validation:
            check(path, validation[key])
    required = {directory / manifest_name, directory / '证据/formal_functions.json',
                directory / '证据/bounded_raw.json'}
    required.update(path for path in directory.glob('*.txt') if path.name[:2].isdigit())
    assert {path.resolve() for path in required} <= checked, (
        directory.name, sorted(str(path) for path in required if path.resolve() not in checked))
    return len(checked)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十二批推进快照.json')
    args = parser.parse_args()
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十一批推进快照.json')
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
    all_reviews = [item for row in review['functions'] for item in row['reviews']]
    image = Image()
    counts, bindings, adapted, owner_pairs, data_counts = {}, {}, {}, set(), Counter()
    for topic, (manifest_name, validation_name, _) in TOPICS.items():
        directory = ROOT / '专题' / topic
        adapted[topic] = formal_equivalence(topic, directory, image)
        manifest = load(directory / manifest_name)
        bindings[topic] = check_bindings(directory, load(directory / '证据' / validation_name), manifest_name)
        source = (directory / manifest_name).relative_to(ROOT).as_posix()
        counts[topic] = len(manifest['functions'])
        for index, item in enumerate(manifest['functions']):
            candidates = [row for row in central[hex(va(item['va']))]
                          if row['source'] == source and row['json_pointer'] == f'/functions/{index}']
            assert len(candidates) == 1, (topic, item['va'])
            assert all(candidates[0][key] == item[key] for key in ('status', 'conclusion'))
        expected_records = {f'/functions/{index}' for index in range(len(manifest['functions']))}
        assert {row['json_pointer'] for row in all_reviews if row['source'] == source} == expected_records
        for raw_path in directory.rglob('bounded_raw.json'):
            raw = load(raw_path)
            assert raw['disk_sha256'] == PE_SHA
            forbidden = raw_path.relative_to(ROOT).as_posix()
            assert not any(row['source'] == forbidden for row in all_reviews)
            assert not any(forbidden in row['evidence'] for row in evidence['functions'] + evidence['unrecognized_code_ranges'])
            if raw_path.parent != directory / '证据':
                assert not raw['functions'] and not raw['reused_seeds'], raw_path
            for row in raw['data_windows']:
                data_counts[image.check_data(row)] += 1
            for node, _ in walk(raw):
                if 'owner_va' in node and isinstance(node.get('assembly'), list):
                    assert not any(key in node for key in ADDRESS_KEYS)
                    for item in node['assembly']:
                        image.check(item['bytes'], item['site_va'])
        formal_source = (directory / '证据/formal_functions.json').relative_to(ROOT).as_posix()
        assert not any(row['source'] == formal_source for row in all_reviews)
        for owner_path in directory.glob('证据/*owner_context.json'):
            owner_source = owner_path.relative_to(ROOT).as_posix()
            owner = load(owner_path)
            assert owner['disk_sha256'] == PE_SHA
            assert not any(row['source'] == owner_source for row in all_reviews)
            assert not any(owner_source in row['evidence'] for row in evidence['functions'])
            for window in owner['windows']:
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
    assert '全量分析/independent_snapshot_audit22.py' in captured
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exclusive_exports = [row for row in evidence['functions']
                         if all(source.startswith(prefixes) for source in row['evidence'])]
    exclusive_reviews = [row for row in review['functions']
                         if all(item['source'].startswith(prefixes) for item in row['reviews'])]
    new_records = [item for item in all_reviews if item['source'].startswith(prefixes)]
    expected_sources = {(ROOT / '专题' / name / values[0]).relative_to(ROOT).as_posix()
                        for name, values in TOPICS.items()}
    # Gold 原样复用一条历史审阅；保留来源记录，不称为新增函数或新语义结论。
    reused_source = '专题/GoldCharge四槽与金额消费/证据/reused_raw.json'
    reused_path = ROOT / reused_source
    original_copy = load(reused_path)['records'][10]
    assert original_copy['va'] == '0x7b9ca0'
    historical_path = (reused_path.parent / original_copy['source']['path']).resolve()
    assert historical_path.is_relative_to(ROOT.resolve())
    assert digest(historical_path)[1] == original_copy['source']['sha256']
    historical = load(historical_path)
    for part in original_copy['source']['pointer'].split('/')[1:]:
        historical = historical[part.replace('~1', '/').replace('~0', '~')]
    assert historical == original_copy['original_record']
    extra = [item for item in new_records if item['source'] not in expected_sources]
    assert len(extra) == 1 and extra[0]['source'] == reused_source
    assert extra[0]['json_pointer'] == '/records/10/original_record'
    assert all(extra[0][key] == historical[key] for key in ('status', 'conclusion'))
    assert any(item['source'] == historical_path.relative_to(ROOT).as_posix()
               for item in central['0x7b9ca0'])
    assert '0x7b9ca0' not in {row['va'] for row in exclusive_exports + exclusive_reviews}
    assert {item['source'] for item in new_records} == expected_sources | {reused_source}
    derived = dict(zip(keys, (len(exclusive_exports), len(exclusive_reviews), len(new_records))))
    assert changes == derived, (changes, derived)
    assert counts == dict(zip(TOPICS, (9, 14, 19, 36)))
    assert len(new_records) == sum(counts.values()) + 1
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot,
        counts={key: snapshot[key] for key in keys}, changes=changes,
        source_fingerprints=len(sources), captured_archive_files=len(captured),
        topic_manifest_counts=counts, topic_binding_counts=bindings, adapted_functions=adapted,
        copied_historical_review_records=len(extra),
        navigation_windows=len(navigation), owner_context_unique_ranges=len(owner_pairs),
        data_windows_checked=dict(data_counts), undeclared_ranges=len(snapshot['unrecognized_code_ranges']),
        scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
