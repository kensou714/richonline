"""第二十三批中央独审：固定来源、机械等价、历史复制边界；只读不写盘。"""
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
    'Help配置与分类文本消费': ('函数审阅清单.json', 'independent_validation.json', 9),
    '地图选择字段与列表消费': ('函数审阅清单.json', 'independent_review_validation.json', 6),
    '124字节共享记录与判断门': ('function_review.json', 'independent_validation.json', 8),
    '按钮音效配置与文本输出': ('函数审阅清单.json', 'independent_validation.json', 6),
}


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


def pointer(value, path):
    for part in path.split('/')[1:]:
        key = part.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def walk(value, path=''):
    if isinstance(value, dict):
        yield value, path or '/'
        for key, child in value.items():
            yield from walk(child, path + '/' + str(key).replace('~', '~0').replace('/', '~1'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, path + '/' + str(index))


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
        offsets = [offset + rva - start for _, start, raw_size, offset in self.sections
                   if 0 <= rva - start and rva - start + size <= raw_size]
        assert len(offsets) == 1, (address, size)
        return self.raw[offsets[0]:offsets[0] + size]

    def check(self, row, address=None):
        address = address or row.get('start_va', row.get('va'))
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        if row['disk_hex'] is None:
            assert row['matching'] is None and '虚拟' in row['pending_status']
            rva = va(address) - self.base
            assert any(raw_size <= rva - start and rva - start + row['size'] <= size
                       for size, start, raw_size, _ in self.sections)
            return 'virtual'
        assert row['matching'] is True
        assert raw == bytes.fromhex(row['disk_hex']) == self.read(address, row['size'])
        return 'disk'


def formal_check(topic, directory, image):
    path = directory / '证据/bounded_raw.json'
    raw, formal = load(path), load(directory / '证据/formal_functions.json')
    sha = digest(path)[1]
    assert raw['disk_sha256'] == formal['disk_sha256'] == PE_SHA
    assert len(raw['functions']) == TOPICS[topic][2]
    assert len(formal['functions']) == len(raw['functions']) + (topic == '按钮音效配置与文本输出')
    for index, old in enumerate(raw['functions']):
        new = formal['functions'][index]
        assert new['va'] == old['seed_va'] and new['end_va'] == old['end_va']
        assert new['name'] == old['name'] and new['pseudocode'] == old['pseudocode']
        assert new['decompile_error'] == old['decompile_error'] and 'conclusion' not in new
        chunks = old['chunk_byte_ranges']
        for chunk in chunks:
            assert image.check(chunk) == 'disk'
        expected_chunks = [dict(start_va=row['start_va'], end_va=hex(va(row['start_va']) + row['size']),
                                is_main=row['start_va'] == old['seed_va']) for row in chunks]
        assert new['declared_chunks'] == expected_chunks
        ref = f'/functions/{index}'
        if topic == '地图选择字段与列表消费':
            assert all(new[key] == value for key, value in old.items())
            assert new['source_path'] == path.relative_to(ROOT).as_posix()
            assert new['source_sha256'] == sha and new['source_pointer'] == ref
            assert new['source_field_pointers'] == {key: ref + '/' + key for key in old}
            assert new['normalized_chunks'] == chunks and new['byte_ranges'] == chunks
            assert new['normalized_assembly'] == [dict(site_va=row['site_va'], text=row['text'],
                is_code=row['is_code'], original=row) for row in old['assembly']]
        elif topic == 'Help配置与分类文本消费':
            assert formal['source_sha256'] == sha
            assert new['assembly'] == [dict(row, va=row['site_va']) for row in old['assembly']]
            assert new['byte_ranges'] == [dict(row, va=row['start_va']) for row in chunks]
            assert new['source'] == '证据/bounded_raw.json' and new['source_sha256'] == sha
            assert new['json_pointer'] == ref and new['bytes_match_disk'] is True
        else:
            assert formal['source_sha256'] == sha
            assert new['assembly'] == [dict(va=row['site_va'], text=row['text'], is_code=row['is_code'])
                                       for row in old['assembly']]
            assert new['chunk_byte_ranges'] == [dict(va=row['start_va'], **{key: value for key, value
                in row.items() if key != 'start_va'}) for row in chunks]
            assert new['source'] == dict(path='证据/bounded_raw.json', sha256=sha, json_pointer=ref)
            assert new['bytes_match_disk'] is True
    if topic == 'Help配置与分类文本消费':
        assert formal['thunks'] == [dict(row, va=row['start_va'], target=row['target_va'])
                                    for row in raw['verified_direct_bridges']]
    if topic == '按钮音效配置与文本输出':
        new = formal['functions'][-1]
        old_path = ROOT / '专题/界面系统/第二批/ida_ui_batch2_raw.json'
        old = load(old_path)['functions']['0x90b500']
        assert new['va'] == old['address'] == '0x90b500'
        assert new['end_va'] == old['end'] and new['name'] == old['name']
        assert new['pseudocode'] == old['pseudocode'] and new['assembly'] == old['instructions']
        assert new['source'] == dict(path='../界面系统/第二批/ida_ui_batch2_raw.json',
            sha256=digest(old_path)[1], json_pointer='/functions/0x90b500')
        ref = new['current_audit_source']
        assert ref['path'] == '证据/bounded_raw.json' and ref['sha256'] == sha
        current = pointer(raw, ref['json_pointer'])
        assert current['seed_va'] == new['va']
        assert new['chunk_byte_ranges'] == [dict(va=row['start_va'], **{key: value for key, value
            in row.items() if key != 'start_va'}) for row in current['chunk_byte_ranges']]
        assert new['decompile_error'] is None and new['bytes_match_disk'] is True
        assert new['declared_chunks'] == [dict(start_va=row['start_va'],
            end_va=hex(va(row['start_va']) + row['size']), is_main=row['start_va'] == new['va'])
            for row in current['chunk_byte_ranges']]
        for chunk in current['chunk_byte_ranges']:
            assert image.check(chunk) == 'disk'
    if topic == '地图选择字段与列表消费':
        map_adaptation_check(directory, image)
    return len(raw['functions'])


def map_adaptation_check(directory, image):
    evidence_dir = directory / '证据'
    dependencies = load(evidence_dir / 'dependency_raw.json')
    formal = load(evidence_dir / 'formal_dependencies.json')
    reused = load(evidence_dir / 'reused_functions.json')
    assert dependencies['disk_sha256'] == formal['disk_sha256'] == reused['disk_sha256'] == PE_SHA
    assert len(dependencies['functions']) == len(formal['functions']) == 3
    expected = [('专题/地图选择字段与列表消费/证据/dependency_raw.json', f'/functions/{i}',
                 '本批补充完整原证无损适配') for i in range(3)]
    specs = [('专题/MapView配置记录与预览消费/证据/closure_raw.json', ['0x73f420'], '历史部分分析本体；本批分级审阅'),
             ('专题/随机地图候选与配置索引/证据/dependencies_raw.json', ['0x64f200', '0x7e9610'], '既有局部契约复用'),
             ('专题/随机地图候选与配置索引/证据/functions_raw.json', ['0x6aaa80'], '既有局部契约复用'),
             ('专题/Pawn四档配置与业务消费/证据/reused_raw.json',
              ['0x629dd0', '0x629df0', '0x63edd0', '0x63e1a0', '0x629e10'], '模式谓词复用'),
             ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', ['0x629e60'], '根对象字段地址复用'),
             ('专题/回合继续与落点调度/证据/stage1_dependencies.json', ['0x922570'], '未初始化诊断局部契约复用'),
             ('专题/聊天发送与重复提示契约/证据/chat_contract_discovery.json',
              ['0x9204c0', '0x9204d0'], '既有CRT入口与共享复制块复用')]
    for name, addresses, scope in specs:
        source = load(ROOT / name)
        for address in addresses:
            candidates = [(node, ref) for node, ref in walk(source)
                          if node.get('va', node.get('address')) == address
                          and any(key in node for key in ('assembly', 'instructions'))]
            assert len(candidates) == 1, (name, address)
            expected.append((name, candidates[0][1], scope))
    rows = formal['functions'] + reused['functions']
    assert len(rows) == len(expected) == 16
    for new, (name, ref, scope) in zip(rows, expected):
        path = ROOT / name
        old = pointer(load(path), ref)
        address = old.get('seed_va', old.get('va', old.get('address')))
        chunks = old.get('chunk_byte_ranges', old.get('chunks', old.get('byte_ranges')))
        assembly = old.get('assembly', old.get('instructions'))
        normalized = [dict(start_va=chunk.get('start_va', chunk.get('va', chunk.get('address'))),
            **{key: value for key, value in chunk.items() if key not in ('start_va', 'va', 'address')})
            for chunk in chunks]
        wanted = dict(old, va=address, source_path=name, source_pointer=ref,
            source_sha256=digest(path)[1], source_field_pointers={key: ref + '/' + key for key in old},
            adaptation_scope=scope, normalized_chunks=normalized,
            normalized_assembly=[dict(site_va=item.get('site_va', item.get('va', item.get('address'))),
                text=item['text'], is_code=item.get('is_code', True), original=item) for item in assembly])
        wanted.setdefault('declared_chunks', [dict(start_va=chunk['start_va'],
            end_va=hex(va(chunk['start_va']) + chunk['size']), is_main=chunk['start_va'] == address)
            for chunk in normalized])
        wanted.setdefault('byte_ranges', chunks)
        assert new == wanted, (name, ref)
        for chunk in normalized:
            raw = bytes.fromhex(chunk.get('idb_hex', chunk.get('ida_hex')))
            assert len(raw) == chunk['size'] and raw == bytes.fromhex(chunk['disk_hex'])
            assert raw == image.read(chunk['start_va'], chunk['size'])
            assert chunk.get('matching', chunk.get('equal')) is True
            if 'sha256' in chunk:
                assert hashlib.sha256(raw).hexdigest() == chunk['sha256']


def check_bindings(directory, validation, manifest_name):
    assert validation['status'] == 'PASS', directory.name
    checked = set()
    for key in ('sources', 'source_sha256', 'reviewed_final_sha256', 'author_text_sha256',
                'manifest_reference_sha256', 'bound_files', 'final_text_sha256', 'documents',
                'reference_sha256', 'document_sha256', 'source_files'):
        value = validation.get(key)
        pairs = value.items() if isinstance(value, dict) else (
            ((row['path'], row.get('sha256', row.get('source_sha256'))) for row in value)
            if isinstance(value, list) else [])
        for name, sha in pairs:
            name = name.replace('\\', '/')
            base = PROJECT if name.startswith('docs/') else ROOT if name.startswith('专题/') else directory
            path = base / name
            if not path.is_file():
                path = directory / '证据' / name
            assert path.is_file() and digest(path)[1] == sha.lower(), path
            checked.add(path.resolve())
    for key, name in {'manifest_sha256': manifest_name, 'review_sha256': manifest_name,
        'formal_sha256': '证据/formal_functions.json', 'formal_source_sha256': '证据/formal_functions.json',
        'raw_source_sha256': '证据/bounded_raw.json'}.items():
        if key in validation:
            path = directory / name
            assert digest(path)[1] == validation[key]
            checked.add(path.resolve())
    required = {directory / manifest_name, directory / '证据/formal_functions.json', directory / '证据/bounded_raw.json'}
    required.update(path for path in directory.glob('*.txt') if path.name[:2].isdigit())
    if directory.name == '124字节共享记录与判断门':
        required.update(directory / name for name in ('独立审阅.txt', '证据/独立审阅.txt')
                        if (directory / name).is_file())
    assert {path.resolve() for path in required} <= checked, directory.name
    return len(checked)


def bounded_check(path, image):
    raw = load(path)
    assert raw['disk_sha256'] == PE_SHA
    counts = Counter(image.check(row) for row in raw['data_windows'])
    owners = instructions = 0
    for node, _ in walk(raw):
        if 'owner_va' in node and isinstance(node.get('assembly'), list):
            assert not any(key in node for key in ('va', 'address', 'ea', '地址'))
            owners += 1
            for item in node['assembly']:
                assert image.check(item['bytes'], item['site_va']) == 'disk'
                instructions += 1
    return counts, owners, instructions


def shared_reuse_check():
    path = ROOT / '专题/124字节共享记录与判断门/证据/reused_raw.json'
    data = load(path)
    assert len(data['records']) == 9
    exceptions = []
    historical = ROOT / '专题/游戏分派桥接/证据/property_and_6021_handlers.json'
    assert digest(historical)[1] == '9861f1e478a0ccb56863d5b766b813c03cb641da93fd7e726c5a59220d971a50'
    for index, row in enumerate(data['records']):
        ref = row['source']
        source = (path.parent / ref['path']).resolve()
        assert digest(source)[1] == ref['sha256']
        original = pointer(load(source), ref['pointer'])
        assert row['original_record'] == original and row['va'] == original['va']
        if index < 3:
            assert source == historical.resolve() and ref['pointer'] == f'/functions/{20 + index}'
            assert row['va'] == ['0x6b7ce0', '0x6a6cd0', '0x629ea0'][index]
            assert isinstance(original['status'], str) and isinstance(original['conclusion'], str)
            exceptions.append(dict(va=row['va'], source=path.relative_to(ROOT).as_posix(),
                json_pointer=f'/records/{index}/original_record', original=original,
                original_source=source.relative_to(ROOT).as_posix(), original_pointer=ref['pointer']))
        else:
            assert not (isinstance(original.get('status'), str) and isinstance(original.get('conclusion'), str))
    return exceptions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十三批推进快照.json')
    args = parser.parse_args()
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十二批推进快照.json')
    sources = {}
    for row in snapshot['source_fingerprints']:
        path = HERE / row['path']
        assert digest(path) == (row['bytes'], row['sha256']), path
        sources[path.name] = load(path)
    assert set(sources) == {'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json',
                            '结构覆盖口径.json', 'archive_validation.json'}
    evidence, review, archive = (sources[name] for name in ('evidence_coverage.json', 'review_coverage.json', 'archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts']
    assert snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions'] == evidence['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions'] == review['unique_functions_with_explicit_reviews']
    assert len({row['va'] for row in evidence['functions']}) == len(evidence['functions'])
    assert len({row['va'] for row in review['functions']}) == len(review['functions'])
    central = {row['va']: row['reviews'] for row in review['functions']}
    records = [dict(item, function_va=row['va']) for row in review['functions'] for item in row['reviews']]
    states = Counter(item['status'] for item in records)
    assert sum(states.values()) == review['review_record_count'] == snapshot['review_record_count']
    assert dict(states) == review['raw_status_counts'] == snapshot['raw_status_counts']
    assert snapshot['structural_groups'] == sources['结构覆盖口径.json']['groups']
    assert snapshot['instruction_observation_count'] == evidence['instruction_observation_count'] == prior['instruction_observation_count']
    assert snapshot['unrecognized_code_ranges'] == evidence['unrecognized_code_ranges'] == prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows'] == evidence['navigation_windows']
    navigation = {(va(row['start_va']), va(row['end_va'])) for row in snapshot['navigation_windows']}
    assert len(navigation) == len(snapshot['navigation_windows']) == evidence['navigation_window_count']
    assert {(va(row['start_va']), va(row['end_va'])) for row in prior['navigation_windows']} <= navigation
    image = Image()
    historical_copies = shared_reuse_check()
    for copied in historical_copies:
        reviews = central[copied['va']]
        matches = [row for row in reviews if (row['source'], row['json_pointer']) ==
                   (copied['source'], copied['json_pointer'])]
        originals = [row for row in reviews if (row['source'], row['json_pointer']) ==
                     (copied['original_source'], copied['original_pointer'])]
        assert len(matches) == len(originals) == 1
        assert all(matches[0][key] == originals[0][key] == copied['original'][key]
                   for key in ('status', 'conclusion'))
        exported = next(row for row in evidence['functions'] if row['va'] == copied['va'])
        assert copied['source'] in exported['evidence'] and copied['original_source'] in exported['evidence']
    counts, bindings, adapted, data_counts = {}, {}, {}, Counter()
    for topic, (manifest_name, validation_name, _) in TOPICS.items():
        directory = ROOT / '专题' / topic
        adapted[topic] = formal_check(topic, directory, image)
        manifest = load(directory / manifest_name)
        bindings[topic] = check_bindings(directory, load(directory / '证据' / validation_name), manifest_name)
        source = (directory / manifest_name).relative_to(ROOT).as_posix()
        counts[topic] = len(manifest['functions'])
        for index, item in enumerate(manifest['functions']):
            matches = [row for row in central[hex(va(item['va']))] if row['source'] == source
                       and row['json_pointer'] == f'/functions/{index}']
            assert len(matches) == 1 and all(matches[0][key] == item[key] for key in ('status', 'conclusion'))
        assert {row['json_pointer'] for row in records if row['source'] == source} == {
            f'/functions/{index}' for index in range(len(manifest['functions']))}
        for raw_path in directory.rglob('bounded_raw.json'):
            checked, _, _ = bounded_check(raw_path, image)
            data_counts.update(checked)
            forbidden = raw_path.relative_to(ROOT).as_posix()
            assert not any(row['source'] == forbidden for row in records)
            assert not any(forbidden in row['evidence'] for row in evidence['functions'] + evidence['unrecognized_code_ranges'])
    captured = set()
    for row in archive['files']:
        assert not row['errors'] and digest(ROOT / row['path']) == (row['bytes'], row['sha256'])
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(name).suffix for name in captured)) == archive['counts']
    assert '全量分析/independent_snapshot_audit23.py' in captured
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exclusive_exports = [row for row in evidence['functions'] if all(source.startswith(prefixes) for source in row['evidence'])]
    exclusive_reviews = [row for row in review['functions'] if all(item['source'].startswith(prefixes) for item in row['reviews'])]
    new_records = [item for item in records if item['source'].startswith(prefixes)]
    expected_records = {((ROOT / '专题' / name / TOPICS[name][0]).relative_to(ROOT).as_posix(), f'/functions/{index}')
                        for name, count in counts.items() for index in range(count)}
    expected_records.update((row['source'], row['json_pointer']) for row in historical_copies)
    assert {(row['source'], row['json_pointer']) for row in new_records} == expected_records
    assert len(new_records) == len(expected_records)
    assert not {row['va'] for row in historical_copies} & {row['va'] for row in exclusive_exports + exclusive_reviews}
    derived = dict(zip(keys, (len(exclusive_exports), len(exclusive_reviews), len(new_records))))
    assert changes == derived and len(new_records) == sum(counts.values()) + 3, (changes, derived)
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot, counts={key: snapshot[key] for key in keys},
        changes=changes, source_fingerprints=len(sources), captured_archive_files=len(captured),
        topic_manifest_counts=counts, topic_binding_counts=bindings, adapted_functions=adapted,
        historical_review_copies=len(historical_copies),
        navigation_windows=len(navigation), data_windows_checked=dict(data_counts),
        scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
