"""第二十四批中央独审：固定来源和冻结归档；原证未齐时拒绝正式检查。"""
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
    '124字节共享记录内容写入': {'fresh': 5, 'reused': 3},
    '角色档案配置与字段消费': {'fresh': 7, 'reused': 3},
    '地图视图初始化平移与夹取': {'fresh': 4, 'reused': 3},
    '文本控件光标与行边界': {'fresh': 3, 'reused': 4},
}
READY = False


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
    assert {path.resolve() for path in required} <= checked, directory.name
    return len(checked)


def topic_check(topic, directory, image, central, records, evidence):
    # 各组正式模式与历史复制例外需在原证落盘后精确实现，准备阶段不得宣称已审。
    raise NotImplementedError('本批正式原证和终稿模式尚未冻结：' + topic)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十四批推进快照.json')
    args = parser.parse_args()
    assert READY, '准备阶段；原证与终稿校验尚未实现，禁止正式中央检查'
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十三批推进快照.json')
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
    topic_results = {topic: topic_check(topic, ROOT / '专题' / topic, image, central, records, evidence)
                     for topic in TOPICS}
    captured = set()
    for row in archive['files']:
        assert not row['errors'] and digest(ROOT / row['path']) == (row['bytes'], row['sha256'])
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(name).suffix for name in captured)) == archive['counts']
    assert '全量分析/independent_snapshot_audit24.py' in captured
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exclusive_exports = [row for row in evidence['functions'] if all(source.startswith(prefixes) for source in row['evidence'])]
    exclusive_reviews = [row for row in review['functions'] if all(item['source'].startswith(prefixes) for item in row['reviews'])]
    new_records = [item for item in records if item['source'].startswith(prefixes)]
    derived = dict(zip(keys, (len(exclusive_exports), len(exclusive_reviews), len(new_records))))
    assert changes == derived, (changes, derived)
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot, counts={key: snapshot[key] for key in keys},
        changes=changes, source_fingerprints=len(sources), captured_archive_files=len(captured),
        topics=topic_results, navigation_windows=len(navigation),
        scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
