"""独立核对第二十批固定快照、中央口径及四专题终稿绑定；只读不写盘。"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent
TOPICS = {
    'Avatar配置与角色图片': ('函数审阅清单.json', '证据/independent_validation.json'),
    'Grant全局配置与短消费': ('函数审阅清单.json', '证据/independent_review_validation.json'),
    'PlusPrize配置与双消费': ('function_review.json', '证据/independent_pe.json'),
    'NewProps与CombCard配置': ('函数审阅清单.json', '证据/independent_final_validation.json'),
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
    count = 0
    for name, expected in mapping.items():
        path = base / name.replace('\\', '/')
        assert path.is_file(), path
        assert digest(path)[1] == expected.lower(), path
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十批推进快照.json')
    args = parser.parse_args()
    assert Path(args.snapshot).name == args.snapshot
    snapshot = load(HERE / args.snapshot)
    prior = load(HERE / '第十九批推进快照.json')
    sources = {}
    for fingerprint in snapshot['source_fingerprints']:
        path = HERE / fingerprint['path']
        size, sha = digest(path)
        assert size == fingerprint['bytes'] and sha == fingerprint['sha256'], path
        sources[path.name] = load(path)
    assert set(sources) == {
        'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json',
        '结构覆盖口径.json', 'archive_validation.json',
    }
    evidence = sources['evidence_coverage.json']
    review = sources['review_coverage.json']
    archive = sources['archive_validation.json']
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts']
    assert snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions']
    assert len({row['va'] for row in evidence['functions']}) == len(evidence['functions'])
    assert len({row['va'] for row in review['functions']}) == len(review['functions'])
    records = sum(len(row['reviews']) for row in review['functions'])
    assert records == review['review_record_count'] == snapshot['review_record_count']
    states = Counter(item['status'] for row in review['functions'] for item in row['reviews'])
    assert dict(states) == review['raw_status_counts'] == snapshot['raw_status_counts']
    assert snapshot['structural_groups'] == sources['结构覆盖口径.json']['groups']
    assert evidence['instruction_observation_count'] == snapshot['instruction_observation_count']
    assert snapshot['instruction_observation_count'] == prior['instruction_observation_count'] == 33
    # 第二十批没有新的未声明范围；锚点记录不能借 va/disassembly 成为伪函数。
    assert snapshot['unrecognized_code_ranges'] == prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows'] == prior['navigation_windows']
    assert len(snapshot['unrecognized_code_ranges']) == 24
    for row in evidence['functions'] + evidence['unrecognized_code_ranges']:
        assert not any('bounded_raw.json' in path for path in row['evidence']), row['va']
    central = {row['va']: row['reviews'] for row in review['functions']}
    manifest_counts = {}
    binding_counts = {}
    for topic, (manifest_name, validation_name) in TOPICS.items():
        directory = ROOT / '专题' / topic
        manifest = load(directory / manifest_name)
        validation = load(directory / validation_name)
        assert validation['status'] == 'PASS', topic
        source = (directory / manifest_name).relative_to(ROOT).as_posix()
        manifest_counts[topic] = len(manifest['functions'])
        for index, item in enumerate(manifest['functions']):
            rows = [row for row in central[item['va']]
                    if row['source'] == source and row['json_pointer'] == f'/functions/{index}']
            assert len(rows) == 1, (topic, item['va'])
            assert rows[0]['status'] == item['status'], (topic, item['va'])
            assert rows[0]['conclusion'] == item['conclusion'], (topic, item['va'])
        if topic == 'Avatar配置与角色图片':
            count = check_hashes(validation['author_document_hashes'], PROJECT)
            count += check_hashes(validation['source_hashes'], PROJECT)
            # historical 的完整块复核属于合法复用；只有单指令锚点必须排除。
            historical = {item['va'] for item in validation['historical']}
            actual = {row['va'] for row in evidence['functions']
                      if '专题/Avatar配置与角色图片/证据/independent_validation.json'
                      in row['evidence']}
            assert actual == historical and len(historical) == 8
            for item in validation['historical']:
                assert item['chunks'] and isinstance(item['instructions'], int)
                assert item['instructions'] > 0
                assert all(chunk['size'] > 0 and len(chunk['sha256']) == 64
                           for chunk in item['chunks'])
            for anchor in validation['semantic_anchors']:
                assert 'va' not in anchor and 'disassembly' not in anchor, anchor
                assert anchor['site_va'] not in {
                    row['va'] for row in evidence['unrecognized_code_ranges']}, anchor
        elif topic == 'Grant全局配置与短消费':
            count = check_hashes(validation['source_sha256'], PROJECT)
        elif topic == 'PlusPrize配置与双消费':
            count = check_hashes(validation['input_sha256'], PROJECT)
            count += check_hashes(validation['document_sha256'], directory)
        else:
            count = check_hashes(validation['author_snapshots'], directory)
            for name, sha in validation['evidence_snapshots'].items():
                base = PROJECT if name.replace('\\', '/').startswith('docs/') else directory / '证据'
                count += check_hashes({name: sha}, base)
        binding_counts[topic] = count
    assert manifest_counts == dict(zip(TOPICS, (15, 15, 21, 26)))
    captured_paths = set()
    for item in archive['files']:
        path = ROOT / item['path']
        assert not item['errors'], path
        assert digest(path) == (item['bytes'], item['sha256']), path
        assert item['path'] not in captured_paths, path
        captured_paths.add(item['path'])
    assert dict(Counter(Path(name).suffix for name in captured_paths)) == archive['counts']
    assert '全量分析/independent_snapshot_audit.py' in captured_paths
    changes = {key: snapshot[key] - prior[key] for key in (
        'unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')}
    assert changes == dict(unique_exported_functions=39,
                           unique_explicit_review_functions=41, review_record_count=77), changes
    original_counts_unchanged = None
    if args.snapshot == '第二十批复核快照.json':
        original = load(HERE / '第二十批推进快照.json')
        original_counts_unchanged = all(original[key] == snapshot[key] for key in changes)
        assert original_counts_unchanged
        assert original['unrecognized_code_ranges'] == snapshot['unrecognized_code_ranges']
        assert original['navigation_windows'] == snapshot['navigation_windows']
        assert original['instruction_observation_count'] == snapshot['instruction_observation_count']
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot,
                         counts={key: snapshot[key] for key in changes}, changes=changes,
                         original_counts_unchanged=original_counts_unchanged,
                         captured_archive_files=len(captured_paths),
                         source_fingerprints=len(sources), topic_manifest_counts=manifest_counts,
                         topic_binding_counts=binding_counts, undeclared_ranges=24,
                         instruction_observations=33,
                         scope='冻结时点的字节与归档独审；不表示全程序语义完成或实机验证'),
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
