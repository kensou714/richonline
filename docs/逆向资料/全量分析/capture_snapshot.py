"""冻结本次汇总及来源指纹；不覆写已有批次，不把汇总分级当作完成率。"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name', help='当前目录内的新JSON文件名')
    args = parser.parse_args()
    assert Path(args.name).name == args.name and args.name.endswith('.json')
    destination = HERE / args.name
    assert not destination.exists(), '已有固定快照不可覆盖'
    documents, fingerprints = {}, []
    for name in ('evidence_coverage.json', 'review_coverage.json', 'followup_queue.json',
                 '结构覆盖口径.json', 'archive_validation.json'):
        source = HERE / name
        before = source.stat()
        raw = source.read_bytes()
        after = source.stat()
        assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
        documents[name] = json.loads(raw.decode('utf-8-sig'))
        fingerprints.append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                                 mtime_ns=after.st_mtime_ns))
    evidence = documents['evidence_coverage.json']
    review = documents['review_coverage.json']
    archive = documents['archive_validation.json']
    assert not review['invalid_records'] and not archive['error_files']
    snapshot = dict(
        utc=datetime.now(timezone.utc).isoformat(),
        scope='固定汇总时点；并行在写专题可计入原证，不等于全部独审完成或全程序语义完成',
        unique_exported_functions=evidence['unique_exported_functions'],
        unique_explicit_review_functions=review['unique_functions_with_explicit_reviews'],
        review_record_count=review['review_record_count'],
        structural_groups=documents['结构覆盖口径.json']['groups'],
        raw_status_counts=review['raw_status_counts'],
        unrecognized_code_ranges=evidence['unrecognized_code_ranges'],
        navigation_windows=evidence.get('navigation_windows', []),
        instruction_observation_count=evidence['instruction_observation_count'],
        format_check=dict(checked_at=archive['checked_at'], counts=archive['counts'],
                          errors=archive['error_files']),
        invalid_records=review['invalid_records'], source_fingerprints=fingerprints)
    # x模式拒绝并发同名写入；不改动之前批次。
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(snapshot, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(dict(file=args.name, exported=snapshot['unique_exported_functions'],
                         explicit=snapshot['unique_explicit_review_functions']), ensure_ascii=False))


if __name__ == '__main__':
    main()
