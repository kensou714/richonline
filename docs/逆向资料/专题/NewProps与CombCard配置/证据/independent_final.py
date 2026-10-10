"""终稿门：运行自己的字节与资源核验，并绑定人工审读的文档快照。"""
import hashlib
import json
from pathlib import Path

import independent_resources
import independent_verify

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    raw = independent_verify.review()
    resources = independent_resources.review()
    manifest_path = TOPIC / '函数审阅清单.json'
    manifest = json.loads(manifest_path.read_bytes())
    entries = {row['va']: row for row in manifest['functions']}
    assert len(entries) == len(manifest['functions']) == 26
    assert set(entries) == {row['va'] for row in raw['functions']}
    for row in entries.values():
        assert row['unknown'] and row['conclusion'] and row['evidence']
        for relative in row['evidence']:
            path = TOPIC / relative
            assert path.is_file() and path.resolve().is_relative_to(TOPIC.resolve())
    docs = sorted(TOPIC.glob('[0-9][0-9]_*.txt'))
    assert len(docs) == 7
    for path in docs:
        assert all(not line.strip() or line.startswith('//')
                   for line in path.read_text('utf-8').splitlines()), path
    author_validation = HERE / 'validation.json'
    assert author_validation.is_file()
    author_result = json.loads(author_validation.read_bytes())
    assert author_result['status'] == 'PASS' and author_result['disk_sha256'] == raw['pe_sha256']
    assert (author_result['unique_functions'], author_result['new_business_functions'],
            author_result['new_direct_bridges'], author_result['reused_functions']) == (26, 7, 2, 17)
    assert author_result['checked_unique_bridges'] == raw['bridge_count'] == 572
    assert author_result['direct_delete_pointer_offsets'] == [
        row['field_offset'] for row in raw['direct_release_groups']]
    result = dict(
        status='PASS', pe_sha256=raw['pe_sha256'],
        manual_review='七篇正文和清单人工逐项审读；脚本重跑不会替代新的语义审阅',
        new_body_objects=7, new_direct_bridge_objects=2, reused_body_objects=17,
        raw_object_count=len(raw['functions']), unique_bridges_rechecked=raw['bridge_count'],
        semantic_anchor_count=len(raw['semantic_anchors']),
        author_snapshots={str(path.relative_to(TOPIC)): digest(path)
                          for path in docs + [manifest_path, author_validation,
                                               TOPIC / 'validate_evidence.py', HERE / 'resources_author.json']},
        evidence_snapshots=raw['sources'],
        resources=dict(author_sha256=resources['author_sha256'],
                       author_fields_compared=resources['author_fields_compared']),
        boundary='全块字节及全部唯一桥重核不是全语义完成；复用主体、7FEBF0其他数组、外部后端均按有限范围；未运行游戏')
    (HERE / 'independent_final_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(result['status'], result['raw_object_count'], result['unique_bridges_rechecked'])


if __name__ == '__main__':
    main()
