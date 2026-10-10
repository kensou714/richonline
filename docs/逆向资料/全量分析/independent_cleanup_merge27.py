"""独审中文与清理原证归并：剥离预期来源后逐字节复现第26批，禁止中央写入。"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MANIFEST_SHA = '0245e003f53f0b25fa7532946072f0743aee8e0894740ab34ee0973a2e21f8c2'
BODY_FILES = (
    '全量分析/异常尾块与清理契约/cleanup_targets_full.json',
    '全量分析/异常尾块与清理契约/unwind_runtime.json',
)
CHINESE_FILES = (
    '专题/移动与动画协议/证据/movement_protocol_core.json',
    '专题/地图与路径/证据/map_runtime_core.json',
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    manifest_path = HERE / 'chinese_merge27_frozen_sources.json'
    assert sha(manifest_path) == MANIFEST_SHA
    manifest = read(manifest_path)
    snapshot = read(HERE / '第二十六批推进快照.json')
    frozen_sha = {r['path']: r['sha256'] for r in snapshot['source_fingerprints']}
    assert manifest['archive_sha256'] == frozen_sha['archive_validation.json']
    frozen_paths = []
    for entry in manifest['files']:
        name = entry['path']
        assert name.startswith('专题/') and name.endswith('.json')
        path = ROOT / name
        assert sha(path) == entry['sha256'], name
        frozen_paths.append(path)
    assert len(frozen_paths) == len(set(frozen_paths)) == 1446
    expected_pairs, body_pairs, chinese_pairs = set(), set(), set()
    for relative in BODY_FILES:
        data = read(ROOT / relative)
        # 独审只从顶层函数数组建期望集合，裸桥、指令站点及owner绝不参与。
        body_pairs.update((row['va'], relative) for row in data['functions'])
    for relative in CHINESE_FILES:
        data = read(ROOT / relative)
        chinese_pairs.update((hex(int(row['地址'], 16)), relative) for row in data['函数'])
    assert len(body_pairs) == 78 and len(chinese_pairs) == 159
    expected_pairs = body_pairs | chinese_pairs
    assert len(expected_pairs) == 237

    module_path = HERE / 'merge_evidence.py'
    spec = importlib.util.spec_from_file_location('readonly_merge_under_review', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tracked = [HERE / name for name in (
        'merge_evidence.py', 'evidence_coverage.json', 'review_coverage.json',
        'followup_queue.json', 'archive_validation.json', '第二十六批推进快照.json')]
    tracked += [ROOT / name for name in BODY_FILES] + [manifest_path] + frozen_paths
    before = {str(path): sha(path) for path in tracked}
    permitted_reads = set(frozen_paths) | {ROOT / name for name in BODY_FILES}
    permitted_reads |= {HERE / 'functions.json', HERE / 'segments.json'}
    original_read_text = Path.read_text
    writes = []

    def frozen_rglob(path, pattern):
        assert path == module.TOPICS and pattern == '*.json', ('非冻结扫描', str(path), pattern)
        return iter(frozen_paths)

    def guarded_read(path, *args, **kwargs):
        assert path in permitted_reads, ('非冻结来源读取', str(path))
        return original_read_text(path, *args, **kwargs)

    def intercepted_write(path, content, *args, **kwargs):
        assert path == HERE / 'evidence_coverage.json', ('额外输出', str(path))
        writes.append(json.loads(content))
        return len(content)

    with patch.object(Path, 'rglob', frozen_rglob), patch.object(Path, 'read_text', guarded_read), \
            patch.object(Path, 'write_text', intercepted_write), contextlib.redirect_stdout(io.StringIO()):
        module.main()
    assert len(writes) == 1
    result = writes[0]
    assert result['unique_exported_functions'] == 6137
    rows = {row['va']: row for row in result['functions']}
    actual_pairs = {(va, source) for va, row in rows.items() for source in row['evidence']
                    if source in BODY_FILES + CHINESE_FILES}
    assert actual_pairs == expected_pairs, ('两文件白名单或中文入口集合异常', actual_pairs ^ expected_pairs)

    # 不依赖作者的开关或测试辅助函数。直接从真实输出移除预期237关系，再与26完整原文SHA比。
    reconstructed = copy.deepcopy(result)
    preserved = []
    removed_entries = set()
    for row in reconstructed['functions']:
        row['evidence'] = [source for source in row['evidence']
                           if (row['va'], source) not in expected_pairs]
        if row['evidence']:
            preserved.append(row)
        else:
            removed_entries.add(row['va'])
    reconstructed['functions'] = preserved
    reconstructed['unique_exported_functions'] = len(preserved)
    assert len(preserved) == 6052 and len(removed_entries) == 85
    serialized = json.dumps(reconstructed, ensure_ascii=False, indent=2).replace('\n', '\r\n').encode('utf-8')
    assert hashlib.sha256(serialized).hexdigest() == frozen_sha['evidence_coverage.json'], \
        '剥离237关系后没有逐字节还原第26批完整台账'
    missing_body = removed_entries & {va for va, _ in body_pairs}
    missing_chinese = removed_entries & {va for va, _ in chinese_pairs}
    assert len(missing_body) == 46 and len(missing_chinese) == 39
    assert not missing_body & missing_chinese
    assert before == {name: sha(Path(name)) for name in before}, '中央文件或作者来源发生变更'
    print(json.dumps(dict(
        结果='PASS', 冻结专题来源=1446, 严格白名单文件=2,
        第26批原证入口=6052, 仅历史修复后入口=6137,
        中文历史补计=39, 清理历史补计=46, 两项交集=0,
        新增来源关系=237, 完整还原第26批台账SHA=True,
        第27批新材料参与=False, 额外尾块导航桥入口=0, 中央写入=False,
        被审实现SHA=before[str(module_path)]), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
