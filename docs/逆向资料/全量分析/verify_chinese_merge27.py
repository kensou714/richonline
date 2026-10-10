"""第二十七批中文原证修复的可重放差分校验；不写中央 JSON。"""

import contextlib
import hashlib
import importlib
import io
import json
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def frozen_topic_files():
    # 独立保存第二十六批来源集；后续批次可以重建中央归档而不破坏本校验。
    archive = read(HERE / "chinese_merge27_frozen_sources.json")
    snapshot = read(HERE / "第二十六批推进快照.json")
    assert archive['archive_sha256'] == next(
        row['sha256'] for row in snapshot['source_fingerprints']
        if row['path'] == 'archive_validation.json')
    files = []
    for item in archive["files"]:
        name = item["path"]
        if name.startswith("专题/") and name.endswith(".json"):
            path = ROOT / name
            assert path.exists(), name
            assert sha(path) == item["sha256"], name
            files.append(path)
    assert len(files) == 1446, len(files)
    assert len(set(files)) == len(files)
    return files


def run(module, frozen):
    """截获 merge 的 evidence_coverage 写入，只返回内存结果。"""
    output = []
    expected = module.ROOT / "evidence_coverage.json"

    def capture(path, content, *args, **kwargs):
        assert path == expected, str(path)
        output.append(json.loads(content))
        return len(content)

    with patch.object(Path, "write_text", capture), patch.object(
            module, "iter_evidence_sources", lambda: iter((path, False) for path in frozen)
            ), contextlib.redirect_stdout(io.StringIO()):
        module.main()
    assert len(output) == 1
    return output[0]


def source_additions(before, after):
    old = {row["va"]: row for row in before["functions"]}
    additions = 0
    changed = set()
    for row in after["functions"]:
        evidence = set(row["evidence"])
        previous = set(old.get(row["va"], {}).get("evidence", []))
        added = evidence - previous
        if added:
            additions += len(added)
            changed.add(row["va"])
    return additions, changed


def main():
    module = importlib.import_module("merge_evidence")
    tracked = [HERE / name for name in (
        "merge_evidence.py", "evidence_coverage.json", "review_coverage.json",
        "followup_queue.json", "archive_validation.json", "第二十六批推进快照.json")]
    before_hashes = {path: sha(path) for path in tracked}
    frozen = frozen_topic_files()
    original_gate = module.strict_chinese_function_address
    try:
        # 严格门关闭的对照只用于内存计量，绝不改脚本或中央结果。
        module.strict_chinese_function_address = lambda *args, **kwargs: None
        baseline = run(module, frozen)
    finally:
        module.strict_chinese_function_address = original_gate
    candidate = run(module, frozen)

    added_relations, changed = source_additions(baseline, candidate)
    assert candidate["unique_exported_functions"] - baseline["unique_exported_functions"] == 39
    assert len(changed) == 159
    assert added_relations == 159
    assert candidate["unique_exported_functions"] == 6091
    assert baseline["unique_exported_functions"] == 6052
    assert all(candidate[key] == baseline[key] for key in (
        "total_identified_functions", "outside_inventory",
        "unrecognized_code_ranges", "instruction_observations",
        "navigation_windows"))
    assert all(sha(path) == value for path, value in before_hashes.items())
    print(json.dumps({
        "状态": "通过",
        "冻结专题JSON": len(frozen),
        "严格门关闭原证函数": baseline["unique_exported_functions"],
        "严格中文门启用原证函数": candidate["unique_exported_functions"],
        "补计函数入口": 39,
        "新增来源关系": added_relations,
        "导航范围指令观察变化": 0,
        "中央文件写入": False,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
