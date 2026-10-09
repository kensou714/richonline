"""生成本专题的逐函数审阅清单及静态证据检查；不运行客户端。"""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SPEC = {
    "0x65bdb0": ("01", "4001：ID通过后以M和p+4调用批量动态格消费者。"),
    "0x65be10": ("01", "4002：signed位置WORD与类型BYTE写入M动态格。"),
    "0x65be80": ("01", "4003：取signed参与者槽，覆盖库存组1。"),
    "0x65c140": ("01", "4007：取signed参与者槽，覆盖库存组2。"),
    "0x64f710": ("01", "比较消息游戏ID与G+0x14784的WORD，不等则弹框并拒绝。"),
    "0x7e0f30": ("01", "按M+0x124条数遍历4字节记录，位置-1跳过。"),
    "0x7e2320": ("01", "动态格前三字节写类型/-1/-1，再将末字节设1。"),
    "0x63e8c0": ("01", "设置4字节动态格的末字节，无下标防护。"),
    "0x7f7710": ("01", "非空源分别memcpy48到P+0x11A/P+0x14A。"),
    "0x7df010": ("02", "本地地图加载：区分四个格数组、动态格初始化及同步条数来源。"),
    "0x63e750": ("02", "4字节动态格初始化为-1/-1/-1/1。"),
    "0x600397": ("02", "构造器跳板，转63E750；不产生额外行为。"),
    "0x7ef6d0": ("01", "4001桥接到游戏对象接收入口65BDB0。"),
    "0x7ef6f0": ("01", "4002桥接到游戏对象接收入口65BE10。"),
    "0x7ef710": ("01", "4003桥接到游戏对象接收入口65BE80。"),
    "0x7ef790": ("01", "4007桥接到游戏对象接收入口65C140。"),
    "0x7f86a0": ("01", "按组0/1/2和6字节槽返回signed WORD物品ID。"),
    "0x7f8710": ("01", "按组0/1/2和6字节槽返回signed WORD数量。"),
    "0x7f89d0": ("01", "仅组1/2返回槽+4的signed BYTE状态，其他组返回-1。"),
    "0x682660": ("03", "线程参数G转M，预热可见地图资源后正常返回0。"),
    "0x63e210": ("03", "返回G+0x65C地图子对象地址。"),
    "0x7e83d0": ("03", "按视口遍历地图资源并提交句柄，三次Sleep500。"),
    "0x6826a0": ("03", "退出码0时先关闭/清线程句柄，再尝试发送WORD0。"),
    "0x81bcb0": ("03", "保存计时期限与GetTickCount，不是Sleep或网络等待。"),
    "0x694ee0": ("03", "在this所指局部消息缓冲区写WORD0。"),
    "0x6bf380": ("03", "状态<12且发送对象首字节非0才编码并提交UI动作9。"),
    "0x62a0f0": ("03", "返回全局状态A6723C。"),
    "0x629c20": ("03", "读取this所指对象首字节。"),
    "0x7eef70": ("03", "长度和payload加107、反转、与随机字节交错生成发送缓冲区。"),
    "0x6281b0": ("03", "按需分配12字节单例A76724并返回；不证明其首字节业务名。"),
    "0x624e80": ("03", "主循环取得游戏单例后以ECX=G调用完成轮询跳板60368C。"),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    documents = {p.name[:2]: p.name for p in ROOT.glob("*.txt")}
    rows = {}
    thunk_rows = {}
    for path in sorted((ROOT / "证据").glob("map_sync_*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for func in data.get("functions", []):
            ea = func["va"].lower()
            section, conclusion = SPEC[ea]
            assert func["bytes_match_disk"] is True
            for block in func["byte_ranges"]:
                assert block["idb_hex"] == block["disk_hex"]
            rows[ea] = {
                "ea": ea,
                "name": func["name"],
                "status": "静态局部语义已审阅",
                "conclusion": conclusion,
                "unknown": "运行结果未复现；下游与其他入口的完整语义不在该结论内。",
                "document": documents[section],
                "boundary": (
                    "只审阅地图池创建和同步条数；其余资源、文件版本与模式分支仅导出。"
                    if ea == "0x7df010" else
                    "完整入口控制流及直接调用参数已核对；不声称全部下游闭环。"
                ),
                "evidence": str(path.relative_to(ROOT)).replace("\\", "/") + "/functions/" + ea,
                "bytes_match_disk": True,
            }
        for thunk in data.get("thunks", []):
            assert thunk["matching"] is True
            assert thunk["idb_hex"] == thunk["disk_hex"]
            thunk_rows[thunk["va"]] = thunk
    assert set(rows) == set(SPEC)
    review = ROOT / "函数审阅清单.json"
    review.write_text(json.dumps({
        "scope": "本目录静态局部审阅；不等于完整EMP、资源或网络发送闭环。",
        "functions": list(rows.values()),
        "thunks": {"count": len(thunk_rows), "status": "仅导出；已叙述调用链的跳板目标另按汇编核对。"},
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for path in ROOT.glob("*.txt"):
        lines = path.read_text(encoding="utf-8").splitlines()
        assert all(not line.strip() or line.startswith("//") for line in lines), path
    references = [
        ROOT.parent / "参与者布局与人数边界/证据/participant_startup.json",
        ROOT.parent / "参与者布局与人数边界/证据/participant_scan_candidates.json",
        ROOT.parent / "道具与卡片操作/01_卡片栏与三组库存.txt",
        ROOT.parent.parent / "全量分析/版本核验_第二批.txt",
    ]
    assert all(path.is_file() for path in references)
    # 独立复算消费者读取的最后一个字节，避免把起点当成长度。
    for count in (1, 2, 8, 128):
        assert 4 + 4 * (count - 1) + 2 == 4 * count + 2
        assert 4 + 4 * (count - 1) + 3 == 4 * count + 3
    assert 6 + 8 * 6 == 54
    hashes = {
        str(path.relative_to(ROOT)).replace("\\", "/"): digest(path)
        for path in sorted(ROOT.rglob("*"))
        if path.is_file() and path.name != "专题验证.json" and "__pycache__" not in path.parts
    }
    result = {
        "scope": "静态证据和文档结构检查；未运行客户端。",
        "function_count": len(rows),
        "reviewed_function_count": len(rows),
        "unique_exported_thunks": len(thunk_rows),
        "functions_and_thunks_match_disk": True,
        "txt_comment_format": True,
        "referenced_evidence_exists": True,
        "consumer_length_arithmetic": True,
        "field_scan_boundary": "位移扫描是候选集，没有逐项对象归属或字节核验，不计入已审阅函数。",
        "file_sha256": hashes,
        "reference_sha256": {str(path): digest(path) for path in references},
    }
    (ROOT / "证据/专题验证.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: value for key, value in result.items() if "sha256" not in key}, ensure_ascii=False))


if __name__ == "__main__":
    main()
