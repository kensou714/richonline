"""核验网络专题证据的输入版本与导出完整性；不修改客户端或 IDB。"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT.parents[3] / "RnClient.exe"
EXPECTED = "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77"
actual = hashlib.sha256(CLIENT.read_bytes()).hexdigest()
assert actual == EXPECTED, "客户端指纹变化，不可复用当前地址结论"

reviewed = {
    "0x8ccc20", "0x8cd400", "0x8ce1b0", "0x8cd270", "0x8cd1e0",
    "0x8cd2c0", "0x8ce040", "0x8ce2a0", "0x8ce140", "0x8cd220",
    "0x8cd790", "0x8cd7d0", "0x8cd820", "0x8ccbb0", "0x8cca10",
    "0x8cd310", "0x8cd890", "0x8cd9e0", "0x8cdc80", "0x8cdeb0",
    "0x8cdf60", "0x8cdbf0", "0x8cc970", "0x8ce220", "0x8ce320",
    "0x8ce370", "0x8ce0d0", "0x625310", "0x729220", "0x749a20",
    "0x6befb0",
}
partial_callers = {"0x74b720", "0x74d650"}
inventory, artifacts = [], []
for name in ["network_workers.json", "dual_text_channel.json",
             "dual_text_callers.json", "dual_text_callback.json"]:
    path = ROOT / "证据" / name
    content = path.read_bytes()
    rows = json.loads(content.decode("utf-8"))
    rows = rows if isinstance(rows, list) else [rows]
    artifacts.append({"文件": "证据/" + name, "SHA-256": hashlib.sha256(content).hexdigest(),
                      "函数数": len(rows)})
    for row in rows:
        assert row["pseudocode"] and row["assembly"], row["va"]
        status = ("函数及链路静态复核" if row["va"] in reviewed else
                  "只复核文本通道调用位置" if row["va"] in partial_callers else
                  "候选函数初读，业务未闭环")
        inventory.append({"va": row["va"], "end_va": row["end_va"], "状态": status,
                          "证据": "证据/" + name,
                          "伪代码行数": len(row["pseudocode"]),
                          "汇编行数": len(row["assembly"])})
assert len({row["va"] for row in inventory}) == len(inventory)
for name in ["winsock_import_xrefs.json", "dual_text_links.json"]:
    content = (ROOT / "证据" / name).read_bytes()
    json.loads(content.decode("utf-8"))
    artifacts.append({"文件": "证据/" + name,
                      "SHA-256": hashlib.sha256(content).hexdigest()})
for path in ROOT.glob("*.txt"):
    text = path.read_text(encoding="utf-8")
    in_block = False
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("/*"):
            in_block = True
        assert in_block or stripped.startswith("//"), (path.name, n)
        if "*/" in stripped:
            in_block = False
    assert not in_block, path.name
summary = {"日期": "2026-10-09", "输入": str(CLIENT), "SHA-256": actual,
           "方式": "IDA-MCP 只读导出；未执行客户端，未修改 IDB/EXE",
           "函数总数": len(inventory), "函数及链路静态复核": len(reviewed),
           "只复核调用位置": len(partial_callers), "证据文件": artifacts}
(ROOT / "函数审阅清单.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
(ROOT / "证据/采集清单.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))
