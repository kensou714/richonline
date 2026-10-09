"""合并专题原始证据索引，不把导出数量视为语义分析覆盖。
不修改专题；保留函数清单里的人工结论作为独立依据。
"""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parent
TOPICS = ROOT.parent / "专题"
def main():
    records={}
    for path in sorted(TOPICS.rglob("*.json")):
        data=json.loads(path.read_text(encoding="utf-8-sig"))
        def walk(node):
            if isinstance(node,list):
                for child in node: walk(child)
            elif isinstance(node,dict):
                va=node.get("va") or node.get("address") or node.get("ea")
                if va is not None and ("pseudocode" in node or "disassembly" in node or "assembly" in node):
                    if isinstance(va,int): va=hex(va)
                    try: va=hex(int(str(va),16))
                    except ValueError: return
                    record=records.setdefault(va,dict(va=va,evidence=[],status="已导出待按专题清单复核"))
                    record["evidence"].append(str(path.relative_to(ROOT.parent)).replace("\\","/"))
                for value in node.values():
                    if isinstance(value,(dict,list)):walk(value)
        walk(data)
    for record in records.values():record["evidence"]=sorted(set(record["evidence"]))
    functions=json.loads((ROOT/"functions.json").read_text(encoding="utf-8"))
    known={r["va"] for r in functions}
    result=dict(unique_exported_functions=len(records),total_identified_functions=len(functions),
                outside_inventory=sorted(set(records)-known),
                note="证据导出不是逐函数已分析数量；人工状态见各专题函数清单",
                functions=sorted(records.values(),key=lambda r:int(r["va"],16)))
    (ROOT/"evidence_coverage.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k!="functions"},ensure_ascii=False))
if __name__=="__main__":main()

