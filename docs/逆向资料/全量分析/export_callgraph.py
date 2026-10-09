"""只读分批提取直接调用与函数尾跳转，不把间接调用伪装成已解析边。
在 IDA-MCP execute_python 中加载后调用 export_batch(db)；可重复续跑。
"""
import json
import pathlib
import time

GRAPH_ROOT = pathlib.Path("F:/大富翁online/Richonline/docs/逆向资料/全量分析")
def export_batch(db, batch_size=1000, seconds=35):
    rows = json.loads((GRAPH_ROOT / "functions.json").read_text(encoding="utf-8"))
    thunks = {r["va"]:r["target_va"] for r in rows if "target_va" in r}
    graph_dir = GRAPH_ROOT / "callgraph"
    graph_dir.mkdir(exist_ok=True)
    done = set()
    for path in graph_dir.glob("batch_*.json"):
        done.update(r["va"] for r in json.loads(path.read_text(encoding="utf-8")))
    starts = {r["va"] for r in rows}
    result = []
    began = time.monotonic()
    for row in rows:
        if row["va"] in done:
            continue
        f = db.functions.get_at(int(row["va"],16))
        out = dict(va=row["va"], edges=[], unresolved_indirect=[], error=None)
        try:
            for ins in db.functions.get_instructions(f):
                mnemonic = db.instructions.get_mnemonic(ins)
                if mnemonic not in ("call","jmp"):
                    continue
                refs = list(db.xrefs.from_ea(ins.ea))
                # 16/17 是远/近 call；18/19 是远/近 jump。
                code_refs = [r for r in refs if int(r.type) in (16,17,18,19)]
                if not code_refs:
                    out["unresolved_indirect"].append(dict(site=hex(ins.ea),kind=mnemonic))
                for ref in code_refs:
                    target = hex(ref.to_ea)
                    if mnemonic == "jmp" and target not in starts:
                        continue
                    normalized, seen = target, set()
                    while normalized in thunks and normalized not in seen:
                        seen.add(normalized)
                        normalized = thunks[normalized]
                    out["edges"].append(dict(site=hex(ins.ea),kind=mnemonic,
                        target_va=target,normalized_target_va=normalized))
        except Exception as exc:
            out["error"]=str(exc)
        result.append(out)
        if len(result)>=batch_size or time.monotonic()-began>=seconds:
            break
    if result:
        file=graph_dir / ("batch_"+result[0]["va"][2:]+".json")
        file.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    return dict(processed=len(result), total_done=len(done)+len(result), total=len(rows),
                seconds=round(time.monotonic()-began,2),errors=sum(r["error"] is not None for r in result))

