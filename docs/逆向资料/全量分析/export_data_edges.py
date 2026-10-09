"""全函数数据引用台账：保留IDA引用类型和来源指令，不猜测变量类型。"""
import json
from pathlib import Path
ROOT = Path("F:/大富翁online/Richonline/docs/逆向资料/全量分析")
def export_data_edges(db):
    targets={}
    for func in db.functions.get_all():
        for ins in db.functions.get_instructions(func):
            for ref in db.xrefs.from_ea(ins.ea):
                kind=int(ref.type)
                if kind not in (1,2,3,4):
                    continue
                target=hex(ref.to_ea)
                targets.setdefault(target,set()).add((hex(func.start_ea),hex(ins.ea),kind))
    rows=[]
    for target,refs in targets.items():
        rows.append(dict(va=target,references=[
            dict(function_va=f,site=site,kind=kind)
            for f,site,kind in sorted(refs,key=lambda r:(int(r[0],16),int(r[1],16),r[2]))]))
    rows.sort(key=lambda r:int(r["va"],16))
    result=dict(scope="IDA类型1偏移/2写/3读/4文本引用；包含导入、常量、代码指针和变量，非全部全局变量",
                targets=len(rows),references=sum(len(r["references"]) for r in rows),items=rows)
    (ROOT/"all_data_edges.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    return {k:v for k,v in result.items() if k!="items"}

