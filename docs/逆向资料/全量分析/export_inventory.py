"""在已打开的当前 IDA 数据库中只读导出全量函数、跳板和引用台账。
通过 IDA-MCP execute_python 执行；不修改函数、类型或数据库。
"""
import collections
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path("F:/大富翁online/Richonline")
OUTPUT = ROOT / "docs/逆向资料/全量分析"
EXPECTED = "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77"

def write_json(name, value):
    (OUTPUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

def export_inventory(db):
    actual = hashlib.sha256((ROOT / "RnClient.exe").read_bytes()).hexdigest()
    if actual != EXPECTED:
        raise ValueError("客户端指纹变化，请复核数据库与输入后另建版本台账")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    rows, thunks = [], []
    for func in db.functions.get_all():
        ea = func.start_ea
        span = func.end_ea - ea
        flags = func.flags
        row = dict(va=hex(ea), end_va=hex(func.end_ea), span_bytes=span,
                   name=db.functions.get_name(func), ida_flags=flags,
                   status="未分析", classification="普通函数待分析")
        if flags & 4:
            row["classification"] = "IDA库标记候选"
        if flags & 128:
            row["classification"] = "IDA跳板候选"
        raw = db.bytes.get_bytes_at(ea, min(6, span)) if span else None
        if raw and span == 5 and raw[0] == 0xE9:
            target = ea + 5 + struct.unpack("<i", raw[1:5])[0]
            row.update(classification="直接跳板已识别", target_va=hex(target))
            thunks.append(dict(va=hex(ea), target_va=hex(target),
                               bytes=raw.hex(), kind="E9 rel32"))
        rows.append(row)
    strings = [dict(va=hex(s.address), text=s.contents.decode("utf-8", "replace"))
               for s in db.strings.get_all()]
    names = [dict(va=hex(ea), name=name) for ea, name in db.names.get_all()]
    segments = [dict(name=db.segments.get_name(s), start_va=hex(s.start_ea),
                     end_va=hex(s.end_ea), permission=s.perm, bitness=s.bitness)
                for s in db.segments.get_all()]
    write_json("functions.json", rows)
    write_json("strings.json", strings)
    write_json("names.json", names)
    write_json("segments.json", segments)
    write_json("thunks.json", thunks)
    meta = dict(input="RnClient.exe", sha256=actual, date="2026-10-09",
                function_count=len(rows), string_count=len(strings), name_count=len(names),
                classification_counts=dict(collections.Counter(r["classification"] for r in rows)),
                scope="IDA当前已识别范围；分类不等于语义审阅；人工审阅保存在独立专题清单")
    write_json("inventory.json", meta)
    return meta

def export_reference_index(db):
    # 引用计数取自现有 IDB，不会补造数据项或创建交叉引用。
    name_rows = json.loads((OUTPUT / "names.json").read_text(encoding="utf-8"))
    strings = json.loads((OUTPUT / "strings.json").read_text(encoding="utf-8"))
    funcs = json.loads((OUTPUT / "functions.json").read_text(encoding="utf-8"))
    func_starts = {int(r["va"], 16) for r in funcs}
    string_starts = {int(r["va"], 16) for r in strings}
    data_candidates = [r for r in name_rows if int(r["va"], 16) not in func_starts
                       and int(r["va"], 16) not in string_starts]
    references = []
    for kind, records in [("字符串", strings), ("命名数据候选", data_candidates)]:
        for row in records:
            refs, seen = [], set()
            for ref in db.xrefs.to_ea(int(row["va"], 16)):
                key = (ref.from_ea, ref.to_ea, str(ref.type))
                if key in seen:
                    continue
                seen.add(key)
                parent = db.functions.get_at(ref.from_ea)
                refs.append(dict(from_va=hex(ref.from_ea), type=str(ref.type),
                                 function_va=hex(parent.start_ea) if parent else None))
            references.append(dict(kind=kind, target=row, references=refs))
    write_json("data_references.json", references)
    return dict(targets=len(references), references=sum(len(r["references"]) for r in references))

