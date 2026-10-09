"""合并专题原始证据索引，不把导出数量视为语义分析覆盖。
不修改专题；保留函数清单里的人工结论作为独立依据。
"""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parent
TOPICS = ROOT.parent / "专题"
def main():
    records={}
    instruction_observations={}
    navigation_windows={}
    segments=json.loads((ROOT/'segments.json').read_text(encoding='utf-8'))
    code_ranges=[(int(s['start_va'],16),int(s['end_va'],16))
                 for s in segments if s['permission'] & 1]
    for path in sorted(TOPICS.rglob("*.json")):
        data=json.loads(path.read_text(encoding="utf-8-sig"))
        def walk(node, address_key=None):
            if isinstance(node,list):
                for child in node: walk(child)
            elif isinstance(node,dict):
                # 人工窗口可能包含相邻函数、尾指令或数据；不能把start_va当函数入口。
                # 保存独立导航，按完整字节长度与代码段边界筛选，不提升语义状态。
                # 新窗口原证用va/end_va，完整字节放在byte_range；兼容旧的扁平格式。
                window_start=node.get('start_va')
                window_bytes=node
                nested_window=(isinstance(node.get('byte_range'),dict)
                               and isinstance(node.get('kind'),str)
                               and ('未定义' in node['kind'] or '未声明' in node['kind']))
                if window_start is None and nested_window:
                    window_start=node.get('va')
                    window_bytes=node['byte_range']
                if (window_start is not None and 'end_va' in node
                        and isinstance(node.get('assembly'), list) and 'idb_hex' in window_bytes):
                    try:
                        start=int(window_start,16)
                        end=int(node['end_va'],16)
                        nested_valid=(not nested_window or (
                            int(window_bytes['va'],16) == start and window_bytes['size'] == end-start
                            and window_bytes.get('matching') is True
                            and window_bytes['idb_hex'] == window_bytes['disk_hex']))
                        if (nested_valid and end > start
                                and len(bytes.fromhex(window_bytes['idb_hex'])) == end-start
                                and any(a <= start < end <= b for a,b in code_ranges)):
                            item=navigation_windows.setdefault((start,end),dict(
                                start_va=hex(start),end_va=hex(end),size=end-start,evidence=[],
                                scope='人工代码导航窗口；不确认函数入口、边界或完整语义',
                                source_scopes=[]))
                            item['evidence'].append(path.relative_to(ROOT.parent).as_posix())
                            if isinstance(node.get('scope'),str):
                                item['source_scopes'].append(node['scope'])
                    except (KeyError,ValueError,TypeError):
                        pass
                va=node.get("va") or node.get("address") or node.get("ea") or address_key
                bodies=[node.get(key) for key in ('pseudocode','disassembly','assembly','instructions')]
                # 单条字面/立即数扫描的assembly是字符串，只有指令站点而非函数范围。
                # 保留为线索，不能把恰好位于函数头的扫描命中也计为函数原证。
                single_instruction=(isinstance(node.get('assembly'),str)
                                    and 'function' in node and 'pseudocode' not in node
                                    and 'byte_ranges' not in node and 'end_va' not in node)
                # 某些未声明代码区间只保存 idb_hex/disk_hex/size/kind，
                # 没有伪代码字段；只要地址落在可执行段且两份字节齐全，
                # 仍应作为范围原证单列，不能在合并阶段误报为非法入口。
                raw_code_range = False
                kind = node.get('kind', '')
                if isinstance(kind, str) and ('未定义' in kind or '未声明' in kind):
                    try:
                        range_va = va if isinstance(va, int) else int(va, 16)
                        raw_code_range = (len(bytes.fromhex(node['idb_hex'])) == node['size']
                                          and len(bytes.fromhex(node['disk_hex'])) == node['size']
                                          and node['size'] > 0 and 'matching' in node
                                          and any(start <= range_va < end
                                                  for start, end in code_ranges))
                    except (KeyError, TypeError, ValueError):
                        pass
                if va is not None and (any(body is not None for body in bodies) or raw_code_range):
                    if isinstance(va,int): va=hex(va)
                    try: va=hex(int(str(va),16))
                    except ValueError: return
                    collection=instruction_observations if single_instruction else records
                    record=collection.setdefault(va,dict(va=va,evidence=[],status=(
                        "单条指令候选，非函数范围原证" if single_instruction else "已导出待按专题清单复核")))
                    record["evidence"].append(str(path.relative_to(ROOT.parent)).replace("\\","/"))
                # 未定义函数片段可能以十六进制地址作字典键；仍单列，不能增加函数总数。
                for key,value in node.items():
                    if isinstance(value,(dict,list)):
                        candidate=None
                        if isinstance(key,str) and key.startswith('0x'):
                            try: keyed_va=int(key,16)
                            except ValueError: keyed_va=-1
                            # 虚表槽也常以0x24之类作键；只有映射到代码段的键才是VA候选。
                            if any(start <= keyed_va < end for start,end in code_ranges):
                                candidate=key
                        walk(value,candidate)
        walk(data)
    for record in list(records.values())+list(instruction_observations.values()):
        record["evidence"]=sorted(set(record["evidence"]))
    for record in navigation_windows.values():
        record['evidence']=sorted(set(record['evidence']))
        record['source_scopes']=sorted(set(record['source_scopes']))
    functions=json.loads((ROOT/"functions.json").read_text(encoding="utf-8"))
    known={r["va"] for r in functions}
    unidentified=sorted(set(records)-known)
    result=dict(unique_exported_functions=len(set(records)&known),total_identified_functions=len(functions),
                outside_inventory=unidentified,
                unrecognized_code_range_count=len(unidentified),
                unrecognized_code_ranges=[records[va] for va in unidentified],
                instruction_observation_count=len(instruction_observations),
                instruction_observations=sorted(instruction_observations.values(),key=lambda r:int(r['va'],16)),
                navigation_window_count=len(navigation_windows),
                navigation_windows=[navigation_windows[key] for key in sorted(navigation_windows)],
                note="证据导出不是逐函数已分析数量；人工状态见各专题函数清单",
                functions=sorted((record for va,record in records.items() if va in known),key=lambda r:int(r["va"],16)))
    (ROOT/"evidence_coverage.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k not in {"functions","unrecognized_code_ranges","instruction_observations","navigation_windows"}},ensure_ascii=False))
if __name__=="__main__":main()
