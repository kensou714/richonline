"""合并专题原始证据索引，不把导出数量视为语义分析覆盖。
不修改专题；保留函数清单里的人工结论作为独立依据。
"""
import json
import hashlib
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parent
TOPICS = ROOT.parent / "专题"
COMPLETE_BODY_SOURCES = (
    '异常尾块与清理契约/cleanup_targets_full.json',
    '异常尾块与清理契约/unwind_runtime.json',
)
COMPLETE_NORMALIZED_SOURCES = (
    '专题/资源槽池生产与归还/证据/formal_functions.json',
)


def iter_evidence_sources():
    """专题保留递归规则；指定适配和白名单文件只允许顶层完整函数主体入账。"""
    for path in sorted(TOPICS.rglob('*.json')):
        relative = path.relative_to(ROOT.parent).as_posix()
        yield path, 'normalized' if relative in COMPLETE_NORMALIZED_SOURCES else False
    for relative in COMPLETE_BODY_SOURCES:
        path = ROOT / relative
        if path.is_file():
            yield path, True


def normalized_ranges(ranges):
    """合并紧邻区间；空区间、逆序边界和重叠都表示证据不完整。"""
    result = []
    for lo, hi in sorted(ranges):
        if lo >= hi or (result and lo < result[-1][1]):
            raise ValueError('范围重叠或边界无效')
        if result and lo == result[-1][1]:
            result[-1] = (result[-1][0], hi)
        else:
            result.append((lo, hi))
    return result


def strict_complete_body_address(node, inventory, code_ranges):
    """检查白名单主体的库存主块、完整字节并集及汇编站点；不采嵌套引用。"""
    if not isinstance(node, dict):
        return None
    if any(key in node for key in ('owner', 'owner_va', 'site_va', 'start_va', 'prefix')):
        return None
    if any(any(word in str(node.get(key, '')).lower()
               for word in ('窗口', '导航', '片段', '前缀', 'window', 'navigation', 'fragment', 'prefix'))
           for key in ('scope', 'kind', 'status')):
        return None
    try:
        start, end = int(node['va'], 16), int(node['end_va'], 16)
        va = hex(start)
        declared = inventory[va]
        assembly = node['assembly']
        chunks = node['declared_chunks']
        spans = node['byte_ranges']
        if (node.get('bytes_match_disk') is not True
                or end != int(declared['end_va'], 16)
                or end - start != declared['span_bytes']
                or not isinstance(assembly, list) or not assembly
                or not isinstance(chunks, list) or not chunks
                or not isinstance(spans, list) or not spans
                or int(assembly[0]['va'], 16) != start):
            return None
        chunk_ranges = []
        main_count = 0
        for chunk in chunks:
            lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
            if type(chunk['is_main']) is not bool:
                return None
            if chunk['is_main']:
                main_count += 1
                if (lo, hi) != (start, end):
                    return None
            chunk_ranges.append((lo, hi))
        if main_count != 1:
            return None
        byte_ranges = []
        for span in spans:
            lo, size = int(span['va'], 16), span['size']
            if (type(size) is not int or size <= 0 or span.get('matching') is not True
                    or not isinstance(span['idb_hex'], str)
                    or not isinstance(span['disk_hex'], str)
                    or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', span['idb_hex'])
                    or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', span['disk_hex'])):
                return None
            raw = bytes.fromhex(span['idb_hex'])
            if (len(raw) != size or raw != bytes.fromhex(span['disk_hex'])
                    or not any(a <= lo < lo + size <= b for a, b in code_ranges)):
                return None
            byte_ranges.append((lo, lo + size))
        covered = normalized_ranges(byte_ranges)
        if covered != normalized_ranges(chunk_ranges):
            return None
        sites = []
        for item in assembly:
            site = int(item['va'], 16)
            if (not isinstance(item.get('text'), str) or not item['text'].strip()
                    or not any(lo <= site < hi for lo, hi in covered)):
                return None
            sites.append(site)
        if len(set(sites)) != len(sites):
            return None
        return va
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def strict_normalized_body_address(node, source_path, source_data, source_sha,
                                   inventory, code_ranges):
    """只把已绑定原始记录的无损适配转成完整主体，不遍历 JSON 字符串或原证附件。"""
    if not isinstance(node, dict):
        return None
    try:
        if (node['source_path'] != source_path or node['source_sha256'] != source_sha
                or not isinstance(node['source_pointer'], str)
                or not re.fullmatch(r'/functions/(0|[1-9][0-9]*)', node['source_pointer'])):
            return None
        index = int(node['source_pointer'].split('/')[-1])
        original = source_data['functions'][index]
        for record in (node, original):
            if any(key in record for key in ('owner', 'owner_va', 'site_va', 'start_va', 'prefix')):
                return None
            if any(any(word in str(record.get(key, '')).lower()
                       for word in ('窗口', '导航', '片段', '前缀', 'window', 'navigation', 'fragment', 'prefix'))
                   for key in ('scope', 'kind', 'status')):
                return None
        if (node['source_record_json'] != json.dumps(original, ensure_ascii=False,
                                                     separators=(',', ':'))
                or node['source_field_pointers'] != {
                    key: f'/functions/{index}/{key}' for key in original
                    if key in ('seed_va', 'end_va', 'name', 'assembly', 'pseudocode',
                               'decompile_error', 'chunk_byte_ranges', 'pending_status')}):
            return None
        if node['va'] != original['seed_va']:
            return None
        chunks = node['normalized_chunks']
        assembly = node['normalized_assembly']
        if (not isinstance(chunks, list) or not chunks
                or not isinstance(assembly, list) or not assembly
                or len(chunks) != len(original['chunk_byte_ranges'])
                or len(assembly) != len(original['assembly'])):
            return None
        normalized_ranges = []
        for adapted, raw in zip(chunks, original['chunk_byte_ranges']):
            if (adapted['original'] != raw or adapted['start_va'] != raw['start_va']
                    or adapted['size'] != raw['size']):
                return None
            byte_string = raw['idb_hex']
            if (type(raw['size']) is not int or raw['size'] <= 0
                    or not isinstance(byte_string, str)
                    or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', byte_string)
                    or hashlib.sha256(bytes.fromhex(byte_string)).hexdigest() != raw['sha256']):
                return None
            normalized_ranges.append(dict(va=adapted['start_va'], size=adapted['size'],
                                          idb_hex=byte_string, disk_hex=raw['disk_hex'],
                                          matching=raw['matching']))
        normalized_assembly = []
        for adapted, raw in zip(assembly, original['assembly']):
            if (adapted['original'] != raw or adapted['site_va'] != raw['site_va']
                    or adapted['text'] != raw['text'] or adapted['is_code'] is not True
                    or raw['is_code'] is not True):
                return None
            normalized_assembly.append(dict(va=adapted['site_va'], text=adapted['text']))
        if (node['declared_chunks'][0] != dict(start_va=node['va'],
                                               end_va=original['end_va'], is_main=True)
                or len(node['declared_chunks']) != len(chunks)):
            return None
        for adapted, declared in zip(chunks, node['declared_chunks']):
            if (declared['start_va'] != adapted['start_va']
                    or int(declared['end_va'], 16) != int(adapted['start_va'], 16) + adapted['size']):
                return None
        body = dict(va=node['va'], end_va=original['end_va'], bytes_match_disk=True,
                    assembly=normalized_assembly, declared_chunks=node['declared_chunks'],
                    byte_ranges=normalized_ranges)
        return strict_complete_body_address(body, inventory, code_ranges)
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return None


def strict_chinese_function_address(node, known, code_ranges, inventory):
    """只接纳已在库存中、逐条字节核验的中文完整函数原证。"""
    if any(key in node for key in ('start_va', 'owner_va', 'site_va', '范围起点')):
        return None
    if any(any(word in str(node.get(key, '')).lower()
               for word in ('窗口', '导航', '片段', 'window', 'navigation', 'fragment'))
           for key in ('scope', 'kind', 'status', '状态')):
        return None
    try:
        start = int(node['地址'], 16)
        va = hex(start)
        size = node['大小']
        rows = node['完整汇编']
        if (va not in known or type(size) is not int or size <= 0
                or not isinstance(rows, list) or not rows):
            return None
        # 同一记录若兼带英文地址，不能借中文正文给另一入口背书。
        for key in ('va', 'address', 'ea'):
            if key in node and node[key] is not None:
                other = node[key] if isinstance(node[key], int) else int(node[key], 16)
                if other != start:
                    return None
        declared = inventory[va]
        if (size != declared['span_bytes']
                or start + size != int(declared['end_va'], 16)
                or node.get('字节一致') is not True
                or int(rows[0]['地址'], 16) != start):
            return None
        previous_end = None
        primary_end = None
        for row in rows:
            site = int(row['地址'], 16)
            audit = row['字节核验']
            if not isinstance(audit, dict):
                return None
            idb_hex = audit['IDB字节']
            disk_hex = audit['磁盘字节']
            if (audit.get('匹配') is not True
                    or not isinstance(idb_hex, str) or not isinstance(disk_hex, str)
                    or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', idb_hex)
                    or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+', disk_hex)):
                return None
            raw = bytes.fromhex(idb_hex)
            if (raw != bytes.fromhex(disk_hex)
                    or not any(lo <= site < site + len(raw) <= hi
                               for lo, hi in code_ranges)):
                return None
            if previous_end is not None:
                if site < previous_end:
                    return None
                if site != previous_end and primary_end is None:
                    primary_end = previous_end
            previous_end = site + len(raw)
        # IDA FuncItems 可含不连续尾块；大小与库存描述的是首连续主块。
        if (primary_end if primary_end is not None else previous_end) != start + size:
            return None
        return va
    except (KeyError, TypeError, ValueError):
        return None


def main():
    records={}
    instruction_observations={}
    navigation_windows={}
    functions=json.loads((ROOT/'functions.json').read_text(encoding='utf-8'))
    known={r['va'] for r in functions}
    inventory_by_va={r['va']:r for r in functions}
    segments=json.loads((ROOT/'segments.json').read_text(encoding='utf-8'))
    code_ranges=[(int(s['start_va'],16),int(s['end_va'],16))
                 for s in segments if s['permission'] & 1]
    for path, complete_bodies_only in iter_evidence_sources():
        data=json.loads(path.read_text(encoding="utf-8-sig"))
        if complete_bodies_only == 'normalized':
            # 唯一允许的原件是适配文件同目录 bounded_raw.json，不接受记录指定的任意路径。
            original_path=path.with_name('bounded_raw.json')
            try:
                raw=original_path.read_bytes()
                source_data=json.loads(raw)
                source_sha=hashlib.sha256(raw).hexdigest()
                bodies=data.get('functions') if isinstance(data,dict) else None
                if (isinstance(bodies,list)
                        and data.get('disk_sha256') == source_data.get('disk_sha256')):
                    for body in bodies:
                        va=strict_normalized_body_address(
                            body,original_path.relative_to(ROOT.parent).as_posix(),
                            source_data,source_sha,inventory_by_va,code_ranges)
                        if va is not None:
                            record=records.setdefault(va,dict(
                                va=va,evidence=[],status='已导出待按专题清单复核'))
                            record['evidence'].append(path.relative_to(ROOT.parent).as_posix())
            except (OSError,UnicodeError,ValueError,AttributeError):
                pass
            # 成功或拒绝都不递归适配附件，不从 original 或 source_record_json 兜底入账。
            continue
        if complete_bodies_only:
            # 不调用递归 walker，文件内 thunks、owner、前缀和调用站点均不是新主体。
            bodies=data.get('functions') if isinstance(data,dict) else None
            if isinstance(bodies,list):
                for body in bodies:
                    va=strict_complete_body_address(body,inventory_by_va,code_ranges)
                    if va is not None:
                        record=records.setdefault(va,dict(
                            va=va,evidence=[],status='已导出待按专题清单复核'))
                        record['evidence'].append(path.relative_to(ROOT.parent).as_posix())
            continue
        def walk(node, address_key=None):
            if isinstance(node,list):
                for child in node: walk(child)
            elif isinstance(node,dict):
                # 有些未声明代码的完整字节放在父节点 block 内；只接纳明确
                # 标为未声明、跨度正确且 IDA/磁盘一致的范围，绝不推造函数入口。
                block=node.get('block')
                scope=node.get('scope', '')
                if (isinstance(scope,str) and ('未声明' in scope or '未定义' in scope)
                        and isinstance(block,dict)):
                    try:
                        start=int(block['va'],16)
                        end=int(block.get('end_va',block.get('end')),16)
                        raw=bytes.fromhex(block['ida_hex'])
                        matched=(block.get('equal',block.get('matching')) is True
                                 and raw == bytes.fromhex(block['disk_hex']))
                        if (matched and start < end and end-start == block['size'] == len(raw)
                                and any(a <= start < end <= b for a,b in code_ranges)
                                and hex(start) not in known):
                            record=records.setdefault(hex(start),dict(
                                va=hex(start),evidence=[],
                                status='未声明人工范围原证；不代表完整函数边界'))
                            record['evidence'].append(path.relative_to(ROOT.parent).as_posix())
                    except (KeyError,TypeError,ValueError):
                        pass
                # 人工窗口可能包含相邻函数、尾指令或数据；不能把start_va当函数入口。
                # 保存独立导航，按完整字节长度与代码段边界筛选，不提升语义状态。
                # 新窗口原证用va/end_va，完整字节放在byte_range；兼容旧的扁平格式。
                window_start=node.get('start_va')
                window_bytes=node
                window_scope=node.get('scope', node.get('kind', node.get('status', '')))
                item_window=(isinstance(node.get('raw_range'),dict)
                             and isinstance(node.get('items'),list)
                             and isinstance(window_scope,str)
                             and ('未声明' in window_scope or '未定义' in window_scope))
                nested_window=(isinstance(node.get('byte_range'),dict)
                               and isinstance(node.get('kind'),str)
                               and ('未定义' in node['kind'] or '未声明' in node['kind']))
                if item_window:
                    window_bytes=node['raw_range']
                if window_start is None and nested_window:
                    window_start=node.get('va')
                    window_bytes=node['byte_range']
                window_candidate=(window_start is not None and 'end_va' in node
                                  and (isinstance(node.get('assembly'),list) or item_window))
                if (window_start is not None and 'end_va' in node
                        and (isinstance(node.get('assembly'), list) or item_window)
                        and 'idb_hex' in window_bytes):
                    try:
                        start=int(window_start,16)
                        end=int(node['end_va'],16)
                        nested_valid=(not (nested_window or item_window) or (
                            int(window_bytes['va'],16) == start and window_bytes['size'] == end-start
                            and window_bytes.get('matching') is True
                            and window_bytes['idb_hex'] == window_bytes['disk_hex']))
                        raw=bytes.fromhex(window_bytes['idb_hex'])
                        has_disk='disk_hex' in window_bytes
                        same_bytes=(has_disk and raw == bytes.fromhex(window_bytes['disk_hex']))
                        # 旧导航允许缺少磁盘副本，但明确不一致的记录不能接纳。
                        navigation_valid=(window_bytes.get('matching') is not False
                                          and (not has_disk or same_bytes))
                        range_valid=(same_bytes and window_bytes.get('matching') is True
                                     and window_bytes.get('size',end-start) == end-start)
                        if (nested_valid and navigation_valid and end > start
                                and len(raw) == end-start
                                and any(a <= start < end <= b for a,b in code_ranges)):
                            item=navigation_windows.setdefault((start,end),dict(
                                start_va=hex(start),end_va=hex(end),size=end-start,evidence=[],
                                scope='人工代码导航窗口；不确认函数入口、边界或完整语义',
                                source_scopes=[]))
                            item['evidence'].append(path.relative_to(ROOT.parent).as_posix())
                            if isinstance(window_scope,str):
                                item['source_scopes'].append(window_scope)
                            # 明确注明未声明的人工范围仍保留在范围台账；
                            # 起点不在函数清单才接纳，绝不由窗口推造函数入口。
                            scope=window_scope
                            if (isinstance(scope,str)
                                    and ('未声明' in scope or '未定义' in scope)
                                    and range_valid
                                    and hex(start) not in known):
                                record=records.setdefault(hex(start),dict(
                                    va=hex(start),evidence=[],
                                    status='未声明人工范围原证；不代表完整函数边界'))
                                record['evidence'].append(path.relative_to(ROOT.parent).as_posix())
                    except (KeyError,ValueError,TypeError):
                        pass
                chinese_va=strict_chinese_function_address(node,known,code_ranges,inventory_by_va)
                va=node.get("va") or node.get("address") or node.get("ea") or chinese_va or address_key
                bodies=[node.get(key) for key in ('pseudocode','disassembly','assembly','instructions')]
                if chinese_va is not None:
                    bodies.append(node['完整汇编'])
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
                                          and node['size'] > 0 and node.get('matching') is True
                                          and bytes.fromhex(node['idb_hex']) == bytes.fromhex(node['disk_hex'])
                                          and any(start <= range_va < range_va+node['size'] <= end
                                                  for start, end in code_ranges))
                    except (KeyError, TypeError, ValueError):
                        pass
                # 窗口即使被完整性校验拒绝，也不能借通用正文分支重新入账；
                # 起点碰巧等于函数头同样不代表导出了该声明函数的正文。
                if (not window_candidate and va is not None
                        and (any(body is not None for body in bodies) or raw_code_range)):
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
