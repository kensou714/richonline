"""合并明确写有状态和结论的人工记录，保留来源与分级，不从导出量推断完成度。"""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOPICS = ROOT.parent / '专题'

ADDRESS_KEYS = ('va', 'address', 'ea', '地址')


def walk(node, pointer='', mapping_key=None):
    if isinstance(node, dict):
        # 部分手工清单以地址作直接字典键；只补这个节点，不修改源数据或继承给后代。
        if (not any(key in node for key in ADDRESS_KEYS)
                and isinstance(mapping_key, str)
                and re.fullmatch(r'0[xX][0-9a-fA-F]+', mapping_key)):
            yield dict(node, va=mapping_key), pointer or '/'
        else:
            yield node, pointer or '/'
        for key, value in node.items():
            yield from walk(value, pointer + '/' + str(key).replace('~', '~0').replace('/', '~1'), key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, pointer + '/' + str(index))


def review_record(node, source, pointer, status, conclusion):
    record = dict(
        source=source, json_pointer=pointer, status=status, conclusion=conclusion,
        unknown=node.get('unknown', node.get('unknowns', node.get('未知项',
                         node.get('unresolved', node.get('boundary'))))),
        evidence=node.get('evidence', node.get('evidence_path', node.get('证据路径',
                          node.get('review_sources')))))
    # 原始边界与复用来源分别保留，不能把复用记录提升成新增完整语义。
    for key in ('boundary', 'reuse_reference'):
        if key in node:
            record[key] = node[key]
    return record


def explicit_range(node, status):
    # 只接受清单明确声明的未定义范围；普通start_va窗口不是函数审阅。
    if not isinstance(status, str) or not any(word in status for word in ('未声明', '未定义')):
        return None
    start = node.get('start_va', node.get('范围起点'))
    end = node.get('end_va', node.get('结束地址'))
    return (start, end) if start is not None and end is not None else None


def main():
    inventory = json.loads((ROOT / 'functions.json').read_text(encoding='utf-8'))
    known = {int(item['va'], 16) for item in inventory}
    collected = {}
    unrecognized = {}
    coverage = json.loads((ROOT / 'evidence_coverage.json').read_text(encoding='utf-8'))
    exported_ranges = {int(row['va'], 16): row for row in coverage['unrecognized_code_ranges']}
    errors = []
    sources = list(TOPICS.rglob('*.json'))
    # 尾块专题在全量分析内；只白名单读取显式局部清单，
    # 不递归读取生成的coverage，避免将自己的汇总再次算成审阅来源。
    cleanup_reviews = ROOT / '异常尾块与清理契约/function_review.json'
    if cleanup_reviews.exists():
        sources.append(cleanup_reviews)
    for path in sorted(sources):
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        for node, pointer in walk(data):
            address = node.get('va', node.get('address', node.get('ea', node.get('地址'))))
            status = node.get('status', node.get('review_status', node.get('状态')))
            conclusion = node.get('conclusion', node.get('结论'))
            bounds = explicit_range(node, status) if address is None else None
            if bounds is not None:
                address = bounds[0]
            if address is None or not isinstance(status, str) or not isinstance(conclusion, str):
                continue
            try:
                va = address if isinstance(address, int) else int(address, 16)
                if bounds is not None:
                    end = bounds[1] if isinstance(bounds[1], int) else int(bounds[1], 16)
                    if end <= va:
                        raise ValueError('范围结束须大于起点')
            except (ValueError, TypeError):
                errors.append(dict(source=str(path.relative_to(ROOT.parent)), pointer=pointer,
                                   reason='人工记录地址格式不合法'))
                continue
            if va not in known or bounds is not None:
                if va not in known and va in exported_ranges:
                    # 已有原始区间证据的未定义入口独立留档，不混进29019函数覆盖率。
                    entry = unrecognized.setdefault(va, dict(
                        va=hex(va), evidence=exported_ranges[va]['evidence'], reviews=[]))
                    record = review_record(
                        node, path.relative_to(ROOT.parent).as_posix(), pointer, status, conclusion)
                    if bounds is not None:
                        record['end_va'] = hex(end)
                    entry['reviews'].append(record)
                else:
                    errors.append(dict(source=str(path.relative_to(ROOT.parent)), pointer=pointer,
                                       va=hex(va), reason='未在历史函数入口清单且无单列区间原证，需人工复核'))
                continue
            entry = collected.setdefault(va, dict(va=hex(va), reviews=[]))
            entry['reviews'].append(review_record(
                node, path.relative_to(ROOT.parent).as_posix(), pointer, status, conclusion))
    migration = ROOT / '首批人工审阅迁移.json'
    if migration.exists():
        # 主条目显式迁移；辅助引用另存原文件，不能冒充主审阅项目。
        for index, node in enumerate(json.loads(migration.read_text(encoding='utf-8'))['functions']):
            va = int(node['va'], 16)
            if va not in known:
                errors.append(dict(va=hex(va), reason='首批迁移入口不在清单'))
                continue
            entry = collected.setdefault(va, dict(va=hex(va), reviews=[]))
            entry['reviews'].append(dict(source=migration.relative_to(ROOT.parent).as_posix(),
                json_pointer='/functions/' + str(index), status=node['status'],
                conclusion=node['conclusion'], unknown=node['unknown'], evidence=node['evidence'],
                original_source=node['source'], original_topic=node['topic'],
                note='原级保留，不同专题字母等级不能直接等价'))
    bridges_path = TOPICS / '游戏分派桥接/证据/dispatch_bridges_raw.json'
    if bridges_path.exists():
        bridges = json.loads(bridges_path.read_text(encoding='utf-8'))
        for index, node in enumerate(bridges['entries']):
            va = int(node['bridge'], 16)
            if not (node.get('template_verified') and node.get('registration_structure_verified')
                    and node['thunk_audit'].get('target_verified')
                    and node['handler_thunk_audit'].get('target_verified') and va in known):
                errors.append(dict(va=hex(va), reason='桥接证据结构验证缺失'))
                continue
            entry = collected.setdefault(va, dict(va=hex(va), reviews=[]))
            entry['reviews'].append(dict(source=bridges_path.relative_to(ROOT.parent).as_posix(),
                json_pointer='/entries/' + str(index), status='桥接ABI模板核对',
                conclusion='双参数cdecl转thiscall，this偏移为0，消息指针原传；仅限已匹配24字节模板',
                unknown=node['unknowns'], evidence=node['evidence_path'],
                message_code=node['code'], handler=node['handler'],
                note='桥接函数与业务handler是不同入口；不将handler标为已分析'))
    states = Counter(r['status'] for entry in collected.values() for r in entry['reviews'])
    result = dict(
        scope='合并专题JSON显式人工记录及首批主条目迁移；无原结论的迁移项保留null',
        warning='同一函数可能有多份局部审阅；不选最高状态，不自动合成为全函数已分析',
        total_identified_functions=len(inventory),
        unique_functions_with_explicit_reviews=len(collected),
        review_record_count=sum(states.values()), raw_status_counts=dict(sorted(states.items())),
        unrecognized_range_reviews=sorted(unrecognized.values(), key=lambda item: int(item['va'], 16)),
        invalid_records=errors,
        functions=sorted(collected.values(), key=lambda item: int(item['va'], 16)))
    (ROOT / 'review_coverage.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                            encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key not in {'functions', 'unrecognized_range_reviews'}},
                     ensure_ascii=False))

if __name__ == '__main__':
    main()
