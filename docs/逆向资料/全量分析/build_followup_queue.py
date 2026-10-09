"""从全函数清单与显式审阅记录建立可复跑选点队列，不据此宣称函数已完成。"""
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def main():
    inventory = read(ROOT / 'functions.json')
    review_data = read(ROOT / 'review_coverage.json')
    reviews = {row['va']: row['reviews'] for row in review_data['functions']}
    coverage = read(ROOT / 'evidence_coverage.json')
    exports = {row['va'] for row in coverage['functions']}
    incoming = Counter()
    indirect = {}
    for path in sorted((ROOT / 'callgraph').glob('batch_*.json')):
        for function in read(path):
            indirect[function['va']] = len(function['unresolved_indirect'])
            for edge in function['edges']:
                incoming[edge.get('normalized_target_va') or edge['target_va']] += 1
    codes = defaultdict(list)
    bridge_file = ROOT.parent / '专题/游戏分派桥接/证据/dispatch_bridges_raw.json'
    if bridge_file.exists():
        for entry in read(bridge_file)['entries']:
            codes[entry['handler']].append(entry['code'])
    rows = []
    for function in inventory:
        va = function['va']
        row = dict(va=va, end_va=function['end_va'], name=function['name'],
                   classification=function['classification'], span_bytes=function['span_bytes'],
                   direct_incoming_edges=incoming[va],
                   unresolved_indirect_sites=indirect.get(va, 0),
                   game_message_codes=codes.get(va, []),
                   has_exported_evidence=va in exports,
                   review_sources=[dict(source=r['source'], json_pointer=r['json_pointer'],
                                        status=r['status']) for r in reviews.get(va, [])],
                   next_action='逐函数确认职责、字段、调用前提和未知项')
        if function['classification'] == '直接跳板已识别':
            row['next_action'] = '沿已证目标分析；跳板识别不代表目标业务已完成'
            row['target_va'] = function.get('target_va')
        elif codes.get(va):
            row['next_action'] = '按消息号追踪构造/接收、字段最小跨度、副作用、等待完成条件'
        elif row['review_sources']:
            row['next_action'] = '复用已有局部结论，按原清单未知项补闭环；不重复从零导出'
        elif '库' in function['classification']:
            row['next_action'] = '先复核自动库识别；存在MFC误名，不能整体排除'
        rows.append(row)
    # 只提供结构排序；入边包括RTC/库和跳板，不把热度伪装成业务价值评分。
    ordinary = [row for row in rows if row['classification'] != '直接跳板已识别']
    order = sorted(ordinary, key=lambda r: (
        not bool(r['game_message_codes']), bool(r['review_sources']),
        -r['direct_incoming_edges'], -r['unresolved_indirect_sites'], int(r['va'], 16)))
    result = dict(
        scope='全量29019入口仍保留；仅排序辅助选点，无完成率或自动业务命名',
        sorting='游戏handler优先，同组无审阅优先，再按直接入边和间接站点数；非价值评分',
        counts=dict(all_entries=len(rows), direct_thunks=sum(
            r['classification'] == '直接跳板已识别' for r in rows),
            entries_without_explicit_review=sum(not r['review_sources'] for r in rows),
            game_handlers=len(codes)),
        unrecognized_code_ranges=coverage.get('unrecognized_code_ranges', []),
        unrecognized_range_reviews=review_data.get('unrecognized_range_reviews', []),
        unrecognized_range_action='另行核验函数边界/控制流；不能静默并入29019入口或标已分析',
        next_candidates=[row['va'] for row in order[:100]], functions=rows)
    (ROOT / 'followup_queue.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                           encoding='utf-8')
    print(json.dumps(result['counts'], ensure_ascii=False))

if __name__ == '__main__':
    main()
