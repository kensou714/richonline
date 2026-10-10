"""只读导出取得 Ko 对象后立即调用的访问器，实现体须另作语义审阅。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'


def resolve(db, ea):
    chain = []
    while ea not in chain and len(chain) < 16:
        raw = db.bytes.get_bytes_at(ea, 5)
        if not raw or raw[0] != 0xE9:
            break
        chain.append(ea)
        ea += 5 + int.from_bytes(raw[1:], 'little', signed=True)
    return ea, chain


def export(db):
    raw = json.loads((BASE / 'consumer_callsites.json').read_text('utf-8'))
    links, methods = [], set()
    for row in raw['callsites']:
        if row['owner'] == '0x60ae19':
            continue
        window = row['window']
        index = next(i for i, item in enumerate(window) if item['va'] == row['site'])
        calls = [item for item in window[index + 1:] if item['text'].startswith('call')]
        if not calls:
            continue
        site = int(calls[0]['va'], 16)
        edges = [e for e in db.xrefs.from_ea(site) if e.type in (16, 17)]
        if not edges:
            continue
        target, chain = resolve(db, edges[0].to_ea)
        function = db.functions.get_at(target)
        if function is None or function.start_ea != target:
            continue
        methods.add(target)
        links.append(dict(object_site=row['site'], access_site=hex(site),
                          accessor=hex(target), bridges=[hex(t) for t in chain]))
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    exported = namespace['export_group'](db, methods, str(BASE / 'accessors_raw.json'))
    (BASE / 'accessor_links.json').write_text(
        json.dumps(links, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(exported=exported, links=len(links), accessors=len(methods))
