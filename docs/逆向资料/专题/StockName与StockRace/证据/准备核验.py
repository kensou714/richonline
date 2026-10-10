"""仅读核验准备清单；不执行 IDA、不生成原证或审阅状态。"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料'
HERE = BASE / '专题/StockName与StockRace/证据'
REUSE = {
    '专题/股票与交易流程/证据/stock_core.json': (0x623CB0, 0x6283E0, 0x6C0E50),
    '专题/资源容器候选/证据/candidate_owners.json': (0x6C1260, 0x6C1A60, 0x6C5780),
    '专题/资源容器候选/证据/candidate_seeds.json': (0x6C7470,),
    '专题/文本过滤与字码转换/证据/functions_raw.json': (0x6C14E0,),
    '专题/二进制读写游标/证据/cursor_family.json': (0x867290,),
    '专题/文本与容器/证据/parser_lzo_core.json': (0x6C5510,),
}


def rows(document):
    return document if isinstance(document, list) else document['functions']


def check():
    namespace = {'__name__': 'stock_preparation'}
    path = HERE / 'export_ida.py'
    exec(compile(path.read_text('utf-8'), str(path), 'exec'), namespace)
    compile(Path(__file__).read_text('utf-8'), __file__, 'exec')
    blob = (ROOT / 'RnClient.exe').read_bytes()
    if hashlib.sha256(blob).hexdigest() != namespace['ST_SHA256']:
        raise ValueError('磁盘指纹与准备基线不符')
    queue = json.loads((BASE / '全量分析/followup_queue.json').read_text('utf-8'))
    by_va = {int(item['va'], 16): item for item in queue['functions']}
    selected = [va for phase in namespace['ST_PHASES'].values() for va in phase]
    if len(selected) != len(set(selected)):
        raise ValueError('新增入口清单有重复')
    selected_rows = []
    for va in selected:
        entry = by_va[va]
        selected_rows.append(dict(va=hex(va), bytes=entry['span_bytes'],
                                  evidence=entry['has_exported_evidence'],
                                  reviews=len(entry['review_sources'])))
    reused = []
    loader = None
    for relative, addresses in REUSE.items():
        document = json.loads((BASE / relative).read_text('utf-8'))
        entries = {int(item.get('va', item.get('ea')), 16): item
                   for item in rows(document)}
        for va in addresses:
            item = entries[va]
            if not item.get('pseudocode'):
                raise ValueError('复用条目无伪码：' + hex(va))
            reused.append(dict(source=relative, va=hex(va),
                               format='旧数组' if isinstance(document, list) else '标准函数组',
                               byte_match=item.get('bytes_match_disk')))
            if va == 0x6C0E50:
                loader = item

    # 仅从归档伪码筛出导航地址；真实槽偏移和业务语义须另核汇编与消费者。
    pattern = re.compile(r'\*\(this \+ (\d+)\) = sub_([0-9A-Fa-f]+);')
    read = namespace['disk_view'](blob)
    callbacks = []
    for line in loader['pseudocode']:
        match = pattern.search(line)
        if match is None:
            continue
        slot, thunk = int(match[1]), int(match[2], 16)
        raw = read(thunk, 5)
        implementation = thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True) \
            if raw is not None and raw[0] == 0xE9 else None
        callbacks.append(dict(slot=slot, thunk=hex(thunk),
                              disk_e9_target=hex(implementation) if implementation else None))
    if len(callbacks) != 74:
        raise ValueError('既有回调槽导航数量不符合准备清单')
    return dict(status='准备检查通过；未执行 IDA 导出或新增审阅',
                phases={name: len(values) for name, values in namespace['ST_PHASES'].items()},
                selected=selected_rows, reuse=reused, callback_navigation=callbacks)


if __name__ == '__main__':
    print(json.dumps(check(), ensure_ascii=True, indent=2))
