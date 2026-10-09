"""只读导出0x588位移候选、角色字段链及getter全部直接/E9桥接引用。"""
import json
import re
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/角色1416字段来源')
ROOT = HERE.parents[3]


def collect(db):
    candidates, addresses = [], {0x7F3840, 0x7F3C70, 0x7F8780, 0x7FD7A0, 0x65B450}
    total = 0
    for ins in db.instructions.get_all():
        total += 1
        text = db.instructions.get_disassembly(ins) or ''
        # 位移命中只形成候选，不据此认定基址就是角色P。
        if re.search(r'\[[^\]]*\+588h\]', text, re.I):
            function = db.functions.get_at(ins.ea)
            candidates.append({'site': hex(ins.ea), 'text': text,
                               'function': hex(function.start_ea) if function else None,
                               'status': '待归属'})
            if function:
                addresses.add(function.start_ea)
    edges, queue, seen = [], [0x7FD7A0, 0x7F3C70, 0x7F3840], set()
    while queue:
        target = queue.pop()
        if target in seen:
            continue
        seen.add(target)
        for ref in db.xrefs.to_ea(target):
            function = db.functions.get_at(ref.from_ea)
            ins = db.instructions.get_at(ref.from_ea)
            raw = db.bytes.get_bytes_at(ref.from_ea, 5)
            is_bridge = bool(raw and raw[0] == 0xE9 and
                             ref.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
            edges.append({'source': hex(ref.from_ea), 'target': hex(target), 'kind': int(ref.type),
                          'function': hex(function.start_ea) if function else None,
                          'text': db.instructions.get_disassembly(ins) if ins else None,
                          'e9_bridge': is_bridge})
            if is_bridge:
                queue.append(ref.from_ea)
            elif function:
                addresses.add(function.start_ea)
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), namespace)
    result = namespace['export_group'](db, addresses, str(HERE / '证据/functions.json'))
    path = HERE / '证据/functions.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    for function in data['functions']:
        for row in function['assembly']:
            row['size'] = db.instructions.get_at(int(row['va'], 16)).size
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    scan = {'disk_sha256': data['disk_sha256'], 'scope': '当前IDA已解码指令中的[基址+588h]文本候选；不覆盖隐藏位移、别名指针或未定义代码',
            'instruction_count': total, 'candidates': candidates, 'references': edges}
    (HERE / '证据/scan.json').write_text(json.dumps(scan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'export': result, 'candidates': len(candidates), 'edges': len(edges)}


def recheck(db):
    data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    rows, mismatches = [], []
    for saved in data['functions']:
        f = db.functions.get_at(int(saved['va'], 16))
        chunks = list(db.functions.get_chunks(f))
        declared = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]
        actual = {hex(i.ea): i.size for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
        expected = {i['va']: i['size'] for i in saved['assembly']}
        if declared != saved['declared_chunks'] or actual != expected:
            mismatches.append(saved['va'])
        if any(db.bytes.get_bytes_at(int(s['va'], 16), s['size']).hex() != s['idb_hex']
               for s in saved['byte_ranges'] + saved['chunk_byte_ranges']):
            mismatches.append(saved['va'])
        rows.append({'va': saved['va'], 'declared_chunks': declared,
                     'instruction_count': len(actual), 'instruction_bytes': sum(actual.values())})
    result = {'disk_sha256': data['disk_sha256'], 'functions': rows, 'mismatches': sorted(set(mismatches))}
    (HERE / '证据/ida_recheck.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if mismatches:
        raise ValueError(mismatches)
    return {'functions': len(rows), 'mismatches': []}


def supplement(db):
    """补证模式判据、地图字段对象身份及标志转交位置，不重复全库扫描。"""
    path = HERE / '证据/functions.json'
    old = json.loads(path.read_text(encoding='utf-8'))
    addresses = {int(f['va'], 16) for f in old['functions']}
    addresses.update([0x63F300, 0x691A70, 0x63E160, 0x63E990, 0x693680, 0x642740,
                      0x63E210, 0x63E1A0, 0x629E10, 0x63EDD0, 0x691990])
    edges, queue, seen = [], [0x69B600, 0x7DE310, 0x7F4550], set()
    while queue:
        target = queue.pop()
        if target in seen:
            continue
        seen.add(target)
        for ref in db.xrefs.to_ea(target):
            function = db.functions.get_at(ref.from_ea)
            ins = db.instructions.get_at(ref.from_ea)
            raw = db.bytes.get_bytes_at(ref.from_ea, 5)
            bridge = bool(raw and raw[0] == 0xE9 and
                          ref.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
            edges.append({'source': hex(ref.from_ea), 'target': hex(target), 'kind': int(ref.type),
                          'function': hex(function.start_ea) if function else None,
                          'text': db.instructions.get_disassembly(ins) if ins else None,
                          'e9_bridge': bridge})
            if bridge:
                queue.append(ref.from_ea)
            elif function:
                addresses.add(function.start_ea)
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), namespace)
    result = namespace['export_group'](db, addresses, str(path))
    data = json.loads(path.read_text(encoding='utf-8'))
    for function in data['functions']:
        for row in function['assembly']:
            row['size'] = db.instructions.get_at(int(row['va'], 16)).size
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (HERE / '证据/supplement_refs.json').write_text(json.dumps(edges, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {'export': result, 'edges': len(edges)}
