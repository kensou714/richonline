"""只读补采locale更新外层及atoi引用导航，不展开所有业务调用者。"""
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/CRT数字转换契约'


def run(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    result = exporter(db, [0x92DE70], str(HERE / '证据/locale_update.json'))
    constants = []
    # 全局locale指针只作默认值证据；不是当前运行态指针的快照。
    for address, size in [(0xA69A34, 4)]:
        constants.append(dict(va=hex(address), size=size,
                              idb_hex=db.bytes.get_bytes_at(address, size).hex()))
    pending, seen, refs = [0x91F950, 0x91F800], set(), []
    while pending:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        for x in db.xrefs.to_ea(target):
            function = db.functions.get_at(x.from_ea)
            row = dict(site=hex(x.from_ea), target=hex(target), kind=int(x.type),
                       function=hex(function.start_ea) if function else None)
            raw = db.bytes.get_bytes_at(x.from_ea, 5)
            if x.type == 19 and raw and raw[0] == 0xE9:
                row['thunk'] = True
                pending.append(x.from_ea)
            refs.append(row)
    payload = dict(spans=constants, references=refs,
                   limitation='导航引用不是完整调用者审阅；全局指针原值不是运行态locale。')
    (HERE / '证据/navigation.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    return dict(export=result, references=len(refs), navigation_constants=len(constants))
