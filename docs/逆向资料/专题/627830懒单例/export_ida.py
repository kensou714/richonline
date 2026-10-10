"""只读补采627830懒单例入口、构造与释放；不占用IDA租约。"""
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/627830懒单例'


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    chains = []
    entries = {0x627830}
    for entry in (0x600B85, 0x60628D):
        current, seen = entry, []
        while current not in seen and len(seen) < 16:
            raw = db.bytes.get_bytes_at(current, 5)
            if not raw or raw[0] != 0xE9:
                break
            target = current + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            chains.append(dict(va=hex(current), size=5, idb_hex=raw.hex(), target=hex(target)))
            seen.append(current)
            current = target
        entries.add(current)
    result = export(db, sorted(entries), str(HERE / '证据/seeds.json'))
    refs = []
    pending, seen = [0x627830, 0xA766BC], set()
    while pending:
        target = pending.pop()
        if target in seen:
            continue
        seen.add(target)
        for x in db.xrefs.to_ea(target):
            function = db.functions.get_at(x.from_ea)
            raw = db.bytes.get_bytes_at(x.from_ea, 5)
            row = dict(site=hex(x.from_ea), target=hex(target), kind=int(x.type),
                       function=hex(function.start_ea) if function else None,
                       raw5=raw.hex() if raw else None)
            if raw and raw[0] == 0xE9 and x.type == 19:
                row['thunk'] = True
                pending.append(x.from_ea)
            refs.append(row)
    payload = dict(chains=chains, references=refs,
                   globals=[dict(va='0xa766bc', size=4, idb_hex=db.bytes.get_bytes_at(0xA766BC, 4).hex())],
                   limitation='引用导航不是完整消费者审阅；全局原值不是运行态对象。')
    (HERE / '证据/navigation.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    return dict(export=result, entries=[hex(x) for x in sorted(entries)], references=len(refs))
