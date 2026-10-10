"""只读导出三个控件状态种子及引用导航，不自行占用IDA租约。"""
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/727F控件状态接口'
SEEDS = [0x727F10, 0x728060, 0x728120]


def export(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    result = exporter(db, SEEDS, str(HERE / '证据/seeds.json'))
    pending, seen, references = list(SEEDS), set(), []
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
            references.append(row)
    (HERE / '证据/navigation.json').write_text(json.dumps(dict(references=references, limitation='调用导航不是消费者完整审阅。'), ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')
    return dict(export=result, references=len(references))
