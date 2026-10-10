"""补采缺失文本转换/宽文本入口及局部函数调用导航。"""
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/727F控件状态接口'


def export(db):
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    result = exporter(db, [0x8E0590, 0x8FAE70], str(HERE / '证据/text_dependencies.json'))
    targets = [0x727F90, 0x727FC0, 0x728150, 0x7281B0, 0x728220]
    pending, seen, references = list(targets), set(), []
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
    (HERE / '证据/local_navigation.json').write_text(json.dumps(dict(references=references, limitation='调用导航不等于完整消费者分析。'), ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')
    return dict(export=result, references=len(references))
