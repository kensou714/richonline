"""录像续查第二批：当前文件I/O导航、命令解析依赖及记录文本/快捷键候选。"""
import json
import re
import runpy
from pathlib import Path

ROOT = Path(r'F:\大富翁online\Richonline')
OUT = Path(__file__).resolve().parent
stage1 = json.loads((OUT / 'stage1_navigation.json').read_text('utf-8'))
export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
addresses = {0x623030, 0x627020, 0x627050, 0x627060, 0x923F60,
             0x81C190, 0x81C2B0, 0x81E290, 0x81FC50, 0x81C350,
             0x69ABE0, 0x81B150, 0x81B310, 0x625D70, 0x624EE0, 0x624E60,
             0x624E80, 0x624F00, 0x625070, 0x6255D0, 0x625720}
for item in stage1['io_names']:
    if item['name'] in ('_fopen', 'j__fopen', '_fseek', 'j__fseek', '_ftell', 'j__ftell'):
        for ref in item['references']:
            if ref['function'] and 0x612000 <= int(ref['function'], 16) < 0x828000:
                addresses.add(int(ref['function'], 16))
declared, undeclared = [], []
for ea in sorted(addresses):
    f = db.functions.get_at(ea)
    if f is not None and f.start_ea == ea:
        declared.append(ea)
    else:
        undeclared.append(hex(ea))
print(export(db, declared, OUT / 'io_and_parser_navigation.json'))

known = []
for target in [0xA2AB5C, 0x923F60, 0x9243E0, 0xA766A4]:
    pending, done, refs = [target], set(), []
    while pending:
        ea = pending.pop()
        if ea in done:
            continue
        done.add(ea)
        for x in db.xrefs.to_ea(ea):
            f = db.functions.get_at(x.from_ea)
            raw = db.bytes.get_bytes_at(x.from_ea, 5)
            bridge = bool(raw and raw[0] == 0xE9 and x.from_ea+5+int.from_bytes(raw[1:], 'little', signed=True) == ea)
            refs.append(dict(source=hex(x.from_ea), target=hex(ea), kind=int(x.type),
                             function=hex(f.start_ea) if f else None, e9_bridge=bridge))
            if bridge:
                pending.append(x.from_ea)
    known.append(dict(va=hex(target), references=refs))

candidates = []
pattern = re.compile(r'(?<![0-9A-F])(?:3EBh|3F0h|3F1h|3F5h|3F6h|3F8h|3F9h|40Dh|5E6h|5E7h|73h)(?![0-9A-F])')
for f in db.functions.get_all():
    if not 0x612000 <= f.start_ea < 0x820000:
        continue
    for c in db.functions.get_chunks(f):
        for ins in db.instructions.get_between(c.start_ea, c.end_ea):
            text = db.instructions.get_disassembly(ins)
            if pattern.search(text):
                candidates.append(dict(function=hex(f.start_ea), instruction=hex(ins.ea), text=text))
(OUT / 'stage2_navigation.json').write_text(json.dumps(dict(known=known, undecared_candidates=undeclared,
    immediate_candidates=candidates, scope='立即数候选并非已认定录像分支；范围0x612000..0x820000已声明全部chunks'),
    ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(exported=len(declared), undeclared=undeclared, immediate_candidates=len(candidates))))
