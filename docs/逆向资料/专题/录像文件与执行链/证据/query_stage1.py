"""录像续查第一批：只读字符串/函数命名/反向E9调用者及启动参数原证。"""
import hashlib
import json
import re
import runpy
from pathlib import Path

ROOT = Path(r'F:\大富翁online\Richonline')
OUT = Path(__file__).resolve().parent
OUT.mkdir(parents=True, exist_ok=True)


def references(target):
    pending, done, rows = [target], set(), []
    while pending:
        ea = pending.pop()
        if ea in done:
            continue
        done.add(ea)
        for x in db.xrefs.to_ea(ea):
            owner = db.functions.get_at(x.from_ea)
            raw = db.bytes.get_bytes_at(x.from_ea, 5)
            bridge = bool(raw and raw[0] == 0xE9 and
                          x.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == ea)
            rows.append(dict(source=hex(x.from_ea), target=hex(ea), kind=int(x.type),
                             function=hex(owner.start_ea) if owner else None, e9_bridge=bridge))
            if bridge:
                pending.append(x.from_ea)
    return rows


strings = []
for s in db.strings.get_all():
    text = s.contents.decode('utf-8', errors='replace')
    if re.search(r'rcd|replay|record|vide[o0]|run_|\.rep\b|recording', text, re.I):
        strings.append(dict(va=hex(s.address), text=text, references=references(s.address)))
names = []
for ea, name in db.names.get_all():
    if re.search(r'(^|_)(fopen|fread|fwrite|_open|_read|_write|open|read|write|fseek|ftell|CreateFile[AW]?|ReadFile|WriteFile|GetCommandLine[AW]?|FindFirstFile[AW]?|FindNextFile[AW]?)($|@)', name):
        names.append(dict(va=hex(ea), name=name, references=references(ea)))
known = [0x622E20, 0x7A3BB0, 0x7A3D90, 0x624CA0, 0x625310,
         0x762060, 0x760310, 0x7996C0, 0x701D60, 0x9243E0]
result = dict(scope='命名字串候选与E9反向展开；搜索命中不等于录像功能已证明',
              strings=strings, io_names=names,
              known_references=[dict(va=hex(ea), references=references(ea)) for ea in known])
(OUT/'stage1_navigation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
export = runpy.run_path(str(ROOT/'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
addresses = [ea for ea in known if db.functions.get_at(ea) is not None and db.functions.get_at(ea).start_ea == ea]
print(export(db, addresses, OUT/'startup_and_navigation.json'))
print(json.dumps(dict(strings=len(strings), io_names=len(names), script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())))
