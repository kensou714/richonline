"""第四批：F11落点与状态/缓冲来源；未声明I/O的反向调用链。"""
import json
import runpy
from pathlib import Path
ROOT=Path(r'F:\大富翁online\Richonline')
OUT=Path(__file__).resolve().parent
addresses={0x62A0F0,0x691C60,0x6FA210,0x7D8010,0x7D7F20,0x64FB70,0x64FE70}
def resolve(ea):
    seen=set()
    while ea not in seen:
        seen.add(ea)
        b=db.bytes.get_bytes_at(ea,5)
        if not b or b[0]!=0xE9: return ea
        ea+=5+int.from_bytes(b[1:],'little',signed=True)
    return ea
for slot in (0,4,8,12,16,20,24,120,136,160):
    target=int.from_bytes(db.bytes.get_bytes_at(0xA242D0+slot,4),'little')
    target=resolve(target)
    f=db.functions.get_at(target)
    if f is not None and f.start_ea==target: addresses.add(target)
references=[]
for target in (0x7DEDD0,0x81B8B0,0x81C740,0x81B150,0x81B310,0x81BEA0,0x9109D0,0x7D8010):
    pending=[target];seen=set();refs=[]
    while pending:
        ea=pending.pop()
        if ea in seen: continue
        seen.add(ea)
        for x in db.xrefs.to_ea(ea):
            f=db.functions.get_at(x.from_ea)
            bridge=resolve(x.from_ea)==ea and x.from_ea!=ea
            refs.append(dict(source=hex(x.from_ea),target=hex(ea),function=hex(f.start_ea) if f else None,kind=int(x.type),bridge=bridge))
            if bridge: pending.append(x.from_ea)
            elif f is not None and 0x612000<=f.start_ea<0x829000: addresses.add(f.start_ea)
    references.append(dict(target=hex(target),references=refs))
(OUT/'stage4_references.json').write_text(json.dumps(references,ensure_ascii=False,indent=2),encoding='utf-8')
export=runpy.run_path(str(ROOT/'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
print(export(db,addresses,OUT/'controls_and_queue_navigation.json'))
