"""第三批：F11/UI0、文本候选、网络主状态与未声明I/O范围。只读取DB。"""
import json
import runpy
from pathlib import Path
ROOT = Path(r'F:\大富翁online\Richonline')
OUT = Path(__file__).resolve().parent
export = runpy.run_path(str(ROOT/'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
addresses = {0x7045A0,0x705C70,0x66CB00,0x739AE0,0x73A590,0x73CEF0,
             0x72A080,0x72A870,0x81B670,0x9109D0,0x9BEE30}
for name in ('startup_and_navigation.json','io_and_parser_navigation.json'):
    data=json.loads((OUT/name).read_text('utf-8'))
    for f in data['functions']:
        if f['va'] in ('0x624ee0','0x624e80','0x624e60','0x625310'):
            for call in f['calls']:
                ea=int(call['implementation'],16)
                obj=db.functions.get_at(ea)
                if 0x612000<=ea<0x829000 and obj is not None and obj.start_ea==ea:
                    addresses.add(ea)
print(export(db,addresses,OUT/'controls_and_flow_navigation.json'))
rows=[]
for start,end in [(0x7DEDC0,0x7DF010),(0x81B8B0,0x81B980),(0x81C740,0x81C830),(0x827DE0,0x827F50)]:
    rows.append(dict(start_va=hex(start),end_va=hex(end),
        scope='人工划定导航窗口，包含可能的相邻代码/非指令；不声称这些就是函数边界',
        idb_hex=db.bytes.get_bytes_at(start,end-start).hex(),
        assembly=[dict(va=hex(i.ea),size=i.size,text=db.instructions.get_disassembly(i))
                  for i in db.instructions.get_between(start,end)],
        references=[dict(source=hex(x.from_ea),target=hex(ea),kind=int(x.type))
                    for ea in range(start,end) for x in db.xrefs.to_ea(ea)
                    if x.from_ea<start or x.from_ea>=end]))
(OUT/'undeclared_io_windows.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
vt=[]
for start,size in [(0xA242D0,0xD0),(0xA6723C,8),(0xA7C730,20)]:
    vt.append(dict(va=hex(start),size=size,idb_hex=db.bytes.get_bytes_at(start,size).hex()))
(OUT/'control_data_navigation.json').write_text(json.dumps(vt,ensure_ascii=False,indent=2),encoding='utf-8')
print('stage3 ready')
