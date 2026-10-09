"""第五批：启动状态表、记录开关无操作分支、接收队列写入来源。"""
import json,runpy
from pathlib import Path
ROOT=Path(r'F:\大富翁online\Richonline');OUT=Path(__file__).resolve().parent
def resolve(ea):
    seen=set()
    while ea not in seen:
        seen.add(ea);b=db.bytes.get_bytes_at(ea,5)
        if not b or b[0]!=0xe9:return ea
        ea+=5+int.from_bytes(b[1:],'little',signed=True)
    return ea
targets=[0x64F870,0x698050,0x6980F0,0xA6723C,resolve(0x601553),resolve(0x60EE3D),resolve(0x60417C)]
addresses={0x64F870,0x64FA50,0x698050,0x6980F0,0x761D50,0x751BD0,0x7526F0,0x752A00}
rows=[]
for target in targets:
    pending=[target];seen=set();refs=[]
    while pending:
        ea=pending.pop()
        if ea in seen:continue
        seen.add(ea)
        for x in db.xrefs.to_ea(ea):
            f=db.functions.get_at(x.from_ea)
            bridge=resolve(x.from_ea)==ea and x.from_ea!=ea
            refs.append(dict(source=hex(x.from_ea),target=hex(ea),function=hex(f.start_ea) if f else None,kind=int(x.type),bridge=bridge))
            if bridge:pending.append(x.from_ea)
            elif target in [0x64F870,0x698050,0x6980F0] and f is not None and 0x612000<=f.start_ea<0x829000:addresses.add(f.start_ea)
    rows.append(dict(target=hex(target),references=refs))
    f=db.functions.get_at(target)
    if f is not None and f.start_ea==target:addresses.add(target)
(OUT/'state_queue_references.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
data=[]
table=int.from_bytes(db.bytes.get_bytes_at(0x624D96,4),'little')
for ea,size,label in [(table,64,'主状态间接调用表周边64B；不以窗口长度推表容量'),
                       (0x706E82,113,'UI0高号switch索引表'),(0x706E6A,24,'UI0高号跳表周边'),
                       (0x60BD37,5,'虚表120跳板'),(0x611EBC,5,'未声明摘要检验跳板'),
                       (0x60CDBD,5,'未声明原缓冲写出跳板'),(0x608B0A,5,'压缩流写出跳板')]:
    data.append(dict(va=hex(ea),size=size,idb_hex=db.bytes.get_bytes_at(ea,size).hex(),label=label))
(OUT/'state_and_switch_data.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
export=runpy.run_path(str(ROOT/'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
print(export(db,addresses,OUT/'queue_and_ui_gate.json'))
