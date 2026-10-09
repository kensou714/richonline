"""最后补证：未声明正文校验窗口调用的摘要辅助函数及文件名常量。"""
import json,runpy
from pathlib import Path
ROOT=Path(r'F:\大富翁online\Richonline');OUT=Path(__file__).resolve().parent
export=runpy.run_path(str(ROOT/'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
print(export(db,[0x81B980],OUT/'digest_helper.json'))
addresses=[0x622E20,0x623030,0x69AAA0,0x69ABE0,0x6DA7B0,0x6DBE30,0x70F9E0,
           0x72A080,0x72B910,0x738F60,0x762060,0x7A3BB0,0x7A3D90,0x81B150,
           0x81BEA0,0x81E290,0x81E580,0x81B980]
rows={}
for address in addresses:
    f=db.functions.get_at(address)
    for chunk in db.functions.get_chunks(f):
        for ins in db.instructions.get_between(chunk.start_ea,chunk.end_ea):
            for ref in db.xrefs.from_ea(ins.ea):
                if int(ref.type)!=1 or not 0xA00000<=ref.to_ea<0xA60000:continue
                raw=db.bytes.get_bytes_at(ref.to_ea,128)
                if not raw:continue
                r=rows.setdefault(ref.to_ea,dict(va=hex(ref.to_ea),size=len(raw),idb_hex=raw.hex(),sources=[]))
                r['sources'].append(dict(function=hex(address),site=hex(ins.ea)))
(OUT/'file_path_constants.json').write_text(json.dumps(list(rows.values()),ensure_ascii=False,indent=2),encoding='utf-8')
print(dict(constants=len(rows)))
