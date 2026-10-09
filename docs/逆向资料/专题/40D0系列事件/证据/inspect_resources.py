"""只读抽取40D0系列卡片名称、文案、动作配置和UI28资源。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[4]
def sections(text):
    rows=[]
    for lineno,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if line.startswith('[') and line.endswith(']'):
            rows.append(dict(section=line[1:-1],line=lineno,fields={}))
        elif '=' in line and rows and not line.startswith(('//',';','#')):
            k,v=line.split('=',1);rows[-1]['fields'][k.strip()]=v.strip()
    return rows

items={'Data/Prop.kpd':set(map(str,[1067,1068,1069,1070,1072,1073,1075,1077,1078,1079,1080,1081,1082,1083,1084,1115,1116])),
       'Data/RichStr.kpd':set(map(str,[40,41,149,245,265,298,359])),
       'Data/Anim.kpd':set(map(str,[5,23,24,26,34,62,101,103,108,132,148,302,312,316])),
       'Data/FaceCtrl.kpd':set(map(str,[34,62])), 'Interface/Intf.kpd':{'28'},
       'Interface/G_ChaKanCard.ui':None}
records=[]
for relative, ids in items.items():
    source=(ROOT/relative).read_bytes()
    row=dict(source=relative,sha256=hashlib.sha256(source).hexdigest(),size=len(source))
    if relative.endswith('.ui'):
        decoded=bytes((v-b'RichNet'[i%7])&255 for i,v in enumerate(source))
    else:
        key=source[0]; raw,packed=struct.unpack('<II',bytes((v-key)&255 for v in source[1:9]))
        assert 0<raw<=64*1024*1024 and 0<packed<=len(source)-9
        decoded=lzokay.decompress(bytes((v-key)&255 for v in source[9:9+packed]),raw)
        assert len(decoded)==raw
        row.update(key=key,raw_size=raw,packed_size=packed)
    encoding='gb18030' if relative.startswith('Interface/') or relative in ['Data/Anim.kpd','Data/FaceCtrl.kpd'] else 'cp950'
    text=decoded.decode(encoding,errors='strict'); assert text.encode(encoding)==decoded
    parsed=sections(text)
    row.update(encoding=encoding+'严格往返',decoded_sha256=hashlib.sha256(decoded).hexdigest(),
               sections=[r for r in parsed if ids is None or r['fields'].get('indx') in ids])
    records.append(row)
(BASE/'resources.json').write_text(json.dumps(dict(scope='当前资源只读抽样；不同配置同数字编号不自动视为同一对象',records=records),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({r['source']:len(r['sections']) for r in records},ensure_ascii=False))
