"""只读提取40A0系列使用的文本、界面配置及相关道具配置，不写游戏资源。"""
from pathlib import Path
import hashlib
import json
import struct
import runpy
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
sections = runpy.run_path(str(ROOT/'docs/逆向资料/专题/投资事件/证据/inspect_invest_resources.py'))['sections']
records = []
for relative in ['Data/RichStr.kpd', 'Data/Prop.kpd', 'Data/NewProps.kpd',
                 'Interface/Intf.kpd', 'Interface/G_News.ui', 'Interface/G_MsgBox.ui']:
    source = (ROOT/relative).read_bytes()
    row = {'source': relative, 'sha256': hashlib.sha256(source).hexdigest(), 'size': len(source)}
    if relative.endswith('.ui'):
        decoded = bytes((v-b'RichNet'[i % 7]) & 255 for i, v in enumerate(source))
        row['transform'] = '逐字节减RichNet循环密钥，模256'
    else:
        key = source[0]
        raw, packed = struct.unpack('<II', bytes((v-key) & 255 for v in source[1:9]))
        if not 0 < raw <= 64*1024*1024 or not 0 < packed <= len(source)-9:
            raise ValueError('资源容器长度不合法')
        decoded = lzokay.decompress(bytes((v-key) & 255 for v in source[9:9+packed]), raw)
        if len(decoded) != raw:
            raise ValueError('解压长度不符')
        row.update(key=key, raw_size=raw, packed_size=packed)
    encoding = 'gb18030' if relative.startswith('Interface/') else 'cp950'
    value = decoded.decode(encoding, errors='strict')
    if value.encode(encoding) != decoded:
        raise ValueError('资源编码不能无损往返')
    parsed = sections(value)
    if relative.endswith('.ui'):
        selected = parsed
    elif relative.endswith('RichStr.kpd'):
        selected = [s for s in parsed if s['fields'].get('indx') in ['24','28','31','184','185','189','197','293']]
    elif relative.endswith('Intf.kpd'):
        selected = [s for s in parsed if any(v in ['G_News.ui','G_MsgBox.ui'] for v in s['fields'].values())]
    else:
        selected = [s for s in parsed if s['fields'].get('indx') in ['1','2','6','14','48','600']]
    row.update(encoding=encoding+' strict往返', decoded_sha256=hashlib.sha256(decoded).hexdigest(), sections=selected)
    records.append(row)
(BASE/'resources.json').write_text(json.dumps({'scope':'当前资源只读解包；配置文本仅辅助业务命名，不代替函数证据', 'records':records},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'resources':len(records),'selected_sections':[len(r['sections']) for r in records]}))
