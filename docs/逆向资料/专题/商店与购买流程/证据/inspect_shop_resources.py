"""只读解码商店窗口和相关文本；所有输出限定在本专题。"""
from pathlib import Path
import hashlib
import json
import runpy

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
helper = runpy.run_path(str(ROOT / 'docs/逆向资料/专题/投资事件/证据/inspect_invest_resources.py'))
sections = helper['sections']
import struct
import lzokay

records = []
for relative in ['Interface/G_PropStore.ui', 'Interface/Intf.kpd', 'Data/RichStr.kpd']:
    source = (ROOT / relative).read_bytes()
    rec = {'source': relative, 'sha256': hashlib.sha256(source).hexdigest(), 'size': len(source)}
    if relative.endswith('.ui'):
        key = b'RichNet'
        decoded = bytes((v - key[i % 7]) & 255 for i, v in enumerate(source))
        rec['transform'] = '逐字节减RichNet循环密钥，模256'
    else:
        key = source[0]
        raw_size, packed_size = struct.unpack('<II', bytes((v-key) & 255 for v in source[1:9]))
        if not 0 < raw_size <= 64*1024*1024 or not 0 < packed_size <= len(source)-9:
            raise ValueError('容器长度非法')
        decoded = lzokay.decompress(bytes((v-key) & 255 for v in source[9:9+packed_size]), raw_size)
        if len(decoded) != raw_size:
            raise ValueError('解压长度不一致')
        rec.update(key=key, raw_size=raw_size, packed_size=packed_size)
    encoding = 'gbk' if relative == 'Interface/Intf.kpd' else 'cp950'
    parsed = sections(decoded.decode(encoding, errors='strict'))
    rec.update(decoded_sha256=hashlib.sha256(decoded).hexdigest(), encoding=encoding+' strict')
    if relative.endswith('.ui'):
        rec['sections'] = parsed
    elif relative.endswith('Intf.kpd'):
        rec['sections'] = [s for s in parsed if any('G_PropStore.ui' in v for v in s['fields'].values())]
    else:
        rec['sections'] = [s for s in parsed if s['fields'].get('indx') in ['24', '180', '181', '182', '304', '305', '803']]
    records.append(rec)
(BASE / '商店资源样本.json').write_text(json.dumps({'scope': '当前资源只读解码；不模拟游戏运行', 'records': records}, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'资源数': len(records), '各资源记录数': [len(r['sections']) for r in records]}, ensure_ascii=False))
