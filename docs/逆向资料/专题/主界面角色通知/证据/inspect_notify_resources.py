"""只读解码主界面与语音表情资源；545同值条目仅作排除误认的证据。"""
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
for relative in ['Interface/G_TopBar.ui', 'Interface/Intf.kpd', 'Data/RichStr.kpd',
                 'Data/VoiceFace.kpd', 'Data/Prop.kpd', 'Data/NewProps.kpd']:
    source = (ROOT/relative).read_bytes()
    row = {'source': relative, 'sha256': hashlib.sha256(source).hexdigest(), 'size': len(source)}
    if relative.endswith('.ui'):
        decoded = bytes((v-b'RichNet'[i%7])&255 for i,v in enumerate(source))
        row['transform'] = '逐字节减RichNet循环密钥，模256'
    else:
        key = source[0]
        raw, packed = struct.unpack('<II', bytes((v-key)&255 for v in source[1:9]))
        if not 0 < raw <= 64*1024*1024 or not 0 < packed <= len(source)-9:
            raise ValueError('容器长度非法')
        decoded = lzokay.decompress(bytes((v-key)&255 for v in source[9:9+packed]), raw)
        if len(decoded) != raw:
            raise ValueError('解压长度不符')
        row.update(key=key, raw_size=raw, packed_size=packed)
    # 当前资源分别保留可严格往返的编码，不把客户端CP_ACP消费改称UTF-8。
    encoding = 'gb18030' if relative in ['Interface/G_TopBar.ui','Interface/Intf.kpd','Data/VoiceFace.kpd'] else 'cp950'
    try:
        text = decoded.decode(encoding, errors='strict')
    except UnicodeDecodeError as exc:
        raise ValueError(relative+' 不匹配指定编码 '+encoding) from exc
    if text.encode(encoding) != decoded:
        raise ValueError('编码不能无损往返')
    parsed = sections(text)
    row.update(encoding=encoding+' strict往返', decoded_sha256=hashlib.sha256(decoded).hexdigest())
    if relative.endswith('.ui') or relative.endswith('VoiceFace.kpd'):
        selected = parsed
    elif relative.endswith('Intf.kpd'):
        selected = [s for s in parsed if any('G_TopBar.ui' in v for v in s['fields'].values())]
    elif relative.endswith('RichStr.kpd'):
        selected = [s for s in parsed if s['fields'].get('indx') in ['335','336','337','891','1664','1665','1920']]
    else:
        selected = [s for s in parsed if any(v == '545' for v in s['fields'].values())]
    row['sections'] = selected
    records.append(row)
(BASE/'主界面资源样本.json').write_text(json.dumps({'scope':'只读当前资源，未运行游戏', 'records':records},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'resources':len(records),'sections':[len(r['sections']) for r in records]}))
