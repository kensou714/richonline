"""只读当前事件文案与UI19资源，严格解码并保留哈希。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def sections(text):
    result, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = {'section': line[1:-1], 'line': number, 'fields': {}}
            result.append(current)
        elif current is not None and '=' in line and not line.startswith('//'):
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    return result


def decode(relative, encoding):
    source = (ROOT/relative).read_bytes()
    row = {'source': relative, 'size': len(source), 'sha256': hashlib.sha256(source).hexdigest()}
    if relative.endswith('.ui'):
        decoded = bytes((b-b'RichNet'[i % 7]) & 255 for i, b in enumerate(source))
        row['transform'] = '逐字节减RichNet循环密钥，模256'
    else:
        if len(source) < 9:
            raise ValueError('容器不足9字节')
        key = source[0]
        raw, packed = struct.unpack('<II', bytes((b-key) & 255 for b in source[1:9]))
        if not 0 < raw <= 64*1024*1024 or not 0 < packed <= len(source)-9:
            raise ValueError('容器长度越界')
        decoded = lzokay.decompress(bytes((b-key) & 255 for b in source[9:9+packed]), raw)
        if len(decoded) != raw:
            raise ValueError('解压长度不符')
        row.update(key=key, raw_size=raw, packed_size=packed, tail_size=len(source)-9-packed)
    text = decoded.decode(encoding, errors='strict')
    if text.encode(encoding) != decoded:
        raise ValueError('编码不能严格往返')
    row.update(encoding=encoding+' strict往返', decoded_sha256=hashlib.sha256(decoded).hexdigest())
    return row, sections(text)


records = []
intf, parsed = decode('Interface/Intf.kpd', 'gb18030')
selected = [s for s in parsed if s['fields'].get('indx') == '19']
assert len(selected) == 1
intf['sections'] = selected
records.append(intf)
ui_path = 'Interface/'+selected[0]['fields']['file']
ui, parsed = decode(ui_path, 'gb18030')
ui['sections'] = parsed
records.append(ui)
strings, parsed = decode('Data/RichStr.kpd', 'cp950')
strings['sections'] = [s for s in parsed if s['fields'].get('indx') in ['24','28','154','177','178','179','310']]
records.append(strings)
(BASE/'4023系列资源样本.json').write_text(json.dumps({'scope': '只读当前资源，未运行游戏', 'records': records}, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'ui_path': ui_path, 'text_records': strings['sections']}, ensure_ascii=False))
