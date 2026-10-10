"""只读解码当前等级资源，保留哈希、严格编码往返和字段。"""
import hashlib
import json
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def collect():
    raw = (ROOT / 'Data/Level.kpd').read_bytes()
    key = raw[0]
    expanded, packed = struct.unpack('<II', bytes((b-key)&255 for b in raw[1:9]))
    if packed != len(raw)-9 or not 0 < expanded <= 1024*1024:
        raise ValueError('KPD长度不符')
    plain = lzokay.decompress(bytes((b-key)&255 for b in raw[9:]), expanded)
    text = plain.decode('cp950', errors='strict')
    if len(plain) != expanded or text.encode('cp950') != plain:
        raise ValueError('解码长度或编码往返不符')
    sections, current = [], None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('//') or line.startswith(';'):
            continue
        if line.startswith('[') and line.endswith(']'):
            current = dict(name=line[1:-1], fields={})
            sections.append(current)
        elif '=' in line and current is not None:
            name, value = line.split('=', 1)
            if name.strip() in current['fields']:
                raise ValueError('重复字段')
            current['fields'][name.strip()] = value.strip()
        else:
            raise ValueError('不支持的当前资源行')
    result = dict(source='Data/Level.kpd', source_size=len(raw),
        source_sha256=hashlib.sha256(raw).hexdigest(), decoded_size=len(plain),
        decoded_sha256=hashlib.sha256(plain).hexdigest(), codec='cp950', strict_roundtrip=True,
        sections=sections, scope='只读资源采样；不把资源约束误当客户端代码检查')
    (HERE/'证据'/'resource.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (HERE/'Level_kpd_只读转录.txt').write_text('// 当前等级资源只读转录 / cp950严格往返\n'+
        '\n'.join('// '+line for line in text.splitlines())+'\n', encoding='utf-8')
    print(json.dumps(dict(source_size=len(raw), decoded_size=len(plain), sections=len(sections)), ensure_ascii=False))


if __name__ == '__main__':
    collect()
