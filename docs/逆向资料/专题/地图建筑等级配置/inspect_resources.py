"""只读解包当前客户端的三份 Ko 配置并记录结构化样本。"""
from pathlib import Path
import hashlib
import json
import struct

import lzokay

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'
NAMES = ('KoBuild.kpd', 'KoNews.kpd', 'KoNpc.kpd')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(blob):
    if len(blob) < 9:
        raise ValueError('KPD header too short')
    key = blob[0]
    size, packed = struct.unpack('<II', bytes((b - key) & 255 for b in blob[1:9]))
    if not 0 < size <= 16 * 1024 * 1024 or not 0 < packed <= len(blob) - 9:
        raise ValueError('KPD sizes out of range')
    raw = lzokay.decompress(bytes((b - key) & 255 for b in blob[9:9 + packed]), size)
    if len(raw) != size:
        raise ValueError('KPD decoded size mismatch')
    return raw, key, packed


def sections(text):
    result = []
    for number, source in enumerate(text.splitlines(), 1):
        line = source.strip()
        if not line or line.startswith((';', '#', '//')):
            continue
        if line.startswith('[') and line.endswith(']'):
            result.append(dict(name=line[1:-1], line=number, fields={}))
        elif result and '=' in line:
            key, value = line.split('=', 1)
            result[-1]['fields'][key.strip()] = value.strip()
    return result


def main():
    records = []
    for name in NAMES:
        blob = (ROOT / 'Data' / name).read_bytes()
        raw, key, packed = decode(blob)
        # Latin-1 逐字节映射只用于 ASCII 键和数字核验，中文值保留原字节而不猜代码页。
        text = raw.decode('latin1')
        groups = sections(text)
        records.append(dict(source='Data/' + name, size=len(blob), sha256=digest(blob),
                            decoded_size=len(raw), decoded_sha256=digest(raw), key=key,
                            packed_size=packed, tail_size=len(blob) - 9 - packed,
                            encoding='latin1逐字节映射；非ASCII文本不可据此解释；客户端按运行时CP_ACP',
                            sections=groups))
    output = dict(scope='当前 Richonline 资源样本；仅只读解包与结构记录，不模拟客户端容错', records=records)
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'resources.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print([(r['source'], len(r['sections']), r['decoded_size']) for r in records])


if __name__ == '__main__':
    main()
