"""只读解包当前 Npc.kpd，保存指纹、严格解码原文与条目；不改游戏资源。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def decode_resource(relative='Data/Npc.kpd', encoding='cp950'):
    raw = (ROOT / relative).read_bytes()
    key = raw[0]
    expanded, packed = struct.unpack('<II', bytes((b - key) & 255 for b in raw[1:9]))
    assert 0 < expanded <= 64 * 1024 * 1024 and 0 < packed <= len(raw) - 9
    decoded = lzokay.decompress(bytes((b - key) & 255 for b in raw[9:9 + packed]), expanded)
    assert len(decoded) == expanded
    text = decoded.decode(encoding, errors='strict')
    assert text.encode(encoding, errors='strict') == decoded
    sections, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = dict(section=line[1:-1], line=number, fields={})
            sections.append(current)
        elif current is not None and '=' in line and not line.startswith('//'):
            key_name, value = line.split('=', 1)
            current['fields'][key_name.strip()] = value.strip()
    return dict(source=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                decoded_sha256=hashlib.sha256(decoded).hexdigest(), expanded_size=expanded,
                packed_size=packed, key=key, encoding=encoding,
                encoding_boundary='严格往返；不等于客户端CP_ACP已实测',
                source_text=text, sections=sections)


if __name__ == '__main__':
    sample = decode_resource()
    gvalue = decode_resource('Data/GValue.kpd', 'gbk')
    (HERE / 'resource_samples.json').write_text(json.dumps(dict(records=[sample, gvalue]), ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['// Npc.kpd 当前原文 / 每行仅增加注释前缀，JSON另存未加前缀原文',
             '// ============================================================================']
    lines.extend('// ' + line for line in sample['source_text'].splitlines())
    (HERE / 'Npc_kpd_原文.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    cap = [s for s in gvalue['sections'] if s['fields'].get('indx') == '37']
    print(json.dumps(dict(gvalue_37=cap), ensure_ascii=True))
    print(json.dumps({k: v for k, v in sample.items() if k not in ('source_text', 'sections')}))
