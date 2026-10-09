"""只读提取当前客户端胜负、离场文案和界面资源；不写回原资源。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def sections(text):
    result = []
    current = None
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = {'section': line[1:-1], 'line': number, 'fields': {}}
            result.append(current)
        elif current is not None and '=' in line and not line.startswith('//'):
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    return result


def main():
    records = []
    for relative in ['Data/RichStr.kpd', 'Interface/Intf.kpd',
                     'Interface/G_GameOver.ui', 'Interface/G_ExitRecord.ui']:
        raw = (ROOT / relative).read_bytes()
        row = {'source': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
        if relative.endswith('.ui'):
            key = b'RichNet'
            decoded = bytes((b-key[i % 7]) & 255 for i, b in enumerate(raw))
            row['transform'] = '逐字节减去RichNet循环密钥，模256'
        else:
            key = raw[0]
            size, packed = struct.unpack('<II', bytes((b-key) & 255 for b in raw[1:9]))
            assert 0 < size <= 64*1024*1024 and 0 < packed <= len(raw)-9
            decoded = lzokay.decompress(bytes((b-key) & 255 for b in raw[9:9+packed]), size)
            assert len(decoded) == size
            row.update(raw_size=size, packed_size=packed, key=key)
        encoding = 'cp950' if 'RichStr.kpd' in relative else 'gbk'
        parsed = sections(decoded.decode(encoding, errors='strict'))
        row.update(decoded_sha256=hashlib.sha256(decoded).hexdigest(), encoding=encoding+' strict；客户端仍为CP_ACP')
        if 'RichStr' in relative:
            parsed = [x for x in parsed if x['fields'].get('indx') in ['12','13','14','18','97','123','270']]
        elif 'Intf.kpd' in relative:
            parsed = [x for x in parsed if x['fields'].get('indx') in ['29','36','38','68','76','79'] or any(v in ['G_GameOver.ui','G_ExitRecord.ui'] for v in x['fields'].values())]
        row['sections'] = parsed
        records.append(row)
    (BASE/'界面与文案样本.json').write_text(json.dumps({'scope':'当前磁盘资源只读解析，无实机复现', 'records':records}, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
    print(json.dumps(records[:2],ensure_ascii=True))


if __name__ == '__main__':
    main()
