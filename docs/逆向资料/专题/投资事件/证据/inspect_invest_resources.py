"""只读解包当前投资界面、文案与关卡样本；输出仅写入本专题证据目录。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sections(text):
    result = []
    current = None
    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = {'section': line[1:-1], 'line': line_number, 'fields': {}}
            result.append(current)
        elif current is not None and '=' in line and not line.startswith('//'):
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    return result


def main():
    records = []
    for relative in ['Interface/G_Invest.ui', 'Interface/Intf.kpd',
                     'Data/RichStr.kpd', 'Data/BossWar.kpd', 'Data/BossWar_v.kpd']:
        source = (ROOT / relative).read_bytes()
        record = {'source': relative, 'size': len(source), 'sha256': digest(source)}
        if relative.endswith('.ui'):
            key = b'RichNet'
            decoded = bytes((value-key[i % len(key)]) & 255 for i, value in enumerate(source))
            record['transform'] = '每字节减去RichNet循环密钥，模256'
        else:
            if len(source) < 9:
                raise ValueError('容器不足9字节')
            key = source[0]
            raw_size, packed_size = struct.unpack('<II', bytes((b-key) & 255 for b in source[1:9]))
            if not 0 < raw_size <= 64*1024*1024 or not 0 < packed_size <= len(source)-9:
                raise ValueError('容器长度越界')
            decoded = lzokay.decompress(bytes((b-key) & 255 for b in source[9:9+packed_size]), raw_size)
            if len(decoded) != raw_size:
                raise ValueError('解压长度不符')
            record.update(key=key, raw_size=raw_size, packed_size=packed_size,
                          tail_size=len(source)-9-packed_size)
        encoding = 'gbk' if relative == 'Interface/Intf.kpd' else 'cp950'
        text = decoded.decode(encoding, errors='strict')
        record.update(decoded_sha256=digest(decoded), encoding=encoding+' strict，仅样本转录；客户端仍按CP_ACP消费')
        parsed = sections(text)
        if relative.endswith('.ui'):
            record['sections'] = parsed
        elif relative.endswith('Intf.kpd'):
            record['sections'] = [s for s in parsed if any('G_Invest.ui' in v for v in s['fields'].values())]
        elif relative.endswith('RichStr.kpd'):
            record['sections'] = [s for s in parsed if s['fields'].get('indx') in ['344', '345']]
            for row in record['sections']:
                record.setdefault('source_lines', []).append({'line': row['line'], 'fields': row['fields']})
        else:
            record['sections'] = [{'section': s['section'], 'line': s['line'],
                'fields': {k: v for k, v in s['fields'].items()
                           if k in ['mapIndx', 'mapName', 'investBase', 'investReturn']}}
                for s in parsed if s['section'] == 'MAP']
        records.append(record)
    output = {'scope': '当前Richonline资源只读解包，无运行客户端；lzokay安全解包不模拟原解包器缺陷',
              'records': records}
    (BASE / '投资资源样本.json').write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'resources': len(records), 'maps': sum(len(r.get('sections', [])) for r in records if 'BossWar' in r['source'])}, ensure_ascii=False))


if __name__ == '__main__':
    main()
