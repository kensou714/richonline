"""只读解码Data/GValue.kpd；严格GBK往返，保存全部ITEM及原文。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def inspect():
    raw = (ROOT / 'Data/GValue.kpd').read_bytes()
    shift = raw[0]
    expanded, packed = struct.unpack('<II', bytes((b - shift) & 255 for b in raw[1:9]))
    assert 0 < expanded <= 64 * 1024 * 1024 and packed == len(raw) - 9
    decoded = lzokay.decompress(bytes((b - shift) & 255 for b in raw[9:]), expanded)
    assert len(decoded) == expanded
    text = decoded.decode('gbk', errors='strict')
    assert text.encode('gbk', errors='strict') == decoded
    records, current, comments = [], None, []
    for number, source in enumerate(text.splitlines(), 1):
        line = source.strip()
        if line.startswith('//'):
            comments.append(line[2:].strip())
        elif line == '[ITEM]':
            current = {'line': number, 'leading_comments': comments, 'fields': {}}
            comments = []
            records.append(current)
        elif '=' in line and current is not None:
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    for item in records:
        assert re.fullmatch(r'[+-]?\d+', item['fields']['indx'])
        assert re.fullmatch(r'[+-]?\d+', item['fields']['value'])
        item['index'] = int(item['fields']['indx'])
        item['value'] = int(item['fields']['value'])
        item['va'] = hex(0xA87080 + 4 * item['index'])
    return {'source': 'Data/GValue.kpd', 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'decoded_sha256': hashlib.sha256(decoded).hexdigest(), 'encoding': 'gbk',
            'expanded_size': expanded, 'packed_size': packed, 'shift': shift,
            'source_text': text, 'items': records, 'trailing_comments': comments}


def main():
    result = inspect()
    (HERE / '证据').mkdir(exist_ok=True)
    (HERE / '证据/resource.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                             encoding='utf-8')
    lines = ['// GValue.kpd当前原文；每行仅增加//前缀，原始解码文本另存JSON。',
             '// ============================================================================']
    lines.extend('// ' + line for line in result['source_text'].splitlines())
    (HERE / 'GValue_kpd_原文.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({'items': len(result['items']), 'indices': [i['index'] for i in result['items']],
                      'source_sha256': result['source_sha256']}, ensure_ascii=True))


if __name__ == '__main__':
    main()
