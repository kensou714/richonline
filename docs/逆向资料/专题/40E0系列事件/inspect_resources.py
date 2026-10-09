"""只读解码道具、动画、文字资源；原始资源不重打包。"""
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]

def decode(path, codec):
    raw = (ROOT / path).read_bytes()
    data = bytes((b - raw[0]) & 255 for b in raw[1:])
    size, compressed = struct.unpack_from('<II', data)
    assert len(data) == compressed + 8
    plain = lzokay.decompress(data[8:], size)
    text = plain.decode(codec)
    assert text.encode(codec) == plain
    sections = []
    for part in re.split(r'(?m)^\[', text)[1:]:
        name, tail = part.split(']', 1)
        fields = {}
        for line in tail.splitlines():
            if '=' in line and not line.lstrip().startswith('//'):
                k, v = line.split('=', 1)
                fields[k.strip()] = v.strip()
        sections.append({'section': name, 'fields': fields})
    return {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
            'plain_sha256': hashlib.sha256(plain).hexdigest(), 'encoding': codec,
            'roundtrip': True, 'blocks': sections}

def main():
    records = []
    for path, codec, ids in [
        ('Data/Prop.kpd', 'big5', list(range(1117, 1128)) + [1181, 1182, 1183]),
        ('Data/Anim.kpd', 'gb18030', [27, 28, 32, 33, 38]),
        ('Data/RichStr.kpd', 'big5', [10, 24, 28, 40, 41, 69, 70, 300, 301, 313, 314])]:
        record = decode(path, codec)
        blocks = record.pop('blocks')
        record['selected'] = [b for b in blocks if b['fields'].get('indx') in {str(i) for i in ids}]
        record['total_blocks'] = len(blocks)
        assert len(record['selected']) == len(ids), (path, len(record['selected']))
        records.append(record)
    (HERE / '资源原证.json').write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// 当前资源只读摘录；原始编码与散列见资源原证.json。', '//']
    for record in records:
        lines.extend(['// ' + record['path'], '// SHA256 ' + record['sha256']])
        for b in record['selected']:
            lines.append('// [' + b['section'] + ']')
            visible = {'indx', 'name', 'desc', 'icon', 'type', 'chType', 'time', 'free', 'hurt', 'str', 'string', 'text'}
            lines.extend('// ' + k + '=' + v for k, v in b['fields'].items() if k in visible or k.startswith('surf_'))
        lines.append('//')
    (HERE / '04_资源摘录.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('资源编码往返和条目数量通过。')

if __name__ == '__main__':
    main()
