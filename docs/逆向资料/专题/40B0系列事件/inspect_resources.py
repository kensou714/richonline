"""只读解码八种卡片、动画17与骰子窗口；不重打包原始资源。"""
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def blocks(text):
    result = []
    for part in re.split(r'(?m)^\[', text)[1:]:
        label, rest = part.split(']', 1)
        fields = {}
        for line in rest.splitlines():
            if '=' in line and not line.lstrip().startswith('//'):
                key, value = line.split('=', 1)
                fields[key.strip()] = value.strip()
        result.append({'section': label, 'fields': fields})
    return result


def decode(relative, codec):
    raw = (ROOT / relative).read_bytes()
    if relative.endswith('.ui'):
        key = b'RichNet'
        plain = bytes((value - key[i % len(key)]) & 255 for i, value in enumerate(raw))
        method = '逐字节减RichNet循环密钥'
    else:
        decoded = bytes((value - raw[0]) & 255 for value in raw[1:])
        size, compressed = struct.unpack_from('<II', decoded)
        assert len(decoded) == 8 + compressed
        plain = lzokay.decompress(decoded[8:], size)
        assert len(plain) == size
        method = '首字节减法解码、LE32长度、LZO'
    text = plain.decode(codec)
    assert text.encode(codec) == plain
    return {'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(),
            'plain_sha256': hashlib.sha256(plain).hexdigest(), 'method': method,
            'encoding': codec, 'roundtrip': True, 'blocks': blocks(text)}


def main():
    selections = []
    for relative, codec in [('Data/Prop.kpd', 'big5'), ('Data/Anim.kpd', 'gb18030'),
                            ('Interface/Intf.kpd', 'gb18030'),
                            ('Interface/G_YaoKongDice.ui', 'gb18030')]:
        record = decode(relative, codec)
        all_blocks = record.pop('blocks')
        if relative == 'Data/Prop.kpd':
            selected = [b for b in all_blocks if b['fields'].get('indx') in map(str, range(1031, 1039))]
            assert len(selected) == 8
        elif relative == 'Data/Anim.kpd':
            selected = [b for b in all_blocks if b['fields'].get('indx') in ['4', '17']]
            assert len(selected) == 2
        elif relative == 'Interface/Intf.kpd':
            selected = [b for b in all_blocks if b['fields'].get('indx') == '24']
            assert len(selected) == 1
        else:
            selected = all_blocks
            assert sorted(int(b['fields']['ID']) for b in selected if b['fields'].get('Type') == 'button') == list(range(1, 7))
        record.update(total_blocks=len(all_blocks), selected=selected)
        selections.append(record)
    (HERE / '资源原证.json').write_text(json.dumps(selections, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// 当前资源只读摘录；未修改原始文件。编码、散列与解析方法见资源原证.json。', '//']
    for record in selections:
        lines += ['// ' + record['path'], '// SHA256 ' + record['sha256']]
        for block in record['selected']:
            lines.append('// [' + block['section'] + ']')
            lines += ['// ' + key + '=' + value for key, value in block['fields'].items()]
        lines.append('//')
    (HERE / '04_资源摘录.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('只读解码4个资源，编码往返与目标条目数量通过。')


if __name__ == '__main__':
    main()
