"""只读解析等待窗口与相关文本，输出限定在本专题。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]


def sections(text):
    result = []
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r'\s*\[([^]]+)\]\s*', line)
        if match:
            current = {'section': match.group(1), 'fields': {}}
            result.append(current)
        elif current and '=' in line and not line.lstrip().startswith((';', '//')):
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    return result


def decode(relative):
    source = (PROJECT / relative).read_bytes()
    record = {'source': relative, 'sha256': hashlib.sha256(source).hexdigest(),
              'size': len(source)}
    if relative.endswith('.ui'):
        decoded = bytes((value - b'RichNet'[index % 7]) & 255
                        for index, value in enumerate(source))
        record['transform'] = '逐字节减RichNet循环密钥，模256'
    else:
        key = source[0]
        header = bytes((value - key) & 255 for value in source[1:9])
        size, count = struct.unpack('<II', header)
        if not 0 < size <= 64 * 1024 * 1024 or count != len(source) - 9:
            raise ValueError('容器长度非法：' + relative)
        decoded = lzokay.decompress(bytes((value - key) & 255 for value in source[9:]), size)
        if len(decoded) != size:
            raise ValueError('解压长度不符：' + relative)
        record.update(key=key, raw_size=size, packed_size=count)
    encoding = 'cp950' if relative == 'Data/RichStr.kpd' else 'gbk'
    parsed = sections(decoded.decode(encoding, errors='strict'))
    record.update(decoded_sha256=hashlib.sha256(decoded).hexdigest(),
                  encoding=encoding + ' strict')
    return record, parsed


def main():
    records = []
    for relative in ['Interface/L_WaitPlayer.ui', 'Interface/Intf.kpd', 'Data/RichStr.kpd']:
        record, parsed = decode(relative)
        if relative.endswith('.ui'):
            record['sections'] = parsed
        elif relative.endswith('Intf.kpd'):
            record['sections'] = [item for item in parsed
                                  if any('L_WaitPlayer.ui' in value
                                         for value in item['fields'].values())]
        else:
            record['sections'] = [item for item in parsed
                                  if item['fields'].get('indx') in ['95', '96', '328']]
        records.append(record)
    mappings = []
    pictures = {}
    for relative in ['Tex/other.dat', 'Tex/event.dat', 'Tex/build.dat']:
        record, parsed = decode(relative)
        if relative.endswith('other.dat'):
            selected = [item for item in parsed if item['section'].startswith('O_24_S_')
                        or item['section'] in ['OTHER_24', 'O_0_S_90', 'O_21_S_47',
                                               'O_21_S_48', 'O_21_S_49', 'O_21_S_50']]
        elif relative.endswith('event.dat'):
            selected = [item for item in parsed if item['section'].startswith(('E_11_S_', 'E_12_S_'))
                        or item['section'] in ['EVENT_11', 'EVENT_12']]
        else:
            selected = [item for item in parsed if item['section'].startswith('B_10_L_')
                        or item['section'] == 'BUILD_10']
        record['sections'] = selected
        mappings.append(record)
        for item in selected:
            if 'npid' not in item['fields']:
                continue
            npid = int(item['fields']['npid'])
            path = f'Tex/{npid // 500:02d}/{npid:05d}.np'
            source = (PROJECT / path).read_bytes()
            key = source[0]
            size, count = struct.unpack('<II', bytes((value - key) & 255 for value in source[1:9]))
            if not 0 < size <= 64 * 1024 * 1024 or count != len(source) - 9:
                raise ValueError('NP容器长度非法：' + path)
            decoded = lzokay.decompress(bytes((value - key) & 255 for value in source[9:]), size)
            if len(decoded) != size:
                raise ValueError('NP解压长度不符：' + path)
            mode = decoded[0]
            width, height = struct.unpack_from('<II', decoded, 1)
            frames = struct.unpack_from('<I', decoded, 9)[0] if mode == 1 else 1
            pictures[path] = {'source': path, 'npid': npid, 'sha256': hashlib.sha256(source).hexdigest(),
                              'decoded_sha256': hashlib.sha256(decoded).hexdigest(),
                              'mode': mode, 'width': width, 'height': height, 'frames': frames,
                              'has_alpha_plane': bool(decoded[13]) if mode == 1 else None,
                              'scope': '容器与NP头核验；不渲染，不声称动画完成或网络回执'}
    (HERE / '证据' / 'resources.json').write_text(json.dumps(
        {'scope': '当前资源只读解码；资源文字不是协议业务或实机成功的证明',
         'records': records, 'mappings': mappings, 'picture_headers': list(pictures.values())},
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'resource_count': len(records),
                      'record_counts': [len(item['sections']) for item in records],
                      'mapping_count': len(mappings), 'picture_count': len(pictures)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
