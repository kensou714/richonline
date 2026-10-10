"""只读解包GoldCharge当前样本；离线分节不模拟客户端解析器。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def verify():
    source = (ROOT / 'Data/GoldCharge.kpd').read_bytes()
    shift = source[0]
    unmasked = bytes((byte - shift) & 255 for byte in source[1:])
    size, packed = struct.unpack_from('<II', unmasked)
    assert 0 < size <= 64 * 1024 * 1024 and packed == len(source) - 9
    raw = lzokay.decompress(unmasked[8:], size)
    assert len(raw) == size
    text = raw.decode('gbk', errors='strict')
    assert text.encode('gbk', errors='strict') == raw
    records, current, comments = [], None, []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith('//'):
            comments.append(stripped[2:].strip())
        elif stripped == '[ITEM]':
            current = dict(line=number, comments=comments, fields=[])
            comments = []
            records.append(current)
        elif '=' in stripped and current is not None:
            key, value = stripped.split('=', 1)
            current['fields'].append(dict(line=number, key=key.strip(), value=value.strip()))
    for row in records:
        fields = {entry['key']: entry['value'] for entry in row['fields']}
        assert len(fields) == len(row['fields'])
        assert set(fields) == {'indx', 'charge'}
        assert all(re.fullmatch(r'[+-]?\d+', fields[key]) for key in fields)
        row.update(index=int(fields['indx']), charge=int(fields['charge']))
    result = dict(schema='richonline-independent-goldcharge-resource-1', status='PASS',
                  source='Data/GoldCharge.kpd', source_size=len(source),
                  source_sha256=hashlib.sha256(source).hexdigest(), shift=shift,
                  decoded_size=size, packed_size=packed,
                  decoded_sha256=hashlib.sha256(raw).hexdigest(), encoding='gbk严格往返',
                  records=records, source_text=text,
                  boundary='当前样本事实；不证明合法索引上限、货币单位或运行时已装载')
    (HERE / 'independent_resource.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (HERE / 'independent_resource_sample.txt').write_text(
        '\n'.join('// ' + line for line in text.splitlines()) + '\n', encoding='utf-8')
    return dict(status='PASS', records=len(records), values=[(row['index'], row['charge']) for row in records])


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
