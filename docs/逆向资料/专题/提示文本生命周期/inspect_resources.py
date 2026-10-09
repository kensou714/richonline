"""只读验证 UI4 的 Intf 配置和实际 label 资源，不写客户端资源。"""
import hashlib
import json
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]

def sections(text):
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if value.startswith('[') and value.endswith(']'):
            out.append(dict(section=value[1:-1], line=number, fields={}, raw_lines=[line]))
        elif out:
            out[-1]['raw_lines'].append(line)
            if '=' in line and not value.startswith('//'):
                key, val = line.split('=', 1)
                out[-1]['fields'][key.strip().lower()] = val.strip()
    return out

def collect():
    records = []
    for source in ('Interface/Intf.kpd', 'Interface/G_MsgBox.ui'):
        data = (ROOT/source).read_bytes()
        if source.endswith('.kpd'):
            key = data[0]
            expanded, packed = struct.unpack('<II', bytes((b-key)&255 for b in data[1:9]))
            assert packed == len(data)-9
            plain = lzokay.decompress(bytes((b-key)&255 for b in data[9:]), expanded)
            assert len(plain) == expanded
        else:
            key = b'RichNet'
            plain = bytes((b-key[i % len(key)]) & 255 for i,b in enumerate(data))
        text = plain.decode('gbk', errors='strict')
        assert text.encode('gbk') == plain
        rows = sections(text)
        if source.endswith('.kpd'):
            rows = [r for r in rows if r['fields'].get('indx') == '4']
            assert len(rows) == 1 and rows[0]['fields']['file'] == 'G_MsgBox.ui'
        else:
            assert any(r['fields'].get('id') == '1' and r['fields'].get('type') == 'label' for r in rows)
        records.append(dict(source=source, source_sha256=hashlib.sha256(data).hexdigest(),
            decoded_sha256=hashlib.sha256(plain).hexdigest(), codec='gbk', strict_roundtrip=True,
            sections=rows))
    return dict(records=records)

if __name__ == '__main__':
    result = collect()
    (HERE/'证据/resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({r['source']: len(r['sections']) for r in result['records']}, ensure_ascii=False))
