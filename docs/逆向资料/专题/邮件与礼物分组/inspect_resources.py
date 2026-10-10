"""只读解码邮件系统资源，保留分组消费所需的控件证据。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
HELPER = runpy.run_path(str(HERE.parent / '提示文本生命周期/inspect_resources.py'))

def collect():
    records = []
    for source in ('Interface/Intf.kpd', 'Interface/L_MailSystem.ui'):
        data = (ROOT / source).read_bytes()
        if source.endswith('.kpd'):
            key = data[0]
            expanded, packed = HELPER['struct'].unpack('<II', bytes((b-key)&255 for b in data[1:9]))
            assert packed == len(data)-9
            plain = HELPER['lzokay'].decompress(bytes((b-key)&255 for b in data[9:]), expanded)
            assert len(plain) == expanded
        else:
            key = b'RichNet'
            plain = bytes((b-key[i % len(key)]) & 255 for i,b in enumerate(data))
        text = plain.decode('gbk', errors='strict')
        assert text.encode('gbk') == plain
        rows = HELPER['sections'](text)
        if source.endswith('.kpd'):
            rows = [r for r in rows if r['fields'].get('indx') == '108']
            assert len(rows) == 1 and rows[0]['fields']['file'] == 'L_MailSystem.ui'
        else:
            ids = {'2', '3', '4', '1000', '2000', '3000', '1001', '3001'}
            ids |= {str(i+j) for i in range(1010,1121,10) for j in range(4)}
            ids |= {str(i+j) for i in range(3010,3121,10) for j in range(4)}
            rows = [r for r in rows if r['fields'].get('id') in ids]
            assert len(rows) == len(ids)
        records.append(dict(source=source, source_sha256=hashlib.sha256(data).hexdigest(),
                            decoded_sha256=hashlib.sha256(plain).hexdigest(), codec='gbk',
                            strict_roundtrip=True, sections=rows))
    return dict(records=records)

if __name__ == '__main__':
    result = collect()
    (HERE / '证据/resources.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({r['source']:len(r['sections']) for r in result['records']},ensure_ascii=False))
