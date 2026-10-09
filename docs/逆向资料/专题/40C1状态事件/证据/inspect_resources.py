"""只读提取40C1使用的道具与文本编号；编号相同不替代调用对象核验。"""
import hashlib
import json
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def sections(text):
    result, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = dict(section=line[1:-1], line=number, fields={})
            result.append(current)
        elif current is not None and '=' in line and not line.startswith('//'):
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    return result


def main():
    records = []
    for relative, selected in [('Data/Prop.kpd', {'1048'}),
                               ('Data/RichStr.kpd', {'15', '40', '41'})]:
        raw = (ROOT / relative).read_bytes()
        key = raw[0]
        expanded, packed = struct.unpack('<II', bytes((b-key) & 255 for b in raw[1:9]))
        assert 0 < expanded <= 64*1024*1024 and 0 < packed <= len(raw)-9
        data = lzokay.decompress(bytes((b-key) & 255 for b in raw[9:9+packed]), expanded)
        assert len(data) == expanded
        text = data.decode('cp950', errors='strict')
        assert text.encode('cp950') == data
        rows = [s for s in sections(text) if s['fields'].get('indx') in selected]
        records.append(dict(source=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                            decoded_sha256=hashlib.sha256(data).hexdigest(),
                            raw_size=expanded, packed_size=packed, key=key,
                            encoding='cp950严格往返；客户端CP_ACP另论', sections=rows))
    (HERE / 'resource_samples.json').write_text(json.dumps(dict(scope='当前资源只读解包', records=records),
        ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(records, ensure_ascii=False))


if __name__ == '__main__':
    main()
