"""只读解包 TeachBoard 资源，保留完整字节、逐行原字节及编码阅读候选。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

ROOT = Path('F:/大富翁online/Richonline')
BASE = Path(__file__).resolve().parent / '证据'


def main():
    blob = (ROOT / 'Data/TeachBoard.kpd').read_bytes()
    assert len(blob) >= 9
    key = blob[0]
    size, packed = struct.unpack('<II', bytes((value - key) & 255 for value in blob[1:9]))
    assert 0 < size <= 16 * 1024 * 1024 and 0 < packed <= len(blob) - 9
    decoded = lzokay.decompress(bytes((value - key) & 255 for value in blob[9:9 + packed]), size)
    assert len(decoded) == size
    rows = []
    for number, raw in enumerate(decoded.splitlines(), 1):
        fields = raw.split(b'\t')
        rows.append(dict(line=number, raw_hex=raw.hex(), field_count=len(fields),
                         fields_hex=[field.hex() for field in fields],
                         big5_candidate=[field.decode('big5', errors='backslashreplace') for field in fields],
                         gbk_candidate=[field.decode('gbk', errors='backslashreplace') for field in fields]))
    result = dict(source='Data/TeachBoard.kpd', size=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
                  decoded_size=len(decoded), decoded_sha256=hashlib.sha256(decoded).hexdigest(),
                  key=key, packed_size=packed, tail_size=len(blob) - 9 - packed,
                  decoded_hex=decoded.hex(), rows=rows,
                  encoding_boundary='GBK/Big5仅供阅读，原字节为事实；运行时代码页未动态核实。')
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'resource_rows.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(rows=len(rows), decoded_size=len(decoded),
                          widths=sorted(set(row['field_count'] for row in rows))), ensure_ascii=False))


if __name__ == '__main__':
    main()
