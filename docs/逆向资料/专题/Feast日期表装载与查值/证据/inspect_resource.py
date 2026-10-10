"""按既有 KPD 工具的减 key / LZO 契约只读解包，保留二进制日期对。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
BASE = Path(__file__).resolve().parent


def main():
    import lzokay

    raw = (ROOT / 'Data/Feast.kpd').read_bytes()
    if len(raw) < 9:
        raise ValueError('KPD 头长度不足')
    key = raw[0]
    size, packed = struct.unpack('<II', bytes((byte - key) & 255 for byte in raw[1:9]))
    if not 0 < size <= 16 * 1024 * 1024 or not 0 < packed <= len(raw) - 9:
        raise ValueError('KPD 长度不符')
    plain = lzokay.decompress(bytes((byte - key) & 255 for byte in raw[9:9 + packed]), size)
    if len(plain) != size:
        raise ValueError('解包长度不符')
    if len(plain) % 26:
        raise ValueError('当前样本不是 26 字节的整倍数')
    rows = [dict(index=offset // 26, offset=offset, year_by_lookup=2004 + offset // 26,
                 raw_hex=plain[offset:offset + 26].hex(),
                 pairs=[dict(slot=slot, month=plain[offset + 2 * slot],
                             day=plain[offset + 2 * slot + 1]) for slot in range(13)])
            for offset in range(0, len(plain), 26)]
    output = dict(source='Data/Feast.kpd', source_size=len(raw),
                  source_sha256=hashlib.sha256(raw).hexdigest(), key=key,
                  packed_size=packed, tail_size=len(raw) - 9 - packed,
                  decoded_size=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                  decoded_hex=plain.hex(), record_size=26, rows=rows,
                  encoding_boundary='本表按 BYTE 日期对消费；没有文本编码证据。',
                  sample_boundary='年份标签来自已取证查询的 year-2004 算式；样本容量不代表运行时范围检查。')
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'resource_raw.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (BASE.parent / 'Feast_kpd_只读转录.txt').write_text(
        '// 当前 Feast.kpd 二进制只读转录\n' +
        '// 年份标签由查询算式 year-2004 解释；每行 26 字节，依次为槽 0..12 的月/日。\n' +
        '// 原字节、偏移和包指纹见证据/resource_raw.json；没有文本编码判定。\n' +
        '\n'.join('// {:04d} @{:03X}  '.format(row['year_by_lookup'], row['offset']) +
                  ' '.join('{:02X}'.format(byte) for byte in bytes.fromhex(row['raw_hex']))
                  for row in rows) + '\n', encoding='utf-8')
    print(json.dumps(dict(source_size=len(raw), decoded_size=len(plain), rows=len(rows))))


if __name__ == '__main__':
    main()
