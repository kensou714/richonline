"""只读解包股票相关资源并记录来源；不修改游戏资源。"""
from pathlib import Path
import hashlib
import json
import struct
import re
import lzokay

ROOT = Path('F:/大富翁online/Richonline')
OUT = Path(__file__).parent
records = []
for relative in ['Data/Stock.kpd', 'Interface/G_Stock.ui',
                 'Interface/G_MyStock.ui', 'Interface/G_SelectStock.ui',
                 'Data/RichStr.kpd']:
    source = ROOT / relative
    raw = source.read_bytes()
    if source.suffix == '.ui':
        records.append(dict(source=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                            source_bytes=len(raw), note='UI二进制只记原始指纹，不按KPD解包'))
        continue
    decoded = bytes((value - raw[0]) & 255 for value in raw[1:])
    size, compressed_size = struct.unpack_from('<II', decoded)
    assert compressed_size == len(decoded) - 8
    plain = lzokay.decompress(decoded[8:], size)
    assert len(plain) == size
    name = source.stem + '.decoded.bin'
    (OUT / name).write_bytes(plain)
    records.append(dict(source=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                        source_bytes=len(raw), declared_bytes=size,
                        decoded_sha256=hashlib.sha256(plain).hexdigest(),
                        output=name))
(OUT / 'resource_provenance.json').write_text(
    json.dumps(records, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(records, ensure_ascii=False))
stock_text = (OUT / 'Stock.decoded.bin').read_bytes().decode('big5')
stock_rows = []
for block in stock_text.split('[STOCK]')[1:]:
    fields = dict(re.findall(r'^\s*(indx|name|asset|gushu|huopo)\s*=\s*(.*?)\s*$', block, re.M))
    stock_rows.append(fields)
rich_text = (OUT / 'RichStr.decoded.bin').read_bytes().decode('big5')
messages = {}
for block in rich_text.split('[ITEM]')[1:]:
    match = re.search(r'^\s*indx\s*=\s*(\d+)', block, re.M)
    if match and int(match[1]) in set(range(278, 288)) | set(range(311, 319)):
        messages[match[1]] = block.strip()
(OUT / 'resource_semantics.json').write_text(json.dumps(
    dict(encoding='Big5；按资源内可读繁体注释和名称核验',
         stock_rows=stock_rows, selected_richstr=messages),
    ensure_ascii=False, indent=2), encoding='utf-8')
