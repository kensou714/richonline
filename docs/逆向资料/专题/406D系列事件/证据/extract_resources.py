"""只读提取本专题资源原文、配置样本与指纹；不写游戏源文件。"""
from pathlib import Path
import hashlib
import json
import re
import struct
import lzokay

ROOT = Path('F:/大富翁online/Richonline')
OUT = Path(__file__).parent
records = []
texts = {}
for relative in ['Data/RichStr.kpd', 'Data/Anim.kpd', 'Data/Prop.kpd']:
    raw = (ROOT / relative).read_bytes()
    decoded = bytes((value - raw[0]) & 255 for value in raw[1:])
    size, compressed_size = struct.unpack_from('<II', decoded)
    assert compressed_size == len(decoded) - 8
    plain = lzokay.decompress(decoded[8:], size)
    assert len(plain) == size
    output = Path(relative).stem + '.decoded.bin'
    (OUT / output).write_bytes(plain)
    encoding = 'gbk' if relative == 'Data/Anim.kpd' else 'cp950'
    records.append(dict(source=relative, source_sha256=hashlib.sha256(raw).hexdigest(),
                        source_bytes=len(raw), declared_bytes=size,
                        decoded_sha256=hashlib.sha256(plain).hexdigest(), output=output,
                        decoder=encoding+' strict；不代替客户端CP_ACP运行语义'))
    texts[Path(relative).stem] = plain.decode(encoding, errors='strict')

selected = {}
ids = set(range(196, 216)) | {10, 24, 181, 255, 281, 286}
for block in texts['RichStr'].split('[ITEM]')[1:]:
    match = re.search(r'^\s*indx\s*=\s*(\d+)', block, re.M)
    if match and int(match[1]) in ids:
        selected[match[1]] = block.strip()
anim = []
for block in texts['Anim'].split('[ANIM]')[1:]:
    match = re.search(r'^\s*indx\s*=\s*(\d+)', block, re.M)
    if match and int(match[1]) == 9:
        # 下一节名称注释放在[ANIM]之前；只抄本节字段，避免把“出医院”错归9号。
        anim.append('\n'.join(line.strip() for line in block.splitlines()
                              if re.match(r'^\s*(indx|time|free|surf_\d+)\s*=', line)))
(OUT / 'resource_provenance.json').write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding='utf-8')
(OUT / 'resource_semantics.json').write_text(json.dumps(dict(
    encoding='RichStr/Prop按cp950 strict；Anim按gbk strict；原样保留文字及占位符', selected_richstr=selected,
    animation9=anim, prop_note='仅解包保留指纹；完整商品表解析复用商店专题'),
    ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(sources=len(records), richstr=selected, animation9=anim), ensure_ascii=True))
