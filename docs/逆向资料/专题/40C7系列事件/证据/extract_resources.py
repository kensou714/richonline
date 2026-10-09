"""只读解包本组Prop、RichStr、Anim；保存原字节指纹与字段原文。"""
from pathlib import Path
import hashlib, json, struct, re
import lzokay
ROOT = Path('F:/大富翁online/Richonline')
OUT = Path(__file__).parent
provenance, texts = [], {}
for name, encoding in [('RichStr','cp950'),('Prop','cp950'),('Anim','gbk')]:
    source = 'Data/'+name+'.kpd'
    raw = (ROOT/source).read_bytes()
    packed = bytes((b-raw[0])&255 for b in raw[1:])
    size, compressed = struct.unpack_from('<II',packed)
    assert compressed == len(packed)-8
    plain = lzokay.decompress(packed[8:],size)
    assert len(plain)==size
    output = name+'.decoded.bin'
    (OUT/output).write_bytes(plain)
    texts[name] = plain.decode(encoding,errors='strict')
    provenance.append(dict(source=source,source_sha256=hashlib.sha256(raw).hexdigest(),
        decoded_sha256=hashlib.sha256(plain).hexdigest(),output=output,decoder=encoding+' strict'))
def select(text, tag, ids):
    result = {}
    for block in text.split('['+tag+']')[1:]:
        match = re.search(r'^\s*indx\s*=\s*(\d+)',block,re.M)
        if match and int(match[1]) in ids:
            # 下一节中文标题注释在标记前，因此字段摘要仅保留本节赋值。
            result[match[1]] = '\n'.join(line for line in block.splitlines() if '=' in line and not line.lstrip().startswith('//'))
    return result
result=dict(richstr=select(texts['RichStr'],'ITEM',{40,41}),
    props=select(texts['Prop'],'PROP',set(range(1058,1067))),
    animations=select(texts['Anim'],'ANIM',{4,5,19,20,21,22}))
(OUT/'resource_provenance.json').write_text(json.dumps(provenance,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'resource_semantics.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
