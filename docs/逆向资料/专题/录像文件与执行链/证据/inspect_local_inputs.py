"""只读当前客户端，保存RCD样本扫描与录像文字原文，不伪造文件样本。"""
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay

ROOT = Path(r'F:\大富翁online\Richonline')
OUT = Path(__file__).resolve().parent
raw = (ROOT/'Data/RichStr.kpd').read_bytes()
packed = bytes((byte-raw[0])&255 for byte in raw[1:])
size, compressed = struct.unpack_from('<II',packed)
assert compressed == len(packed)-8
plain = lzokay.decompress(packed[8:],size)
assert len(plain)==size
text = plain.decode('cp950',errors='strict')
assert text.encode('cp950')==plain
ids={1003,1004,1005,1006,1007,1008,1009,1010,1011,1013,1014,1016,1017,1037,1510,1511}
entries=[]
for block in text.split('[ITEM]')[1:]:
    match=re.search(r'^\s*indx\s*=\s*(\d+)',block,re.M)
    if match and int(match[1]) in ids:
        entries.append(dict(id=int(match[1]),lines=[line for line in block.splitlines()
                            if '=' in line and not line.lstrip().startswith('//')]))
result=dict(source='Data/RichStr.kpd',source_sha256=hashlib.sha256(raw).hexdigest(),
            decoded_sha256=hashlib.sha256(plain).hexdigest(),encoding='cp950 strict roundtrip',
            raw_size=len(raw),expanded_size=len(plain),entries=entries,
            boundary='资源原文证明当前包保留提示，不证明每个文字都有可达执行路径。')
(OUT/'recording_texts.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
samples=[]
for path in ROOT.rglob('*'):
    if path.is_file() and path.suffix.casefold()=='.rcd':
        b=path.read_bytes()
        samples.append(dict(path=str(path.relative_to(ROOT)),size=len(b),sha256=hashlib.sha256(b).hexdigest(),first64=b[:64].hex()))
(OUT/'sample_inventory.json').write_text(json.dumps(dict(root=str(ROOT),sample_count=len(samples),samples=samples,
    boundary='只搜索当前Richonline目录树；不扫描上级旧客户端或外部用户目录；没有创建RCD样本。'),ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(resource_entries=len(entries),rcd_samples=len(samples))))
