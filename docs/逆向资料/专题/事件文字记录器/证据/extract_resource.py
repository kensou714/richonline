"""只读解包LogFixStr；保留原字节、CP950严格解码及逐行条目。"""
from pathlib import Path
import hashlib
import json
import re
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
source = ROOT/'Data/LogFixStr.kpd'
raw = source.read_bytes()
packed = bytes((b-raw[0]) & 255 for b in raw[1:])
size, compressed = struct.unpack_from('<II',packed)
assert compressed == len(packed)-8
plain = lzokay.decompress(packed[8:],size)
assert len(plain) == size
text = plain.decode('cp950',errors='strict')
assert text.encode('cp950',errors='strict') == plain
(BASE/'LogFixStr.decoded.bin').write_bytes(plain)
entries = []
current = None
header = {}
for number,line in enumerate(text.splitlines(),1):
    if line.strip() == '[STRING]':
        current = dict(section_line=number)
        entries.append(current)
    match = re.fullmatch(r'\s*(\w+)\s*=\s*(.*)',line)
    if match:
        key,value = match.groups()
        if current is None:
            header[key] = int(value)
        else:
            current[key] = int(value) if key=='indx' else value
            current[key+'_line'] = number
ids = [r['indx'] for r in entries]
assert len(ids)==len(set(ids)) and all(0 <= i < header['count'] for i in ids)
for entry in entries:
    entry['win32_bytes'] = entry['win32'].encode('cp950').hex()
    entry['required_bytes_with_nul'] = len(bytes.fromhex(entry['win32_bytes']))+1
    assert entry['required_bytes_with_nul'] <= header['size']
result = dict(source='Data/LogFixStr.kpd',source_sha256=hashlib.sha256(raw).hexdigest(),
              decoded_sha256=hashlib.sha256(plain).hexdigest(),decoded_size=size,
              compressed_size=compressed,key=raw[0],encoding='cp950 strict roundtrip',
              header=header,declared_slots=header['count'],present_entries=len(entries),
              max_required_bytes=max(e['required_bytes_with_nul'] for e in entries),
              entries=entries)
(BASE/'resource.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='entries'},ensure_ascii=True))
