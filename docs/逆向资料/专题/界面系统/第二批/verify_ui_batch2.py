"""只读比较 IDB 函数字节与当前 PE，并联读 Intf.kpd 给窗口槽命名。"""
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay

root = Path(__file__).resolve().parents[5]
outdir = Path(__file__).resolve().parent
data = json.loads((outdir / 'ida_ui_batch2_raw.json').read_text(encoding='utf8'))
binary = (root / 'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', binary, 0x3C)[0]
count = struct.unpack_from('<H', binary, pe + 6)[0]
optsize = struct.unpack_from('<H', binary, pe + 20)[0]
base = struct.unpack_from('<I', binary, pe + 24 + 28)[0]
sections = []
for i in range(count):
    off = pe + 24 + optsize + i * 40
    vsize, rva, size, ptr = struct.unpack_from('<IIII', binary, off + 8)
    sections.append((rva, size, ptr))

def disk_bytes(va, length):
    rva = va - base
    for start, size, ptr in sections:
        if start <= rva and rva + length <= start + size:
            return binary[ptr + rva - start:ptr + rva - start + length]
    return None

checks = []
for function in data['functions'].values():
    old = bytes.fromhex(function['idb_bytes_hex'])
    current = disk_bytes(int(function['address'], 16), len(old))
    checks.append({'address': function['address'], 'length': len(old),
                   'match': old == current,
                   'idb_sha256': hashlib.sha256(old).hexdigest(),
                   'disk_sha256': hashlib.sha256(current).hexdigest() if current else None,
                   'different_offsets': [hex(i) for i, pair in enumerate(zip(old, current or b''))
                                         if pair[0] != pair[1]]})
data_checks = []
for region in data.get('data_regions', []):
    original = bytes.fromhex(region['bytes_hex'])
    current = disk_bytes(int(region['address'], 16), len(original))
    data_checks.append({'address': region['address'], 'length': len(original),
                        'kind': region['kind'], 'match': original == current})
raw = (root / 'Interface' / 'Intf.kpd').read_bytes()
decoded = bytes((value - raw[0]) & 255 for value in raw[1:])
size, compressed = struct.unpack_from('<II', decoded)
plain = lzokay.decompress(decoded[8:8 + compressed], size).decode('cp936')
records = {}
for part in plain.split('[INTF]')[1:]:
    record = dict((k.strip(), v.strip()) for k, v in
                  (line.split('=', 1) for line in part.splitlines()
                   if '=' in line and not line.lstrip().startswith('//')))
    records[int(record['indx'])] = record
slots = []
for i in range(160):
    slots.append({'slot': i, 'resource': records.get(i),
                  'factory': data['window_factories'].get(str(i)),
                  'status': '资源身份及工厂映射已核对；窗口业务未逐项审阅'})
payload = {'idb_input_sha256': data['idb_input_sha256'],
           'disk_sha256': hashlib.sha256(binary).hexdigest(),
           'function_count': len(checks), 'matched': sum(x['match'] for x in checks),
           'checks': checks, 'intf_sha256': hashlib.sha256(raw).hexdigest(),
           'data_checks': data_checks, 'slots': slots}
(outdir / 'ui_batch2_verification.json').write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps({'functions':len(checks), 'matched':payload['matched'],
                  'mismatches':[x['address'] for x in checks if not x['match']],
                  'data_regions':len(data_checks),
                  'data_mismatches':[x['address'] for x in data_checks if not x['match']],
                  'registered_factories':len(data['window_factories']),
                  'configured_slots':len(records)}, ensure_ascii=False))
