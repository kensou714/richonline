"""IDA-MCP只读取证：常量、分派表、RTC声明；db由调用环境注入。"""
from pathlib import Path
import json
import re
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
blob = (ROOT/'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I',blob,0x3c)[0]
image_base = struct.unpack_from('<I',blob,pe+52)[0]
count = struct.unpack_from('<H',blob,pe+6)[0]
optional = struct.unpack_from('<H',blob,pe+20)[0]
sections = [struct.unpack_from('<IIII',blob,pe+24+optional+40*i+8) for i in range(count)]
records = {}
def audit(va,size,kind):
    original = db.bytes.get_bytes_at(va,size)
    disk = None
    for _,rva,raw_size,offset in sections:
        relative = va-image_base-rva
        if 0 <= relative and relative+size <= raw_size:
            disk = blob[offset+relative:offset+relative+size]
            break
    row = dict(va=hex(va),size=size,kind=kind,idb_hex=original.hex(),
               disk_hex=disk.hex() if disk is not None else None,
               matching=original==disk if disk is not None else None)
    records[(va,size)] = row
    return row
def zbytes(va):
    result = bytearray()
    for delta in range(1024):
        item = db.bytes.get_bytes_at(va+delta,1)
        result.extend(item)
        if item==b'\0': return bytes(result)
    raise ValueError(hex(va))

for va,size,kind in [(0xA2EB70,36,'Log/Game/Sys及文件名'),(0xA2D680,4,'ALL标记'),
                     (0xA766AC,4,'格式器单例指针'),(0xABABC4,4,'输出器单例指针'),
                     (0xA6723C,4,'界面文字日志资格门'),
                     (0x7DDD39,64*4,'64项switch跳表')]:
    audit(va,size,kind)
sources = ['core.json','lifecycle.json','buffers.json','record_writers.json',
           'event_producers.json','cleanup_and_encoding.json','resource_parser.json',
           'shutdown.json','shutdown_bridge.json','date.json']
rtc = []
strings = {}
for source in sources:
    for function in json.loads((BASE/source).read_text('utf-8'))['functions']:
        for ins in function['assembly']:
            va = int(ins['va'],16)
            if '; Fd' in ins['text']:
                raw = db.bytes.get_bytes_at(va,6)
                assert raw[:2] == b'\x8d\x15'
                fd = struct.unpack_from('<I',raw,2)[0]
                n,table = struct.unpack('<II',db.bytes.get_bytes_at(fd,8))
                assert 0 < n < 64
                audit(fd,8,'RTC头')
                audit(table,n*12,'RTC变量表')
                variables = []
                for index in range(n):
                    offset,size,name = struct.unpack('<iII',db.bytes.get_bytes_at(table+12*index,12))
                    text = zbytes(name)
                    audit(name,len(text),'RTC变量名')
                    variables.append(dict(offset=offset,size=size,name=text[:-1].decode('ascii')))
                rtc.append(dict(function=function['va'],site=ins['va'],fd=hex(fd),variables=variables))
            raw = db.bytes.get_bytes_at(va,5)
            if raw[0] == 0x68 and ('Format' in ins['text'] or function['va'] in
                                  ['0x7dcfe0','0x8198e0','0x623ad0','0x623b60','0x81bea0','0x7dccc0']):
                pointer = struct.unpack_from('<I',raw,1)[0]
                if 0xA00000 <= pointer < 0xA70000:
                    value = zbytes(pointer)
                    audit(pointer,len(value),'格式/断言常量')
                    strings[hex(pointer)] = dict(hex=value.hex(),ascii=value[:-1].decode('ascii',errors='backslashreplace'))
result = dict(records=list(records.values()),rtc=rtc,strings=strings,
              switch_targets=[hex(x) for x in struct.unpack('<64I',db.bytes.get_bytes_at(0x7DDD39,256))])
(BASE/'data_audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(records=len(records),rtc=len(rtc),strings=len(strings)),ensure_ascii=True))
