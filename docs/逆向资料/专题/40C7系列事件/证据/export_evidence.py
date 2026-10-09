"""在当前IDA只读lease中重建函数字节原证；不声明函数、不修改或保存IDB。"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/40C7系列事件/证据'
assert hashlib.sha256((ROOT/'RnClient.exe').read_bytes()).hexdigest() == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
# db由IDA-MCP注入，公共导出器显式枚举主块和异常尾块。
exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'))
review = json.loads((BASE/'function_review.json').read_text(encoding='utf-8'))
for source in review['sources']:
    existing = json.loads((BASE/source).read_text(encoding='utf-8'))
    print(source, export_group(db, [int(f['va'],16) for f in existing['functions']], BASE/source))

blob = (ROOT/'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I',blob,0x3c)[0]
image_base = struct.unpack_from('<I',blob,pe+52)[0]
section_count = struct.unpack_from('<H',blob,pe+6)[0]
optional_size = struct.unpack_from('<H',blob,pe+20)[0]
sections = [struct.unpack_from('<IIII',blob,pe+24+optional_size+40*i+8)
            for i in range(section_count)]
def audit(va,size):
    original = db.bytes.get_bytes_at(va,size)
    disk = None
    for _,rva,raw_size,offset in sections:
        relative = va-image_base-rva
        if 0 <= relative and relative+size <= raw_size:
            disk = blob[offset+relative:offset+relative+size]
            break
    return dict(va=hex(va),size=size,idb_hex=original.hex(),
                disk_hex=disk.hex() if disk is not None else None,
                matching=original==disk if disk is not None else None)
def save(name,data):
    (BASE/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

data = json.loads((BASE/'data_audit.json').read_text(encoding='utf-8'))
data['records'] = [audit(int(r['va'],16),r['size']) for r in data['records']]
for record in data['virtual_thunks']:
    record.update(audit(int(record['va'],16),5))
save('data_audit.json',data)
ranges = json.loads((BASE/'undeclared_ranges.json').read_text(encoding='utf-8'))
for record in ranges['ranges']:
    start,end = int(record['va'],16),int(record['end_va'],16)
    assert db.functions.get_at(start) is None
    record['assembly'] = [dict(va=hex(ins.ea),text=db.instructions.get_disassembly(ins))
                          for ins in db.instructions.get_between(start,end)]
    record['byte_ranges'] = [audit(start,end-start)]
save('undeclared_ranges.json',ranges)

# 保留上游注册原证，不将继承的“未分析”字段冒充本专题的最新审阅状态。
source_path = ROOT/'docs/逆向资料/专题/游戏分派桥接/证据/dispatch_bridges_raw.json'
source = json.loads(source_path.read_text(encoding='utf-8'))
codes = set(range(0x40c7,0x40d0)) | {0x6000,0x6001,0x6003,0x6005,0x6006,0x6007,0x6061,0x606b,0x6078,0x6079}
entries = [dict(e) for e in source['entries'] if int(e['code'],16) in codes]
for entry in entries:
    entry['upstream_status'] = entry['status']
    entry['status'] = '注册字节和桥接模板已核验；本专题handler结论见function_review.json'
    entry['handler_status'] = '本专题逐项审阅；不等于完整依赖闭包'
    entry['evidence_path'] = '专题/游戏分派桥接/证据/dispatch_bridges_raw.json'
    entry['unknowns'] = ['网络方向与上行请求未在本专题闭合','网络层实际包长不等于已读字段下界','完整依赖与动态运行另核']
save('binding.json',dict(source_reference=str(source_path),entries=entries))
# 资源请另运行extract_resources.py；更换客户端版本须重新核验全部语义。
