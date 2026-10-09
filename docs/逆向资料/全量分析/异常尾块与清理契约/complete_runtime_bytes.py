"""从已核验主范围补入运行库导出的填充字节，不将数据伪装成指令。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def main():
    evidence = json.loads((HERE/'cleanup_evidence.json').read_text(encoding='utf-8'))
    runtime = json.loads((HERE/'unwind_runtime.json').read_text(encoding='utf-8'))
    assert evidence['disk_sha256'] == runtime['disk_sha256']
    index, source = next((n, r) for n, r in enumerate(evidence['records']) if r['function_va']=='0x91fbb0')
    span = source['main_bytes']
    offset, size = 0x91fbbf-int(span['va'],16), 17
    raw = {key: bytes.fromhex(span[key])[offset:offset+size].hex() for key in ('idb_hex','disk_hex')}
    assert raw['idb_hex'] == raw['disk_hex'] == 'cc'*size
    supplement = dict(va='0x91fbbf',size=size,matching=True,**raw,
        kind='原始填充字节，非指令导出',
        source='cleanup_evidence.json#/records/%d/main_bytes' % index,
        note='IDA聚合db 12h dup CCh项已导首字节91FBBE；此项补齐其余17字节。')
    function = next(f for f in runtime['functions'] if f['va']=='0x91fbb0')
    function['byte_ranges'] = sorted([r for r in function['byte_ranges'] if r['va']!='0x91fbbf'] + [supplement], key=lambda r:int(r['va'],16))
    (HERE/'unwind_runtime.json').write_text(json.dumps(runtime,ensure_ascii=False,indent=2),encoding='utf-8')

if __name__ == '__main__':
    main()
