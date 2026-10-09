"""独审补充：复读格式常量与既有专题挂接，不改写作者原证。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/大富翁online/Richonline')
TOPICS = HERE.parents[1]


def audit():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 60)[0]
    count, optional = struct.unpack_from('<H', blob, pe + 6)[0], struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40 * i + 8) for i in range(count)]

    def disk(va, size):
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return blob[offset + relative:offset + relative + size]
        raise AssertionError(('无PE后备', hex(va), size))

    def read(path):
        return json.loads(path.read_text(encoding='utf-8-sig'))

    instruction = disk(0x7B0011, 5)
    assert instruction[0] == 0x68
    address = struct.unpack_from('<I', instruction, 1)[0]
    raw_format = disk(address, 128).split(b'\0', 1)[0]
    assert raw_format == b'%[^\t]%d%*d%*d%*d%*d%*d\t%*[^\t]\t%[^\t]\t%[^\t]'
    startup = read(TOPICS / '4090系列事件/证据/news_startup.json')
    entry = next(f for f in startup['functions'] if f['va'] == '0x7acd60')
    for span in entry['byte_ranges']:
        assert disk(int(span['va'], 16), span['size']).hex() == span['disk_hex'] == span['idb_hex']
    stock = read(TOPICS / '股票与交易流程/证据/stock_core.json')
    source = next(f for f in stock['functions'] if f['va'] == '0x64f2a0')
    external = read(HERE / '外部挂接.json')
    saved_assembly = {row['va']: row['text'] for row in source['assembly']}
    assert all(saved_assembly[row['va']] == row['text'] for row in external['assembly'])
    assert all(row in source['calls'] for row in external['calls'])
    return dict(exe_sha256=hashlib.sha256(blob).hexdigest(), format_instruction='0x7b0011',
                format_address=hex(address), format_hex=raw_format.hex(), format_text=raw_format.decode('ascii'),
                reused_startup='0x7acd60', startup_spans=len(entry['byte_ranges']),
                reused_owner='0x64f2a0', excerpt_instructions=len(external['assembly']),
                excerpt_calls=len(external['calls']), mismatches=0,
                scope='磁盘格式常量和复用原证归属复核；不新增完整函数，不含独立live执行。')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_supplement.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))
