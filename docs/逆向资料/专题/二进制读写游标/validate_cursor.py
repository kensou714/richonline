"""验证当前 PE 原证、完整 chunks、逐函数登记及离线宽度样本；不运行客户端。"""
import ast
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    fingerprint = hashlib.sha256(image).hexdigest()
    nt = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, nt + 6)[0])]
    spans = 0
    size_sum = 0
    functions = {}
    hashes = {}
    for path in sorted((HERE / '证据').glob('cursor_*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        if 'functions' not in data:
            continue
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert data['disk_sha256'] == fingerprint
        items = list(data['thunks'])
        for f in data['functions']:
            functions.setdefault(f['va'], f)
            items.extend(f['byte_ranges'])
            items.extend(f['chunk_byte_ranges'])
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in f['declared_chunks']}
            chunks = {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in f['chunk_byte_ranges']}
            assert chunks == declared, f['va']
        for span in items:
            address = int(span['va'], 16)
            count = span['size']
            mapped = [(rva, off) for _, rva, raw, off in sections
                      if base + rva <= address and address + count <= base + rva + raw]
            assert len(mapped) == 1, hex(address)
            rva, off = mapped[0]
            disk = image[off + address - base - rva:off + address - base - rva + count]
            assert disk.hex() == span['disk_hex'] == span['idb_hex'], hex(address)
            spans += 1
            size_sum += count
    manifest = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert manifest['disk_sha256'] == fingerprint
    assert {r['va'] for r in manifest['functions']} == set(functions)
    assert all(r['status'] and r['conclusion'] and r['unknown'] and r['evidence'] for r in manifest['functions'])
    # 把合成样本绑定回已核原指令，防止仅测试自行编写的格式模型。
    def asm(address):
        return '\n'.join(i['text'] for i in functions[address]['assembly'])
    assert 'push    10A1D85Fh' in asm('0x867cd0')
    assert 'push    12Bh' in asm('0x87ca90')
    assert 'push    4; Size' in asm('0x868530')
    assert 'push    8; Size' in asm('0x87d000')
    assert 'mov     ax, [eax]' in asm('0x893170')
    reader = functions['0x87d060']
    load_index = next(n for n, i in enumerate(reader['assembly']) if 'mov     eax, [eax]' in i['text'])
    advance_site = next(c['site'] for c in reader['calls'] if c['implementation'] == '0x87d0d0')
    assert int(reader['assembly'][load_index]['va'], 16) < int(advance_site, 16)
    for path in HERE.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'))
    for path in HERE.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    # 样本是独立按已证契约构造，不冒充真实抓包或资源文件。
    payload = bytes.fromhex('44332211')
    packet = struct.pack('<III', 0x10A1D85F, 107, len(payload) + 8) + payload
    assert packet.hex() == '5fd8a1106b0000000c00000044332211'
    assert struct.unpack_from('<I', packet, 12)[0] == 0x11223344
    game = struct.pack('<II', 299, len(payload) + 8) + payload
    assert game.hex() == '2b0100000c00000044332211'
    assert struct.pack('<d', 1.5).hex() == '000000000000f83f'
    assert struct.unpack('<H', bytes.fromhex('3412'))[0] == 0x1234
    assert struct.unpack('<Q', bytes.fromhex('8877665544332211'))[0] == 0x1122334455667788
    # 定长字符串先复制再相对推进：若len+1超过width，delta为负而非截断。
    assert 100 + 8 + (4 - 8) == 104
    assert 4 - 8 < 0
    result = dict(pe_sha256=fingerprint, functions=len(functions), span_records=spans,
                  bytes_including_repeats=size_sum, byte_mismatches=0,
                  reviewed=sum(r['status'] == '静态契约已审阅' for r in manifest['functions']),
                  partially_reviewed=sum(r['status'] == '局部消费契约已审阅' for r in manifest['functions']),
                  exported_only=sum(r['status'] == '邻近候选仅导出' for r in manifest['functions']),
                  synthetic_samples=dict(lobby_header=packet.hex(), game_header=game.hex(),
                                         width_samples='WORD/DWORD/QWORD/double 小端样本通过',
                                         note='仅离线模型；不证明客户端实机执行或任意输入安全'),
                  source_hashes=hashes)
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
