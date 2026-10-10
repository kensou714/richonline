"""离线核验本专题原证、既有装载原证和当前 TeachMode 资源。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OLD = ROOT / 'docs/逆向资料/专题/BOSS关卡元数据/证据'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    raw = json.loads((HERE / 'teachmode_raw.json').read_text(encoding='utf-8'))
    old = json.loads((OLD / 'boss_metadata_raw.json').read_text(encoding='utf-8'))
    previous = json.loads((OLD / 'teachmode_offline_validation.json').read_text(encoding='utf-8'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert digest(image) == raw['disk_sha256'] == old['disk_sha256'] == previous['pe_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(ea, size):
        matches = [(rva, off) for _, rva, raw_size, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    counts = {'functions': 0, 'chunks': 0, 'instructions': 0, 'globals': 0, 'thunks': 0}
    thunks = set()
    functions = {}
    for row in raw['functions']:
        assert row['va'] not in functions
        functions[row['va']] = row
        counts['functions'] += 1
        for chunk in row['chunks']:
            data = read(int(chunk['va'], 16), chunk['size'])
            assert chunk['equal'] and data.hex() == chunk['idb_hex'] == chunk['disk_hex']
            assert digest(data) == chunk['sha256']
            counts['chunks'] += 1
        for instruction in row['instructions']:
            assert read(int(instruction['va'], 16), instruction['size']).hex() == instruction['hex']
            counts['instructions'] += 1
        for edge in row['outgoing']:
            chain = [int(ea, 16) for ea in edge['chain']]
            for index, ea in enumerate(chain):
                code = read(ea, 5)
                assert code[0] == 0xE9
                target = ea + 5 + struct.unpack_from('<i', code, 1)[0]
                assert target == (chain[index + 1] if index + 1 < len(chain)
                                  else int(edge['implementation'], 16))
                thunks.add(ea)
    bridges = json.loads((HERE / 'bridge_raw.json').read_text(encoding='utf-8'))
    assert bridges['disk_sha256'] == raw['disk_sha256']
    bridge_rows = {int(row['va'], 16): row for row in bridges['bridges']}
    thunks.add(0x5FF852)
    assert len(bridge_rows) == len(bridges['bridges']) and set(bridge_rows) == thunks
    for ea, row in bridge_rows.items():
        code = read(ea, row['size'])
        assert row['size'] == 5 and row['equal'] and code.hex() == row['idb_hex'] == row['disk_hex']
        assert code[0] == 0xE9 and ea + 5 + struct.unpack_from('<i', code, 1)[0] == int(row['target'], 16)
    counts['thunks'] = len(thunks)
    for row in raw['globals']:
        data = read(int(row['va'], 16), row['size'])
        assert data.hex() == row['idb_hex'] == row['disk_hex'] and digest(data) == row['sha256']
        counts['globals'] += 1
    for row in old['functions']:
        if row['va'] in functions:
            assert row['chunks'] == functions[row['va']]['chunks']
    assert read(0x60F3E2, 5) == bytes.fromhex('e9499a0100')
    assert read(0x603FD3, 5) == bytes.fromhex('e948cd2000')
    assert bridge_rows[0x5FF852]['target'] == '0x8102f0'
    source = (ROOT / 'Data/TeachMode.kpd').read_bytes()
    key = source[0]
    raw_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in source[1:9]))
    assert 0 < raw_size <= 64 * 1024 * 1024 and 0 < packed_size <= len(source) - 9
    decoded = lzokay.decompress(bytes((b - key) & 255 for b in source[9:9 + packed_size]), raw_size)
    assert len(decoded) == raw_size
    assert digest(source) == previous['resource']['sha256']
    assert digest(decoded) == previous['resource']['decoded_sha256']
    records, current = [], None
    for line_number, line in enumerate(decoded.splitlines(), 1):
        line = line.strip()
        if line == b'[MAP]':
            current = dict(line=line_number, fields={})
            records.append(current)
        elif current is not None and b'=' in line and not line.startswith(b'//'):
            name, value = line.split(b'=', 1)
            name, value = name.strip().decode('ascii'), value.strip()
            current['fields'][name] = dict(raw_hex=value.hex(),
                                          ascii=value.decode('ascii') if value.isascii() else None)
    assert len(records) == 6
    assert [r['fields']['indx']['ascii'] for r in records] == [str(i) for i in range(6)]
    result = dict(schema=1, checks='pass', scope='离线原字节核验，不运行游戏或模拟配置解析器',
                  pe_sha256=digest(image), idb_input_sha256=raw['idb_input_sha256'], counts=counts,
                  globals=raw['globals'], function_counts={va: len(row['instructions'])
                                                          for va, row in functions.items()},
                  pseudocode_errors={va: row['pseudocode_error'] for va, row in functions.items()
                                     if row['pseudocode_error']},
                  resource=dict(size=len(source), sha256=digest(source), key=key,
                                raw_size=raw_size, packed_size=packed_size,
                                decoded_sha256=digest(decoded), records=records),
                  references=['../BOSS关卡元数据/证据/boss_metadata_raw.json',
                              '../BOSS关卡元数据/证据/teachmode_offline_validation.json'])
    (HERE / 'offline_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)
                                                 + '\n', encoding='utf-8')
    print(json.dumps(dict(checks=result['checks'], counts=counts,
                         pseudocode_errors=result['pseudocode_errors']), ensure_ascii=False))


if __name__ == '__main__':
    main()
