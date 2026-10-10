"""离线复核 TeachMode 元数据原证、调用归属及当前资源。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
RAW = HERE / 'boss_metadata_raw.json'
STARTUP = ROOT / 'docs/逆向资料/专题/神明附身与元数据/证据/metadata.json'
RESOURCE = ROOT / 'Data/TeachMode.kpd'
PE = ROOT / 'RnClient.exe'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pe_reader(image):
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(ea, size):
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    return read


def decode_kpd(source):
    assert len(source) >= 9
    key = source[0]
    raw_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in source[1:9]))
    assert 0 < raw_size <= 64 * 1024 * 1024 and 0 < packed_size <= len(source) - 9
    decoded = lzokay.decompress(bytes((b - key) & 255 for b in source[9:9 + packed_size]), raw_size)
    assert len(decoded) == raw_size
    return decoded, dict(size=len(source), sha256=digest(source), key=key,
                         raw_size=raw_size, packed_size=packed_size,
                         decoded_sha256=digest(decoded), tail_size=len(source) - 9 - packed_size)


def records(text):
    result = []
    current = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = dict(section=line[1:-1], line=line_number, fields={})
            result.append(current)
        elif current is not None and '=' in line and not line.startswith('//'):
            key, value = line.split('=', 1)
            current['fields'][key.strip()] = value.strip()
    return result


def main():
    raw = json.loads(RAW.read_text(encoding='utf-8'))
    image = PE.read_bytes()
    assert digest(image) == raw['disk_sha256']
    read = pe_reader(image)
    functions = {f['va']: f for f in raw['functions']}
    assert set(functions) == {'0x810360', '0x8103b0', '0x810d20'}
    for function in functions.values():
        assert function['pseudocode_error'] is None
        for chunk in function['chunks']:
            data = read(int(chunk['va'], 16), chunk['size'])
            assert chunk['equal'] and data.hex() == chunk['disk_hex'] == chunk['idb_hex']
            assert digest(data) == chunk['sha256']
        for row in function['instructions']:
            assert read(int(row['va'], 16), row['size']).hex() == row['hex']

    parser = functions['0x8103b0']
    assert parser['end_va'] == '0x810cdb' and len(parser['instructions']) == 568
    pseudo = '\n'.join(parser['pseudocode'])
    assert '368 * *v33' in pseudo and 'a2: 0x170u' in pseudo
    assert 'while ( sub_608335(Str2: (char *)off_A2E874) != 0 )' in pseudo
    assert 'while ( sub_608335(Str2: (char *)off_A2E878) != 0 )' in pseudo
    assert '*(_DWORD *)(v33[1] + 368 * v31 + 4 * i + 336) = v23;' in pseudo
    assert 'return 1;' in pseudo and 'return 0;' in pseudo
    assert any(x['target'] == '0x609528' for x in parser['outgoing'])
    assert any(x['target'] == '0x60fde2' for x in parser['outgoing'])

    startup = json.loads(STARTUP.read_text(encoding='utf-8'))
    assert startup['disk_sha256'] == raw['disk_sha256']
    loader = next(f for f in startup['functions'] if f['va'] == '0x623ee0')
    loader_text = '\n'.join(loader['pseudocode'])
    assert 'sub_609992(this: v8, FileName: "Data\\\\TeachMode.kpd")' in loader_text
    assert any(row['va'] == '0x623fff' and 'call' in row['text'] and 'sub_609992' in row['text']
               for row in loader['assembly'])
    assert any(x['site'] == '0x623fff' and x['implementation'] == '0x8103b0'
               for x in loader['calls'])
    assert read(0x609992, 5).hex() == 'e9196a2000'

    selectors = {}
    for address in (0xA2E874, 0xA2E878):
        value = read(address, 32).split(b'\0', 1)[0]
        selectors[hex(address)] = dict(raw_hex=value.hex(),
                                       ascii=value.decode('ascii'))

    source = RESOURCE.read_bytes()
    decoded, resource = decode_kpd(source)
    text = decoded.decode('latin1')
    resource['encoding'] = 'latin1 字节保真解析 ASCII 键；未判定非 ASCII 名称的客户端编码'
    sections = records(text)
    resource['section_counts'] = {section: sum(r['section'] == section for r in sections)
                                  for section in sorted({r['section'] for r in sections})}
    resource['records'] = [dict(line=r['line'], section=r['section'],
                                fields={key: r['fields'].get(key) for key in
                                        ('indx', 'mapName', 'bossRole', 'bossMood',
                                         'firstExp', 'firstGold', 'againExp', 'againGold',
                                         'firstPropNum', 'firstProp')},
                                bossName_raw_hex=r['fields'].get('bossName', '').encode('latin1').hex())
                           for r in sections]
    result = dict(schema=1, scope='只读离线核验；不模拟运行客户端或异常配置',
                  pe_sha256=raw['disk_sha256'], idb_input_sha256=raw['idb_input_sha256'],
                  function_counts={va: len(f['instructions']) for va, f in functions.items()},
                  startup_call=dict(owner='0x623ee0', site='0x623fff', thunk='0x609992',
                                    implementation='0x8103b0', argument='Data\\TeachMode.kpd'),
                  section_selectors=selectors,
                  resource=resource, checks='pass')
    (HERE / 'teachmode_offline_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(checks='pass', functions=result['function_counts'],
                          resource_sections=resource['section_counts']), ensure_ascii=False))


if __name__ == '__main__':
    main()
