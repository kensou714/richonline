"""离线核对当前 PE/KoNpc，复用来源原证并只写本专题。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    digest = sha(image)
    assert digest == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    pe = struct.unpack_from('<I', image, 0x3c)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(ea, size):
        mapping = [(rva, offset) for _, rva, raw_size, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(mapping) == 1, hex(ea)
        rva, offset = mapping[0]
        start = offset + ea - base - rva
        return image[start:start + size]

    reused = []
    for name, addresses in [('functions_raw.json', {'0x806a30'}),
                            ('accessors_raw.json', {'0x8073c0', '0x807440', '0x8074c0', '0x8074f0', '0x807750'})]:
        content = (SOURCE / name).read_bytes()
        raw = json.loads(content)
        functions = [f for f in raw['functions'] if f['va'] in addresses]
        assert {f['va'] for f in functions} == addresses
        bridges = {va for f in functions for call in f['calls'] for va in call['thunks']}
        output = dict(disk_sha256=raw['disk_sha256'], source='../地图建筑等级配置/证据/' + name,
                      source_sha256=sha(content), scope='原证逐字段摘取，无反编译或语义重写',
                      functions=functions, thunks=[b for b in raw['thunks'] if b['va'] in bridges])
        target = 'reused_' + name
        save(target, output)
        reused.append(target)

    keys = []
    for slot in (0xA2E5F8, 0xA2E650, 0xA2E688):
        # 原证汇编均为 push offset；IDA 的 off_ 名称不代表这里有指针解引用。
        target = slot
        value = bytearray()
        for i in range(128):
            byte = disk(target + i, 1)[0]
            value.append(byte)
            if byte == 0:
                break
        assert value[-1] == 0
        keys.append(dict(slot=hex(slot), slot_hex=disk(slot, 4).hex(), target=hex(target),
                         interpretation='inline C string; push offset in assembly',
                         raw_hex=value.hex(), ascii=value[:-1].decode('ascii')))
    save('npc_key_pointers.json', dict(disk_sha256=digest, records=keys))

    blob = (ROOT / 'Data/KoNpc.kpd').read_bytes()
    key = blob[0]
    decoded_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in blob[1:9]))
    assert packed_size == len(blob) - 9
    decoded = lzokay.decompress(bytes((b - key) & 255 for b in blob[9:]), decoded_size)
    assert len(decoded) == decoded_size
    records = []
    for number, original in enumerate(decoded.splitlines(), 1):
        line = original.strip()
        if not line or line.startswith((b';', b'#', b'//')):
            continue
        if line.startswith(b'[') and line.endswith(b']'):
            records.append(dict(section=line[1:-1].decode('ascii'), line=number, fields={}, field_hex={}))
        elif records and b'=' in line:
            name, value = line.split(b'=', 1)
            name, value = name.strip().decode('ascii'), value.strip()
            assert name not in records[-1]['fields']
            records[-1]['fields'][name] = value.decode('latin1')
            records[-1]['field_hex'][name] = value.hex()
    assert len(records) == 8
    assert [int(r['fields']['indx']) for r in records] == list(range(8))
    for record in records:
        fields = record['fields']
        count = int(fields['tile'])
        assert set(k for k in fields if k.startswith('effect')) == {f'effect{i}' for i in range(count)}
        assert len(bytes.fromhex(record['field_hex']['name'])) < 128
        assert len(bytes.fromhex(record['field_hex']['speak'])) < 128
    previous = json.loads((SOURCE / 'resources.json').read_text('utf-8'))
    previous = next(r for r in previous['records'] if r['source'] == 'Data/KoNpc.kpd')
    assert previous['sha256'] == sha(blob) and previous['decoded_sha256'] == sha(decoded)
    save('npc_resources.json', dict(source='Data/KoNpc.kpd', size=len(blob), sha256=sha(blob),
                                   key=key, packed_size=packed_size, decoded_size=len(decoded),
                                   decoded_sha256=sha(decoded), decoded_hex=decoded.hex(),
                                   text_policy='Latin-1逐字节映射与原始hex；不推定客户端运行时ACP', records=records))

    checked, names, count = 0, reused + ['npc_methods_raw.json', 'npc_consumers_raw.json', 'npc_dependencies_raw.json', 'npc_supplement_raw.json'], 0
    audits, missing = [], []
    for name in names:
        file = HERE / name
        if not file.exists():
            missing.append(name)
            continue
        raw = json.loads(file.read_text('utf-8'))
        assert raw['disk_sha256'] == digest
        for function in raw['functions']:
            assert function['bytes_match_disk']
            for block in function['byte_ranges'] + function['chunk_byte_ranges']:
                assert disk(int(block['va'], 16), block['size']).hex() == block['idb_hex'] == block['disk_hex']
                assert block['matching']
                checked += 1
            count += 1
        for bridge in raw['thunks']:
            ea = int(bridge['va'], 16)
            value = disk(ea, 5)
            assert value.hex() == bridge['idb_hex'] == bridge['disk_hex']
            assert value[0] == 0xe9 and ea + 5 + struct.unpack_from('<i', value, 1)[0] == int(bridge['target'], 16)
            checked += 1
        audits.append(dict(file=name, sha256=sha(file.read_bytes()), functions=len(raw['functions'])))
    links = HERE / 'npc_supplement_links.json'
    if links.exists():
        for link in json.loads(links.read_text('utf-8')):
            ea = int(link['bridge'], 16)
            value = disk(ea, 5)
            assert value.hex() == link['bridge_hex']
            assert ea + 5 + struct.unpack_from('<i', value, 1)[0] == int(link['target'], 16)
            checked += 1
    save('npc_validation.json', dict(status='PASS' if not missing else 'PARTIAL', disk_sha256=digest,
                                    scope='离线PE区段映射、IDA指令/声明块与跳板字节、KPD解包、资源字段计数；未运行游戏',
                                    checked_ranges_and_bridges=checked, function_records=count,
                                    evidence=audits, missing=missing, resource_records=len(records),
                                    resource_effect_counts=[int(r['fields']['tile']) for r in records]))
    print(json.dumps(dict(disk_sha256=digest, functions=count, checked=checked,
                          resource_records=len(records), missing=missing), ensure_ascii=False))


if __name__ == '__main__':
    main()
