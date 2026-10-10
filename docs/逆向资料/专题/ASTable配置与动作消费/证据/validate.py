"""作者离线核验：当前PE、指令边界、原证引用和ASTable精确资源。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import re
import struct
import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    assert blob[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    assert struct.unpack_from('<H', blob, opt)[0] == 0x10b
    base = struct.unpack_from('<I', blob, opt + 28)[0]
    section_at = opt + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, section_at + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(va, count):
        choices = [(rva, offset) for _, rva, raw, offset in sections
                   if base + rva <= va and va + count <= base + rva + raw]
        assert len(choices) == 1, hex(va)
        rva, offset = choices[0]
        at = offset + va - base - rva
        return blob[at:at + count]

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ranges = []
    digest = {}
    count = 0
    transcripts = []

    def compare(value):
        nonlocal count
        if isinstance(value, dict):
            if all(key in value for key in ('va', 'size', 'disk_hex')) and value['disk_hex'] is not None:
                current = disk(int(value['va'], 16), value['size'])
                assert current.hex() == value['disk_hex'].lower(), value['va']
                if 'idb_hex' in value:
                    assert value['matching'] and value['idb_hex'].lower() == current.hex(), value['va']
                count += 1
            for child in value.values():
                compare(child)
        elif isinstance(value, list):
            for child in value:
                compare(child)

    for name in ('functions_raw.json', 'navigation_raw.json', 'closure_raw.json', 'closure_navigation.json', 'lifetime_raw.json', 'fields_raw.json', 'fields_reused.json'):
        source = (HERE / name).read_bytes()
        digest[name] = hashlib.sha256(source).hexdigest()
        data = json.loads(source)
        assert data['disk_sha256'] == SHA
        if 'source' in data:
            assert hashlib.sha256((ROOT / data['source']).read_bytes()).hexdigest() == data['source_sha256']
        compare(data)
        for function in data.get('functions', []):
            ranges.append(dict(va=function['va'], chunks=len(function['chunk_byte_ranges']),
                               instructions=len(function['assembly'])))
            transcripts.append('// 函数 ' + function['va'])
            for item in function['assembly']:
                address = int(item['va'], 16)
                ins = next(decoder.disasm(disk(address, 16), address, count=1))
                transcripts.append('// %08X %s %s' % (address, ins.mnemonic, ins.op_str))
        for window in data.get('windows', []):
            transcripts.append('// 窗口 ' + window['start_va'])
            for item in window['assembly']:
                address = int(item['va'], 16)
                ins = next(decoder.disasm(disk(address, 16), address, count=1))
                assert ins.size == item['bytes']['size']
                transcripts.append('// %08X %s %s' % (address, ins.mnemonic, ins.op_str))
    consumer = json.loads((HERE / 'consumer_reused.json').read_text('utf-8'))
    source = (ROOT / consumer['source']).read_bytes()
    assert hashlib.sha256(source).hexdigest() == consumer['source_sha256']
    old = next(item for item in json.loads(source)['functions'] if item['address'] == consumer['function'])
    for chunk in old['chunks']:
        current = disk(int(chunk['start'], 16), len(bytes.fromhex(chunk['bytes_hex'])))
        assert current.hex() == chunk['bytes_hex'].lower()
        assert hashlib.sha256(current).hexdigest() == chunk['sha256'].lower()
    compare(consumer)
    assert consumer['assembly'][0]['va'] == '0x642921'
    transcripts.append('// 消费者局部 0x642740')
    transcripts.extend('// ' + item['va'] + ' ' + item['text'] for item in consumer['assembly'])

    size_source_path = ROOT / 'docs/逆向资料/专题/角色与精灵动画/证据/动画管理与骰子_IDA原始导出.json'
    size_source = size_source_path.read_bytes()
    size_function = next(item for item in json.loads(size_source)['functions'] if int(item['address'], 16) == 0x63F870)
    transcripts.append('// 历史复用 0x63F870')
    for chunk in size_function['chunks']:
        current = disk(int(chunk['start'], 16), len(bytes.fromhex(chunk['bytes_hex'])))
        assert current.hex() == chunk['bytes_hex'].lower()
        assert hashlib.sha256(current).hexdigest() == chunk['sha256'].lower()
        for ins in decoder.disasm(current, int(chunk['start'], 16)):
            transcripts.append('// %08X %s %s' % (ins.address, ins.mnemonic, ins.op_str))
    size_reuse = dict(source=str(size_source_path.relative_to(ROOT)).replace('\\', '/'),
                      source_sha256=hashlib.sha256(size_source).hexdigest(), function='0x63f870',
                      chunks=size_function['chunks'], scope='既有DWORD序列计数契约复用；当前磁盘全部块核验')
    (HERE / 'size_reused.json').write_text(json.dumps(size_reuse, ensure_ascii=False, indent=2) + '\n', 'utf-8')

    resource = json.loads((HERE / 'resource.json').read_text('utf-8'))
    source = (ROOT / resource['source']).read_bytes()
    assert hashlib.sha256(source).hexdigest() == resource['source_sha256']
    plain = (HERE / 'ASTable.kpd.decoded.bin').read_bytes()
    assert hashlib.sha256(plain).hexdigest() == resource['decoded_sha256']
    stats = {}
    for heading, prefix, expected in (('DICE', 'dice', 28), ('MOVE', 'move', 9), ('BACK', 'back', 100), ('DENG', 'deng', 1)):
        groups = [group for group in resource['sections'] if re.fullmatch(prefix + r'\d+', group['name'])]
        header = next(group for group in resource['sections'] if group['name'] == heading)
        assert int(header['fields']['num']) == len(groups) == expected
        assert [group['name'] for group in groups] == [prefix + str(i) for i in range(expected)]
        props = [int(group['fields']['prop']) for group in groups]
        values = [value for group in groups for key, value in group['fields'].items() if key != 'prop']
        stats[heading] = dict(count=len(groups), props=props,
                              duplicate_props=[key for key, number in Counter(props).items() if number > 1],
                              max_field_bytes=max(group['field_byte_lengths'][key] for group in groups for key in group['fields']),
                              null_values=sum(value == 'NULL' for value in values))
        if heading == 'DICE':
            comm_counts = []
            for group in groups:
                comm = [key for key in group['fields'] if key.startswith('comm')]
                assert comm == ['comm' + str(i) for i in range(len(comm))]
                comm_counts.append(len(comm))
            stats[heading]['comm_counts'] = comm_counts
    duplicates = []
    current = None
    seen = set()
    for number, line in enumerate(plain.decode('latin1').splitlines(), 1):
        if line.strip().startswith('['):
            current = line.strip()
            seen = set()
        elif '=' in line and not line.strip().startswith('//'):
            key = line.split('=', 1)[0].strip()
            if key in seen:
                duplicates.append(dict(section=current, line=number, key=key))
            seen.add(key)
    assert not duplicates
    (HERE / 'resource_stats.json').write_text(json.dumps(stats, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'review_assembly.txt').write_text('\n'.join(transcripts) + '\n', 'utf-8')
    manifest_path = HERE.parent / '函数审阅清单.json'
    status = 'EVIDENCE_ONLY'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text('utf-8'))
        assert len({item['va'] for item in manifest['functions']}) == len(manifest['functions'])
        assert {item['va'] for item in ranges} <= {item['va'] for item in manifest['functions']}
        for item in manifest['functions']:
            assert item['status'] and item['conclusion'] and item['unknown']
            assert all((HERE.parent / path).is_file() for path in item['evidence'])
        status = 'PASS'
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines()), str(path)
    result = dict(status=status, disk_sha256=SHA, evidence_sha256=digest,
                  checked_byte_records=count, functions=ranges,
                  historical_chunks=len(old['chunks']), historical_instructions=len(consumer['assembly']),
                  size_reuse_source_sha256=size_reuse['source_sha256'],
                  resource_stats='resource_stats.json', exact_duplicate_keys=duplicates,
                  scope='作者离线核验；未启动游戏，未修改PE、IDB或资源')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(status=status, byte_records=count, functions=len(ranges), resource_groups=142)))


if __name__ == '__main__':
    main()
