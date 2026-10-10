"""离线核验本专题原证、函数审阅覆盖、注释格式和模型结果。"""
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def validate():
    source = HERE / 'hit_filter.json'
    data = json.loads(source.read_text(encoding='utf-8'))
    image = Path(data['input']).read_bytes()
    assert hashlib.sha256(image).hexdigest() == data['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]
    spans, checks = [], {'byte_comparisons': 0, 'instructions': 0}

    def disk(ea, size):
        candidates = [(rva, off) for _, rva, raw, off in sections
                      if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(candidates) == 1, hex(ea)
        rva, off = candidates[0]
        start = off + ea - base - rva
        return image[start:start + size]

    def check(row):
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['ida_hex'])
        assert len(raw) == size and raw.hex() == row['disk_hex']
        assert raw == disk(va, size) and row['equal'] is True
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        spans.append((va, va + size))
        checks['byte_comparisons'] += 1
        return raw

    fs = data['functions'] + data['contexts']
    assert len({f['va'] for f in fs}) == len(fs)
    assert {f['va'] for f in data['contexts']} == set(data['scope']['selected_callers'])
    assert data['scope']['main'] == '0x64ff10'
    assert {f['va'] for f in data['functions']} == {'0x64ff10'} | set(data['scope']['dependencies'])
    thunks = {}
    for row in data['thunks']:
        raw = check(row)
        ea = int(row['va'], 16)
        assert ea not in thunks and len(raw) == 5 and raw[0] == 0xE9
        assert ea + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
        thunks[ea] = int(row['target'], 16)

    def resolve(ea):
        visited = set()
        while ea in thunks:
            assert ea not in visited
            visited.add(ea)
            ea = thunks[ea]
        return ea

    for f in fs:
        assert all(int(c['end'], 16) == int(c['va'], 16) + c['size'] for c in f['chunks'])
        chunks = [(int(c['va'], 16), check(c)) for c in f['chunks']]
        assert any(start == int(f['va'], 16) for start, _ in chunks)
        addresses = set()
        instruction_bytes = {}
        for ins in f['instructions']:
            ea, raw = int(ins['va'], 16), bytes.fromhex(ins['hex'])
            assert ea not in addresses and len(raw) == ins['size'] > 0
            addresses.add(ea)
            instruction_bytes[ea] = raw
            containing = [(start, content) for start, content in chunks
                          if start <= ea and ea + len(raw) <= start + len(content)]
            assert len(containing) == 1
            start, content = containing[0]
            assert raw == content[ea - start:ea - start + len(raw)]
            checks['instructions'] += 1
        for call in f['calls']:
            assert int(call['site'], 16) in addresses
            assert resolve(int(call['target'], 16)) == int(call['resolved'], 16)
            raw = instruction_bytes[int(call['site'], 16)]
            if raw[0] in (0xE8, 0xE9):
                assert len(raw) == 5
                displacement = struct.unpack_from('<i', raw, 1)[0]
            else:
                assert raw[0] == 0xEB and len(raw) == 2
                displacement = struct.unpack_from('<b', raw, 1)[0]
            assert int(call['site'], 16) + len(raw) + displacement == int(call['target'], 16)
        for row in f['indirect']:
            assert int(row['site'], 16) in addresses

    callers = {f['va']: f for f in fs}
    navigation = data['caller_navigation']
    assert len(navigation) == sum(bool(r['iscode'] and r['caller']) for r in data['incoming'])
    for row in navigation:
        raw = check(row['window'])
        start = int(row['window']['va'], 16)
        assert row['incoming'] in data['incoming']
        assert row['scope'] == '局部调用参数导航，非完整函数审阅'
        assert int(row['incoming']['site'], 16) in {int(i['va'], 16) for i in row['instructions']}
        for ins in row['instructions']:
            offset = int(ins['va'], 16) - start
            assert 0 <= offset and offset + ins['size'] <= len(raw)
            assert raw[offset:offset + ins['size']].hex() == ins['hex']
    for row in data['incoming']:
        if not row['iscode'] or not row['caller']:
            continue
        site = int(row['site'], 16)
        raw = disk(site, 5)
        assert raw[0] in (0xE8, 0xE9)
        assert site + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['entry'], 16)
        assert resolve(int(row['entry'], 16)) == 0x64FF10
        if row['caller'] in callers:
            assert any(c['site'] == row['site'] and c['target'] == row['entry']
                       and c['resolved'] == '0x64ff10' for c in callers[row['caller']]['calls'])
    review = json.loads((HERE / 'function_review.json').read_text(encoding='utf-8'))
    assert set(review) == {f['va'] for f in fs}
    for row in review.values():
        assert row['status'] in ('静态契约已审阅', '复用已有语义', '调用参数局部审阅')
        assert row['conclusion'] and row['boundary']
        if row['status'] == '复用已有语义':
            reference = row['reuse_reference'].split('/functions/')[0]
            assert (HERE.parent.parent / reference).is_file(), reference
    documents = sorted(HERE.parent.glob('*.txt'))
    assert {'00_阅读入口与证据边界.txt', '01_筛选顺序与字段.txt',
            '02_调用参数与命中几何.txt', '03_逐函数审阅.txt'} <= {p.name for p in documents}
    for path in documents:
        lines = path.read_text(encoding='utf-8').splitlines()
        assert all(not line.strip() or line.startswith('//') for line in lines), path.name
        assert all(line == line.rstrip() for line in lines), path.name
        assert not any(re.match(r'//\s*(?:#{1,6}\s|```|[-*+]\s|\|)', line) for line in lines), path.name
    parameter_rows = re.findall(r'^//  ([0-9A-F]{6})\s+([0-9A-F]{6})\s+\(([01]),([01])\)\s+(.+)$',
                                (HERE.parent / '02_调用参数与命中几何.txt').read_text(encoding='utf-8'), re.M)
    assert len(parameter_rows) == len(navigation) == 18
    documented = {int(site, 16): (int(owner, 16), int(a5), int(a6), last)
                  for owner, site, a5, a6, last in parameter_rows}
    flag_cases = []
    for row in navigation:
        site = int(row['incoming']['site'], 16)
        owner, a5, a6, last = documented[site]
        assert owner == int(row['incoming']['caller'], 16)
        before = [i for i in row['instructions'] if int(i['va'], 16) < site]
        candidates = []
        for n in range(len(before) - 5):
            first, second, output = [bytes.fromhex(before[n + k]['hex']) for k in range(3)]
            if (first in (b'\x6a\x00', b'\x6a\x01')
                    and second in (b'\x6a\x00', b'\x6a\x01')
                    and len(output) == 3 and output[0] == 0x8D and output[2] == 0xE8):
                candidates.append(n)
        assert len(candidates) == 1
        n = candidates[0]
        assert bytes.fromhex(before[n]['hex'])[1] == a6
        assert bytes.fromhex(before[n + 1]['hex'])[1] == a5
        last_load = bytes.fromhex(before[n + 4]['hex'])
        if site == 0x65862F:
            assert last_load == b'\x68\x54\x77\xa7\x00' and 'A77754' in last
        else:
            assert len(last_load) == 3 and last_load[0] == 0x8D and last_load[2] == 0xD8
            assert last == 'ebp-28'
        flag_cases.append(dict(site=hex(site), owner=hex(owner), a5=a5, a6=a6))
    model = json.loads((HERE / 'model_result.json').read_text(encoding='utf-8'))
    assert model['failures'] == 0 and model['scope'] == '静态契约模型，非机器码执行或实机'
    merged = []
    for start, end in sorted(set(spans)):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    report = dict(status='PASS', source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  disk_sha256=data['disk_sha256'], idb_input_sha256=data['idb_input_sha256'],
                  whole_idb_identity_claimed=False, functions=len(data['functions']),
                  contexts=len(data['contexts']), thunks=len(thunks), counts=checks,
                  incoming=len(data['incoming']), navigation_windows=len(navigation),
                  documented_call_parameters=flag_cases,
                  unique_spans=len(set(spans)), unique_byte_coverage=sum(b - a for a, b in merged),
                  model=model, scope='PE局部原证、引用及文档校验；非全IDB身份或游戏验证')
    (HERE / 'validation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n',
                                        encoding='utf-8', newline='\n')
    return report


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=False, indent=2))
