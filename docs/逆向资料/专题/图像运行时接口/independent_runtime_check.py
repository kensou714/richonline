"""独立只读核对当前PE、IDA声明块、指令集合及原证，不修改数据库。"""
import hashlib
import itertools
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def run(db):
    import idautils

    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * n + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]
    spans, functions, thunks, hashes = [], {}, {}, {}
    comparisons = instructions = chunks = 0

    def check(span):
        nonlocal comparisons
        va, size = int(span['va'], 16), span['size']
        matches = [(rva, off) for _, rva, raw, off in sections
                   if base + rva <= va and va + size <= base + rva + raw]
        assert len(matches) == 1, span
        rva, off = matches[0]
        offset = off + va - base - rva
        raw = image[offset:offset + size]
        assert raw == db.bytes.get_bytes_at(va, size), hex(va)
        assert raw.hex() == span['idb_hex'], hex(va)
        assert 'disk_hex' not in span or raw.hex() == span['disk_hex'], hex(va)
        if 'target' in span:
            assert size == 5 and raw[0] == 0xE9
            assert va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(span['target'], 16)
            thunks[va] = int(span['target'], 16)
        spans.append((va, va + size))
        comparisons += 1

    for path in sorted((HERE / '证据').glob('*.json')):
        if path.name.startswith('独审'):
            continue
        data = json.loads(path.read_text(encoding='utf-8'))
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if isinstance(data, list):
            if path.name == 'matrix_slots.json':
                for row in data:
                    check(row)
                    assert int.from_bytes(bytes.fromhex(row['idb_hex']), 'little') == int(row['value'], 16)
            continue
        assert data['disk_sha256'] == hashlib.sha256(image).hexdigest()
        for f in data.get('functions', []):
            va = int(f['va'], 16)
            actual = db.functions.get_at(va)
            assert actual and actual.start_ea == va, hex(va)
            declared = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in f['declared_chunks']}
            domain = {(c.start_ea, c.end_ea) for c in db.functions.get_chunks(actual)}
            classic = set(idautils.Chunks(va))
            recorded = {(int(c['va'], 16), int(c['va'], 16) + c['size']) for c in f['chunk_byte_ranges']}
            assert declared == domain == classic == recorded, hex(va)
            addresses = {i.ea for start, end in domain for i in db.instructions.get_between(start, end)}
            assert addresses == {int(i['va'], 16) for i in f['assembly']}, hex(va)
            if va not in functions:
                functions[va] = f
                chunks += len(domain)
                instructions += len(addresses)
            else:
                assert functions[va]['chunk_byte_ranges'] == f['chunk_byte_ranges'], hex(va)
            for row in f['byte_ranges'] + f['chunk_byte_ranges']:
                check(row)
        for row in data.get('thunks', []):
            check(row)

    manifest = json.loads((HERE / '函数审阅清单.json').read_text(encoding='utf-8'))
    assert set(functions) == {int(f['va'], 16) for f in manifest['functions']}
    prefix_strings = []
    sites = [i for i in functions[0x6DAA10]['assembly'] if 'push    offset' in i['text']]
    prefixes = ('road', 'thing', 'event', 'build', 'vehicle', 'role',
                'npc', 'fx', 'mood', 'card', 'other', 'extend')
    assert len(sites) == len(prefixes)
    for site, prefix in zip(sites, prefixes):
        instruction = db.bytes.get_bytes_at(int(site['va'], 16), 5)
        assert instruction[0] == 0x68
        target = int.from_bytes(instruction[1:], 'little')
        expected = prefix.encode('ascii') + b'\0'
        mapped = [(rva, off) for _, rva, raw, off in sections
                  if base + rva <= target and target + len(expected) <= base + rva + raw]
        assert len(mapped) == 1
        rva, off = mapped[0]
        offset = off + target - base - rva
        assert image[offset:offset + len(expected)] == expected == db.bytes.get_bytes_at(target, len(expected))
        prefix_strings.append(dict(site=site['va'], va=hex(target), size=len(expected),
                                   disk_hex=expected.hex(), value=prefix))
    merged = []
    for start, end in sorted(set(spans)):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    # 用枚举后的合格槽集合验证选择结果；不把这些模型样本称为机器码执行。
    cache_cases = 0
    choices = list(itertools.product((False, True), (0, 1, 0xFFFFFFFE, 0xFFFFFFFF), (0, 1)))
    for slots in itertools.product(choices, repeat=3):
        qualified = [index for index, (loaded, count, state) in enumerate(slots)
                     if loaded and count != 0xFFFFFFFF and not state]
        expected = max(qualified, default=0)
        candidate = 0
        for index, (loaded, count, state) in enumerate(slots):
            if loaded and count < 0xFFFFFFFF and state == 0:
                candidate = index
        assert candidate == expected
        cache_cases += 1
    result = dict(execution_source='独审代理自身IDA租约执行；只读数据库',
                  disk_sha256=hashlib.sha256(image).hexdigest(),
                  pe_sha256=hashlib.sha256(image).hexdigest(),
                  function_entries=len(functions), declared_chunks=chunks, instructions=instructions,
                  comparisons=comparisons, unique_spans=len(set(spans)), attached_e9_thunks=len(thunks),
                  unique_e9_entries=len(set(thunks) | {va for va, f in functions.items()
                      if len(f['chunk_byte_ranges']) == 1 and f['chunk_byte_ranges'][0]['size'] == 5
                      and bytes.fromhex(f['chunk_byte_ranges'][0]['idb_hex'])[0] == 0xE9}),
                  unique_byte_coverage=sum(end - start for start, end in merged),
                  additional_prefix_strings=prefix_strings,
                  status_counts={status: sum(f['status'] == status for f in manifest['functions'])
                                 for status in sorted({f['status'] for f in manifest['functions']})},
                  cache_model_cases=cache_cases, failures=0, source_hashes=hashes,
                  limitation='模型样本不是机器码仿真或实机；矩阵填表算法、线程和设备故障未执行。')
    (HERE / '证据/独审完整性.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                      encoding='utf-8', newline='\n')
    return result
