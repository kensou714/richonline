"""离线检查当前 PE、保存原证、逐函数状态与中文注释式正文。"""
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def validate():
    source = HERE / 'width_position.json'
    data = json.loads(source.read_text(encoding='utf-8-sig'))
    blob = Path(data['input']).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == data['disk_sha256'] == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + 40 * n + 8)
                for n in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(ea, size):
        choices = [(rva, offset) for _, rva, raw, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(choices) == 1
        rva, offset = choices[0]
        pos = offset + ea - base - rva
        return blob[pos:pos + size]

    ranges, comparisons = {}, 0

    def check(row):
        nonlocal comparisons
        ea, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['ida_hex'])
        assert int(row['end'], 16) == ea + size
        assert len(raw) == size and raw == bytes.fromhex(row['disk_hex']) == disk(ea, size)
        assert row['equal'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        assert (ea, size) not in ranges or ranges[ea, size] == raw
        ranges[ea, size] = raw
        comparisons += 1
        return raw

    thunks = {}
    for row in data['thunks']:
        ea, raw = int(row['va'], 16), check(row)
        assert ea not in thunks and len(raw) == 5 and raw[0] == 0xE9
        thunks[ea] = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert thunks[ea] == int(row['target'], 16)

    def resolve(ea):
        seen = set()
        while ea in thunks:
            assert ea not in seen
            seen.add(ea)
            ea = thunks[ea]
        return ea

    instruction_count = near_count = indirect_count = 0
    functions = {f['va']: f for f in data['functions']}
    assert len(functions) == len(data['functions'])
    for f in functions.values():
        chunks = {int(c['va'], 16): check(c) for c in f['chunks']}
        assert int(f['va'], 16) in chunks
        ins = {int(i['va'], 16): bytes.fromhex(i['hex']) for i in f['instructions']}
        assert len(ins) == len(f['instructions'])
        for i in f['instructions']:
            ea, raw = int(i['va'], 16), bytes.fromhex(i['hex'])
            assert len(raw) == i['size'] > 0 and raw == disk(ea, len(raw))
            assert any(start <= ea and ea + len(raw) <= start + len(content)
                       for start, content in chunks.items())
        # 当前12入口的声明块全部是连续指令；不把漏导的指令留成未经解释的空洞。
        for start, content in chunks.items():
            position = start
            while position < start + len(content):
                assert position in ins, ('缺少代码头', hex(position))
                position += len(ins[position])
            assert position == start + len(content)
        edges = set()
        for ea, raw in ins.items():
            if raw[0] in (0xE8, 0xE9, 0xEB):
                width = 2 if raw[0] == 0xEB else 5
                assert len(raw) == width
                target = ea + width + struct.unpack_from('<b' if width == 2 else '<i', raw, 1)[0]
                edges.add((ea, target, resolve(target)))
        assert edges == {(int(c['site'], 16), int(c['target'], 16), int(c['resolved'], 16)) for c in f['calls']}
        assert len(edges) == len(f['calls'])
        raw_indirect = set()
        for ea, raw in ins.items():
            if raw[0] == 0xFF and len(raw) > 1 and ((raw[1] >> 3) & 7) in (2, 3, 4, 5):
                raw_indirect.add(ea)
        assert raw_indirect == {int(row['site'], 16) for row in f['indirect']}
        for row in f['indirect']:
            assert int(row['site'], 16) in ins
        instruction_count += len(ins)
        near_count += len(edges)
        indirect_count += len(f['indirect'])
    nav_count = 0
    for row in data['caller_navigation']:
        assert row['incoming'] in data['incoming']
        raw = check(row['window'])
        start = int(row['window']['va'], 16)
        for i in row['instructions']:
            offset = int(i['va'], 16) - start
            assert 0 <= offset and offset + i['size'] <= len(raw)
            assert raw[offset:offset + i['size']].hex() == i['hex']
        site = int(row['incoming']['site'], 16)
        entry = int(row['incoming']['entry'], 16)
        branch = disk(site, 5)
        assert branch[0] in (0xE8, 0xE9) and site + 5 + struct.unpack_from('<i', branch, 1)[0] == entry
        assert resolve(entry) == int(data['main'], 16)
        nav_count += 1
    assert nav_count == sum(bool(r['iscode'] and r['caller']) for r in data['incoming'])
    assert {int(r['site'], 16) for r in data['incoming'] if r['caller'] == '0x90ce80'} == {0x90CF25, 0x90CFEB, 0x90D03E}
    assert len({r['caller'] for r in data['incoming'] if r['caller'] != '0x90ce80'}) == 17
    critical = {
        0x90CE8B: '894c2414', 0x90CEB2: '8a5528', 0x90CED9: '8a1437',
        0x90CEE0: '7f27', 0x90CEE4: '84c0', 0x90CF38: '8d4601',
        0x90CF5F: '8b5004', 0x90CF66: '7f67', 0x90CF6A: '8a4c242c',
        0x90D013: '8b442418', 0x90CF91: '8a16', 0x90D066: '8d440701',
        0x90CF11: '8917', 0x90CFD7: '8902', 0x90D026: '8902',
        0x90CF20: '8b4c2420', 0x90CFE6: '8b4c2420', 0x90D039: '8b4c2420',
        0x90CF1A: '8d442414', 0x90CFDF: '8d542410', 0x90D02E: '8d542410',
        0x90CF06: 'c21000', 0x90D081: 'c70000000000',
        0x90D164: '8b7104', 0x90D183: '8a140e', 0x90D1B7: 'c20800',
        0x90D349: '8a44241c', 0x90D3DB: '03d8', 0x90D3F1: '8b01',
        0x90D415: 'c20c00', 0x8E0A08: '8b8828510000', 0x8E0A63: '7d10',
        0x8E0A71: 'b001', 0x8E0A77: '32c0',
    }
    for ea, expected in critical.items():
        assert disk(ea, len(bytes.fromhex(expected))).hex() == expected, hex(ea)
    review = json.loads((HERE / 'function_review.json').read_text(encoding='utf-8-sig'))
    assert set(review) == set(functions)
    for row in review.values():
        assert row['status'] in ('静态契约已审阅', '复用已有语义', '局部已审阅', '导航已建立')
        assert row['conclusion'] and row['boundary']
        if row.get('reuse_reference'):
            assert (HERE.parent.parent / row['reuse_reference'].split('/functions/')[0]).is_file()
    docs = sorted(HERE.parent.glob('*.txt'))
    assert len(docs) >= 4
    for path in docs:
        lines = path.read_text(encoding='utf-8-sig').splitlines()
        assert all(not line or line.startswith('//') for line in lines)
        assert all(line == line.rstrip() for line in lines)
        assert not any(re.match(r'//\s*(?:#{1,6}\s|```|[-*+]\s|\|)', line) for line in lines)
    model = json.loads((HERE / 'model_result.json').read_text(encoding='utf-8-sig'))
    assert model['failures'] == 0
    merged = []
    for start, size in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], start + size)
        else:
            merged.append([start, start + size])
    result = dict(status='PASS', source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  exe_sha256=SHA, idb_input_sha256=data['idb_input_sha256'], whole_idb_identity_claimed=False,
                  functions=len(functions), instruction_entries=instruction_count,
                  near_transfer_edges=near_count, indirect_transfer_sites=indirect_count,
                  thunks=len(thunks), incoming=len(data['incoming']), navigation_windows=nav_count,
                  byte_comparisons=comparisons, unique_ranges=len(ranges),
                  union_bytes=sum(end - start for start, end in merged),
                  review_levels=dict(Counter(r['status'] for r in review.values())),
                  documents=len(docs), model=model, scope='静态PE及保存原证校验；不替代完整依赖、实时IDA与游戏验收')
    result['critical_instruction_assertions'] = len(critical)
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=False, indent=2))
