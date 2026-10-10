"""文本宽度定位专题独审。local()离线只写独审结果；audit(db)供主持IDA租约代跑。"""
from collections import Counter
from pathlib import Path
import hashlib
import itertools
import json
import struct


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = HERE / 'width_position.json'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def evidence():
    data = json.loads(SOURCE.read_text(encoding='utf-8-sig'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == data['disk_sha256'] == EXPECTED_SHA
    pe = struct.unpack_from('<I', image, 0x3c)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10b
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_at = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_at + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def read(ea, size):
        if isinstance(ea, str):
            ea = int(ea, 16)
        offsets = [offset + ea - base - rva for _, rva, raw, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(offsets) == 1, (hex(ea), size)
        return image[offsets[0]:offsets[0] + size]

    return data, read


def model_checks():
    # 独立事件序列：记录每个可消费单元的起点、终点、宽和原子属性。
    def locate(widths, target, flag, nodes=None, depth=0):
        assert depth < 3
        if not widths:
            return 0, 0, depth
        units = []
        if nodes is None:
            units = [(i, i + 1, w, False) for i, w in enumerate(widths)]
        else:
            pos = 0
            for length, width, atomic in nodes:
                if atomic:
                    units.append((pos, pos + length, width, True))
                else:
                    units.extend((i, i + 1, widths[i], False) for i in range(pos, pos + length))
                pos += length
        consumed = 0
        for start, end, width, atomic in units:
            after = consumed + width
            if after > target:
                delta = consumed - target
                if consumed == target:
                    return start, delta, depth
                result, _, inner_depth = locate(widths, consumed, flag, nodes, depth + 1)
                return result, delta, inner_depth
            if after == target and flag & 0xff == 0:
                return start if atomic else end, 0, depth
            consumed = after
        return len(widths), consumed - target, depth

    cases = [
        ((1, 0, 0, 7), 1, 0, None, (1, 0)),
        ((1, 0, 0, 7), 1, 1, None, (3, 0)),
        ((1, 0, 0, 7), 4, 0, None, (1, -3)),
        ((1, 0, 0, 7), 4, 1, None, (3, -3)),
        ((4, 0, 1), 4, 0, [(2, 4, True), (1, 1, False)], (0, 0)),
        ((4, 0, 1), 4, 1, [(2, 4, True), (1, 1, False)], (2, 0)),
        ((4, 0, 7), 5, 0, [(2, 4, True), (1, 7, False)], (0, -1)),
        ((0, 0), -2, 1, None, (2, 2)),
        ((1, 2), 0, 1, [], (2, 0)),
    ]
    for widths, target, flag, nodes, expected in cases:
        assert locate(widths, target, flag, nodes)[:2] == expected
    periodic = 0
    for widths in itertools.product((0, 1, 7), repeat=3):
        for target in range(-2, 12):
            for flag in (-255, -1, 0, 1, 255, 256, 257, 511):
                assert locate(widths, target, flag)[:2] == locate(widths, target, flag & 0xff)[:2]
                periodic += 1

    def next_segment(widths, position, skip, nodes):
        base = 0
        for length, whole_width, atomic in nodes:
            end = base + length
            candidate = position + 1
            if base <= candidate and end > position:
                if whole_width == 0 and skip & 0xff:
                    position += length
                elif atomic:
                    return end
                elif candidate == end and not skip & 0xff:
                    return candidate
                elif candidate < end:
                    while candidate < end and widths[candidate] == 0 and skip & 0xff:
                        candidate += 1
                    if candidate < end:
                        return candidate
            base = end
        return base

    assert next_segment((2, 0, 0, 3), 0, 0, [(4, 5, False)]) == 1
    assert next_segment((2, 0, 0, 3), 0, 1, [(4, 5, False)]) == 3
    assert next_segment((4, 0, 3), 0, 0, [(2, 4, True), (1, 3, False)]) == 2
    assert next_segment((4, 0, 3), 0, 1, [(2, 4, True), (1, 3, False)]) == 2
    assert next_segment((0, 0, 3), -1, 1, [(2, 0, False), (1, 3, False)]) == 2
    return dict(explicit_locate=len(cases), flag_period_samples=periodic,
                segmented_next_cases=5, max_observed_depth=max(locate(c[0], c[1], c[2], c[3])[2] for c in cases),
                scope='独立有限事件模型；未执行EXE，且不覆盖畸形内存、32位溢出或动态字段')


def local():
    data, read = evidence()
    functions = {f['va']: f for f in data['functions']}
    assert len(functions) == 12
    reviewed = json.loads((HERE / 'function_review.json').read_text(encoding='utf-8-sig'))
    statuses = dict(Counter(x['status'] for x in reviewed.values()))
    assert set(reviewed) == set(functions)
    assert statuses == {'静态契约已审阅': 4, '局部已审阅': 3, '复用已有语义': 5}
    assert reviewed['0x924fc0']['status'] == '局部已审阅'
    all_ranges = []
    comparisons = 0
    instruction_count = 0
    for f in functions.values():
        rows = {int(i['va'], 16): i for i in f['instructions']}
        assert len(rows) == len(f['instructions'])
        instruction_count += len(rows)
        for chunk in f['chunks']:
            start, size = int(chunk['va'], 16), chunk['size']
            saved = bytes.fromhex(chunk['ida_hex'])
            assert saved == read(start, size) == bytes.fromhex(chunk['disk_hex'])
            assert chunk['equal'] and len(saved) == size
            assert hashlib.sha256(saved).hexdigest() == chunk['sha256']
            all_ranges.append((start, start + size))
            comparisons += 1
            cursor = start
            while cursor < start + size:
                assert cursor in rows
                ins = rows[cursor]
                assert bytes.fromhex(ins['hex']) == read(cursor, ins['size'])
                cursor += ins['size']
            assert cursor == start + size
    thunks = {}
    for row in data['thunks']:
        va = int(row['va'], 16)
        raw = read(va, row['size'])
        assert raw == bytes.fromhex(row['ida_hex']) == bytes.fromhex(row['disk_hex'])
        assert row['equal'] and len(raw) == 5 and raw[0] == 0xe9
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == int(row['target'], 16)
        thunks[va] = target
        all_ranges.append((va, va + 5))
        comparisons += 1

    def resolve(ea):
        seen = set()
        while ea in thunks:
            assert ea not in seen
            seen.add(ea)
            ea = thunks[ea]
        return ea

    for nav in data['caller_navigation']:
        assert nav['incoming'] in data['incoming']
        row = nav['window']
        start, raw = int(row['va'], 16), bytes.fromhex(row['ida_hex'])
        assert raw == read(start, row['size']) == bytes.fromhex(row['disk_hex']) and row['equal']
        all_ranges.append((start, start + len(raw)))
        comparisons += 1
        for ins in nav['instructions']:
            off = int(ins['va'], 16) - start
            assert raw[off:off + ins['size']] == bytes.fromhex(ins['hex'])
        call = nav['incoming']
        site, entry = int(call['site'], 16), int(call['entry'], 16)
        encoded = read(site, 5)
        assert encoded[0] in (0xe8, 0xe9)
        assert site + 5 + struct.unpack_from('<i', encoded, 1)[0] == entry
        assert resolve(entry) == 0x90ce80
    assert len(data['caller_navigation']) == len(data['incoming']) == 35
    assert len(thunks) == 17 and instruction_count == 996 and comparisons == 64
    assert len({x['caller'] for x in data['incoming'] if x['caller'] != '0x90ce80'}) == 17
    assert {int(x['site'], 16) for x in data['incoming'] if x['caller'] == '0x90ce80'} == {0x90cf25, 0x90cfeb, 0x90d03e}
    merged = []
    for lo, hi in sorted(all_ranges):
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(hi, merged[-1][1])
        else:
            merged.append([lo, hi])
    union = sum(hi - lo for lo, hi in merged)
    assert union == 6630
    key = {
        0x90ce8b: 'mov     [esp+1Ch+var_8], ecx',
        0x90cee0: 'jg      short loc_90CF09',
        0x90cf1a: 'lea     eax, [esp+20h+var_C]',
        0x90cf20: 'mov     ecx, [esp+28h+var_8]',
        0x90cf6a: 'mov     cl, byte ptr [esp+1Ch+arg_C]',
        0x90cfdf: 'lea     edx, [esp+1Ch+var_C]',
        0x90d02e: 'lea     edx, [esp+1Ch+var_C]',
        0x90d310: 'push    ebx',
        0x90d349: 'mov     al, [esp+10h+arg_8]',
        0x90d3db: 'add     ebx, eax',
        0x8fa298: 'jz      short loc_8FA2A9',
        0x8fa2a9: 'push    esi; String',
    }
    asm = {int(i['va'], 16): i['text'] for f in functions.values() for i in f['instructions']}
    assert all(asm[ea] == expected for ea, expected in key.items())
    result = dict(status='PASS', scope='独立PE字节、保存汇编重点复核及有限模型；不替代实机或完整依赖审阅',
                  disk_sha256=EXPECTED_SHA, functions=len(functions), instruction_entries=instruction_count,
                  byte_comparisons=comparisons, union_bytes=union, thunks=len(thunks),
                  incoming=len(data['incoming']), external_incoming=32, recursive_incoming=3,
                  navigation_windows=len(data['caller_navigation']), review_levels=statuses,
                  manual_assembly_anchors=len(key), model=model_checks(), author_artifacts_modified=False)
    (HERE / 'independent_local_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


def audit(db):
    # 当前IDA数据库只读；仅写本专题新增独审结果，由持有lease的主持代理代跑。
    data, read = evidence()
    byte_checks = instruction_checks = 0
    for f in data['functions']:
        start = int(f['va'], 16)
        live = db.functions.get_at(start)
        assert live is not None and live.start_ea == start
        live_chunks = list(db.functions.get_chunks(live))
        assert [(c.start_ea, c.end_ea) for c in live_chunks] == [
            (int(c['va'], 16), int(c['end'], 16)) for c in f['chunks']]
        for chunk in f['chunks']:
            ea, size = int(chunk['va'], 16), chunk['size']
            assert db.bytes.get_bytes_at(ea, size) == read(ea, size) == bytes.fromhex(chunk['ida_hex'])
            byte_checks += 1
        decoded = {hex(i.ea): db.instructions.get_disassembly(i)
                   for c in live_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
        assert decoded == {i['va']: i['text'] for i in f['instructions']}
        instruction_checks += len(decoded)
    for row in data['thunks']:
        ea = int(row['va'], 16)
        assert db.bytes.get_bytes_at(ea, 5) == read(ea, 5)
        byte_checks += 1
    for nav in data['caller_navigation']:
        row = nav['window']
        ea, size = int(row['va'], 16), row['size']
        assert db.bytes.get_bytes_at(ea, size) == read(ea, size)
        byte_checks += 1
    assert byte_checks == 64 and instruction_checks == 996
    result = dict(status='PASS', scope='主持IDA租约代跑只读audit(db)；非独审代理自己的租约',
                  byte_comparisons=byte_checks, instruction_entries=instruction_checks,
                  functions=len(data['functions']), database_mutations=0)
    (HERE / 'independent_live_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(local(), ensure_ascii=False, indent=2))
