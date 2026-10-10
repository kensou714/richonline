"""独审者只读核对原证、参数与契约模型；仅主入口写独审结果。"""
import hashlib
import itertools
import json
import re
import struct
import types
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/大富翁online/Richonline')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCE_SHA = 'e1f0be9b802ef79e7f71b8e7c22e22b88d4e7b7d81f69bbf18af01d17151c134'
CALL_PARAMETERS = {
    0x6536A1: (0x6535E0, 1, 1), 0x653911: (0x653850, 1, 1),
    0x653B81: (0x653AC0, 1, 1), 0x653DF1: (0x653D30, 0, 1),
    0x654441: (0x654380, 1, 1), 0x654960: (0x654780, 1, 0),
    0x654BD1: (0x654B10, 1, 0), 0x654E81: (0x654DC0, 0, 0),
    0x6550F1: (0x655030, 0, 0), 0x65538A: (0x6552A0, 0, 0),
    0x655631: (0x655570, 0, 0), 0x655B21: (0x655A60, 0, 0),
    0x656F61: (0x656EA0, 0, 0), 0x6574D1: (0x657410, 1, 0),
    0x657741: (0x657680, 1, 1), 0x657BF1: (0x657B30, 1, 1),
    0x65862F: (0x658510, 0, 0), 0x658C91: (0x658BD0, 1, 0),
}


def read(name):
    return json.loads((HERE / name).read_text(encoding='utf-8-sig'))


def audit(db=None):
    """可由主持在已持有的 IDA lease 内调用，不改 EXE、IDB 或作者文件。"""
    source = HERE / 'hit_filter.json'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == SOURCE_SHA
    data = read(source.name)
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert data['input'] == str(ROOT / 'RnClient.exe')
    assert hashlib.sha256(blob).hexdigest() == data['disk_sha256'] == SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = [struct.unpack_from('<4I', blob, pe + 24 + optional_size + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def disk(ea, size):
        candidates = [(rva, off) for _, rva, raw, off in sections
                      if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(candidates) == 1, ('PE 映射', hex(ea), size)
        rva, off = candidates[0]
        pos = off + ea - base - rva
        return blob[pos:pos + size]

    ranges, comparisons = {}, 0

    def check(row):
        nonlocal comparisons
        ea, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['ida_hex'])
        assert len(raw) == size and raw == disk(ea, size) == bytes.fromhex(row['disk_hex'])
        assert row['equal'] is True and hashlib.sha256(raw).hexdigest() == row['sha256']
        assert (ea, size) not in ranges or ranges[(ea, size)] == raw
        if db is not None:
            assert db.bytes.get_bytes_at(ea, size) == raw, ('实时字节', hex(ea))
        ranges[(ea, size)] = raw
        comparisons += 1
        return raw

    thunks = {}
    for row in data['thunks']:
        ea, raw = int(row['va'], 16), check(row)
        assert ea not in thunks and len(raw) == 5 and raw[0] == 0xE9
        target = ea + 5 + struct.unpack_from('<i', raw, 1)[0]
        assert target == int(row['target'], 16)
        thunks[ea] = target

    def resolve(ea):
        visited = set()
        while ea in thunks:
            assert ea not in visited
            visited.add(ea)
            ea = thunks[ea]
        return ea

    functions = {int(f['va'], 16): f for f in data['functions'] + data['contexts']}
    assert len(functions) == len(data['functions']) + len(data['contexts']) == 17
    assert {int(f['va'], 16) for f in data['contexts']} == {0x6535E0, 0x653D30, 0x654780, 0x654DC0}
    assert set(functions) - {int(f['va'], 16) for f in data['contexts']} == {
        0x64FF10, 0x63E000, 0x63E0E0, 0x63E7D0, 0x63E990, 0x63EF50, 0x63EF80,
        0x63EFB0, 0x63F470, 0x63F4A0, 0x7C0C00, 0x7F7400, 0x91F6D0}
    instructions, near_edges, instruction_maps = 0, 0, {}
    for ea, f in functions.items():
        chunks = {}
        for c in f['chunks']:
            start, raw = int(c['va'], 16), check(c)
            assert start not in chunks and int(c['end'], 16) == start + len(raw)
            chunks[start] = raw
        assert ea in chunks
        by_address = {}
        for ins in f['instructions']:
            site, raw = int(ins['va'], 16), bytes.fromhex(ins['hex'])
            assert site not in by_address and len(raw) == ins['size'] > 0
            assert raw == disk(site, len(raw))
            by_address[site] = raw
        # 本输入的块内全部是指令；独立要求逐字节连续，阻止省略一个 code head。
        for start, raw in chunks.items():
            position = start
            while position < start + len(raw):
                assert position in by_address, ('遗漏指令', hex(position))
                piece = by_address[position]
                assert piece == raw[position - start:position - start + len(piece)]
                position += len(piece)
            assert position == start + len(raw)
        assert all(any(start <= site and site + len(raw) <= start + len(content)
                       for start, content in chunks.items()) for site, raw in by_address.items())
        raw_edges = set()
        for site, raw in by_address.items():
            if raw[0] not in (0xE8, 0xE9, 0xEB):
                continue
            width = 2 if raw[0] == 0xEB else 5
            assert len(raw) == width
            delta = struct.unpack_from('<b' if width == 2 else '<i', raw, 1)[0]
            raw_edges.add((site, site + width + delta))
        saved_edges = {(int(c['site'], 16), int(c['target'], 16)) for c in f['calls']}
        assert len(saved_edges) == len(f['calls']) and saved_edges == raw_edges
        assert not f['indirect']
        assert not any(raw[0] == 0xFF and len(raw) > 1 and ((raw[1] >> 3) & 7) in (2, 3, 4, 5)
                       for raw in by_address.values()), ('未记录间接转移', hex(ea))
        for c in f['calls']:
            assert resolve(int(c['target'], 16)) == int(c['resolved'], 16)
        instructions += len(by_address)
        near_edges += len(raw_edges)
        instruction_maps[ea] = by_address

    def expect(ea, expected):
        assert disk(ea, len(bytes.fromhex(expected))).hex() == expected, ('关键指令', hex(ea))

    # 下列断言来自独审者逐指令审阅，不从正文重新解析出“预期”。
    critical = {
        0x64FF47: '837df408', 0x64FF57: 'c60100', 0x64FF77: '8b8c8a000e0000',
        0x64FFE1: '0fb64d1c', 0x64FFE9: '0fb6551c', 0x650004: '0fb65518',
        0x650046: 'c60101', 0x650058: '8908', 0x65006F: 'c21800',
        0x63E7E4: '8a80300e0000', 0x63E011: '83c004', 0x63E0F1: '05140c0000',
        0x63E9A1: '8b4818', 0x63F484: '2b88280e0000', 0x7C0C11: '81c15c060000',
        0x7C0C29: '2b4174', 0x7F7420: '8b887c050000', 0x7F7436: '0fbf08',
        0x7F744F: '0fbf4802', 0x7F743C: '8b821c020000', 0x7F7456: '8b8220020000',
        0x7F746A: '7e24', 0x7F7472: '7d1c', 0x7F747D: '7e11', 0x7F7485: '7d09',
        0x7F7497: '8a45ec', 0x7F74A7: 'c20800', 0x91F6D0: '7501', 0x91F6D2: 'c3',
    }
    for ea, raw in critical.items():
        expect(ea, raw)
    al_consumers = [0x64FF66, 0x64FF83, 0x64FFA0, 0x64FFBD, 0x64FFDA,
                    0x64FFFD, 0x650018, 0x650039]
    for ea in al_consumers:
        assert instruction_maps[0x64FF10][ea] in (b'\x0f\xb6\xc0', b'\x0f\xb6\xc8')
    for ea, offset in [(0x63F4A0, 1493), (0x63EF50, 1494), (0x63EF80, 1495), (0x63EFB0, 1497)]:
        expect(ea + 0x11, '0fbe88' + struct.pack('<I', offset).hex())
        expect(ea + 0x18, '33c0')
        expect(ea + 0x1A, '83f9ff')
        expect(ea + 0x1D, '0f95c0')

    navigation = data['caller_navigation']
    assert len(navigation) == len(data['incoming']) == 18
    assert {int(r['site'], 16) for r in data['incoming']} == set(CALL_PARAMETERS)
    for row in navigation:
        incoming = row['incoming']
        site = int(incoming['site'], 16)
        owner, a5, a6 = CALL_PARAMETERS[site]
        assert incoming in data['incoming'] and int(incoming['caller'], 16) == owner
        assert incoming['iscode'] and incoming['type'] == 17 and incoming['entry'] == '0x61193f'
        raw, start = check(row['window']), int(row['window']['va'], 16)
        assert resolve(int(incoming['entry'], 16)) == 0x64FF10
        assert disk(site, 5)[0] == 0xE8
        assert site + 5 + struct.unpack_from('<i', disk(site, 5), 1)[0] == 0x61193F
        nav = {int(i['va'], 16): bytes.fromhex(i['hex']) for i in row['instructions']}
        assert len(nav) == len(row['instructions']) and site in nav
        assert all(len(nav[int(i['va'], 16)]) == i['size'] for i in row['instructions'])
        assert all(raw[address - start:address - start + len(piece)] == piece
                   for address, piece in nav.items())
        before = [nav[address] for address in sorted(nav) if address < site]
        candidates = [n for n in range(len(before) - 5)
                      if before[n:n + 2] == [bytes([0x6A, a6]), bytes([0x6A, a5])]
                      and len(before[n + 2]) == 3 and before[n + 2][0] == 0x8D
                      and before[n + 2][2] == 0xE8]
        assert len(candidates) == 1
        n = candidates[0]
        assert before[n + 3] == bytes([0x50 + ((before[n + 2][1] >> 3) & 7)]), ('out push', hex(site))
        last = before[n + 4]
        if site == 0x65862F:
            assert last == b'\x68\x54\x77\xa7\x00'
        else:
            assert len(last) == 3 and last[0] == 0x8D and last[2] == 0xD8
            assert before[n + 5] == bytes([0x50 + ((last[1] >> 3) & 7)])

    review = read('function_review.json')
    assert {int(ea, 16) for ea in review} == set(functions)
    levels = dict(Counter(row['status'] for row in review.values()))
    assert levels == {'静态契约已审阅': 2, '复用已有语义': 11, '调用参数局部审阅': 4}
    reuse_checks = 0
    for ea, row in review.items():
        assert row['conclusion'] and row['boundary']
        if row['status'] != '复用已有语义':
            continue
        relative = row['reuse_reference'].split('/functions/')[0]
        target = HERE.parent.parent / relative
        assert target.is_file()
        if target.suffix != '.json':
            continue
        reused = json.loads(target.read_text(encoding='utf-8-sig'))
        prior = [f for f in reused['functions'] if f['va'] == ea]
        assert len(prior) == 1
        for r in prior[0]['byte_ranges']:
            raw = bytes.fromhex(r['idb_hex'])
            assert r['matching'] is True and raw == bytes.fromhex(r['disk_hex'])
            assert raw == disk(int(r['va'], 16), r['size'])
        reuse_checks += 1
    modes = json.loads((HERE.parent.parent / '40B8系列事件/证据/geometry_modes.json').read_text(encoding='utf-8-sig'))
    mode4 = next(f for f in modes['functions'] if f['va'] == '0x629e10')
    assert mode4['byte_ranges'][0]['idb_hex'] == '558bec33c0837d08040f94c05dc3'
    assert disk(0x629E10, 14).hex() == mode4['byte_ranges'][0]['idb_hex']
    for path in HERE.parent.glob('*.txt'):
        lines = path.read_text(encoding='utf-8-sig').splitlines()
        assert all(not line or line.startswith('//') for line in lines)
        assert all(line == line.rstrip() for line in lines)
        assert not any(re.match(r'//\s*(?:#{1,6}\s|```|[-*+]\s|\|)', line) for line in lines)

    live = None
    if db is not None:
        import ida_bytes
        import ida_funcs
        import ida_nalt
        import idautils
        import idc

        def live_resolve(ea):
            seen = set()
            while ida_bytes.get_byte(ea) == 0xE9:
                assert ea not in seen
                seen.add(ea)
                ea += 5 + struct.unpack('<i', ida_bytes.get_bytes(ea + 1, 4))[0]
            return ea

        for ea, f in functions.items():
            owner = ida_funcs.get_func(ea)
            assert owner and owner.start_ea == ea
            actual_chunks = list(idautils.Chunks(ea))
            assert set(actual_chunks) == {(int(c['va'], 16), int(c['end'], 16)) for c in f['chunks']}
            actual_instructions, actual_edges, indirect = [], set(), []
            for start, end in actual_chunks:
                for address in idautils.Heads(start, end):
                    if not ida_bytes.is_code(ida_bytes.get_full_flags(address)):
                        continue
                    size = idc.get_item_size(address)
                    actual_instructions.append(dict(va=hex(address), size=size,
                                                    hex=ida_bytes.get_bytes(address, size).hex(),
                                                    text=idc.generate_disasm_line(address, 0) or ''))
                    if idc.print_insn_mnem(address) in ('call', 'jmp'):
                        if idc.get_operand_type(address, 0) in (idc.o_near, idc.o_far):
                            target = idc.get_operand_value(address, 0)
                            actual_edges.add((address, target, live_resolve(target)))
                        else:
                            indirect.append(dict(site=hex(address), text=idc.generate_disasm_line(address, 0) or ''))
            assert actual_instructions == f['instructions'], ('实时完整指令', hex(ea))
            assert actual_edges == {(int(c['site'], 16), int(c['target'], 16), int(c['resolved'], 16)) for c in f['calls']}
            assert indirect == f['indirect']
        entries = {0x64FF10}
        for ea in idautils.Functions():
            if ida_bytes.get_byte(ea) == 0xE9 and live_resolve(ea) == 0x64FF10:
                entries.add(ea)
        assert entries == {int(ea, 16) for ea in data['scope']['entries']} == {0x61193F, 0x64FF10}
        incoming = set()
        for entry in entries:
            for x in idautils.XrefsTo(entry, 0):
                owner = ida_funcs.get_func(x.frm)
                caller = owner.start_ea if owner else None
                if caller in entries:
                    continue
                incoming.add((x.frm, entry, int(x.type), bool(x.iscode), caller))
        assert incoming == {(int(r['site'], 16), int(r['entry'], 16), r['type'], r['iscode'],
                             int(r['caller'], 16) if r['caller'] else None) for r in data['incoming']}
        for row in navigation:
            address = int(row['incoming']['site'], 16)
            start, end = address, address + idc.get_item_size(address)
            owner_ea = int(row['incoming']['caller'], 16)
            for _ in range(32):
                previous = idc.prev_head(start)
                owner = ida_funcs.get_func(previous)
                if not owner or owner.start_ea != owner_ea:
                    break
                start = previous
            for _ in range(10):
                following = idc.next_head(end - 1)
                owner = ida_funcs.get_func(following)
                if not owner or owner.start_ea != owner_ea:
                    break
                end = following + idc.get_item_size(following)
            assert (start, end) == (int(row['window']['va'], 16), int(row['window']['va'], 16) + row['window']['size'])
            actual = [dict(va=hex(ea), size=idc.get_item_size(ea),
                           hex=ida_bytes.get_bytes(ea, idc.get_item_size(ea)).hex(),
                           text=idc.generate_disasm_line(ea, 0) or '')
                      for ea in idautils.Heads(start, end) if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]
            assert actual == row['instructions'], ('实时导航窗口', hex(address))
        assert ida_nalt.retrieve_input_file_sha256().hex() == data['idb_input_sha256']
        live = dict(function_chunk_sets=17, complete_instruction_sets=17,
                    near_transfer_sets=17, indirect_transfer_sets=17,
                    entry_set=sorted(hex(ea) for ea in entries), incoming_set=len(incoming), navigation_sets=18)

    merged = []
    for start, size in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], start + size)
        else:
            merged.append([start, start + size])
    assert len(ranges) == 79 and sum(end - start for start, end in merged) == 5531
    assert instructions == 1111 and len(thunks) == 44
    return dict(status='PASS', source_sha256=SOURCE_SHA, exe_sha256=SHA,
                idb_input_sha256=data['idb_input_sha256'], whole_idb_identity_claimed=False,
                functions=13, caller_contexts=4, complete_instruction_entries=instructions,
                near_transfer_edges=near_edges, thunk_ranges=len(thunks), incoming=18,
                navigation_windows=18, parameter_cases=len(CALL_PARAMETERS),
                byte_comparisons=comparisons, unique_ranges=len(ranges), union_bytes=5531,
                critical_instruction_assertions=len(critical) + len(al_consumers) + 16,
                reuse_function_byte_checks=reuse_checks, reused_mode4_byte_check=True,
                review_levels=levels, independent_model=model_audit(),
                live_ida_checked=db is not None, live_sets=live, mismatches=0,
                scope='当前 PE 与保存原证；两项新静态契约，11 项复用，四调用者限定参数消费；不替代实机。')


def model_audit():
    """仅调用作者纯函数；不运行会覆写作者文件的 run()/validate()。"""
    model_path = HERE / 'model_hit_filter.py'
    model = types.ModuleType('hit_filter_contract_under_review')
    model.__file__ = str(model_path)
    # 用内存编译避免 importlib 在作者证据目录自动写入 .pyc。
    exec(compile(model_path.read_text(encoding='utf-8-sig'), str(model_path), 'exec'), model.__dict__)
    signed_state_cases = flags = masks = geometry = 0
    for index, raw in itertools.product(range(4), range(256)):
        states = [-1] * 4
        states[index] = raw if raw < 128 else raw - 256
        assert model.eligible(True, states, False, False, True, 0, 0) == (raw == 255)
        signed_state_cases += 1
    # 穷举开关低 BYTE 与一个完整高字节周期，并验证负数等价表示。
    for available, special, current, inside in itertools.product((False, True), repeat=4):
        for value in range(512):
            for a5, a6 in [(value, 0), (0, value), (value - 512, 0), (0, value - 512)]:
                expected = bool(available and inside and (a6 % 256 or not special)
                                and (a5 % 256 or not current))
                assert model.eligible(available, [-1] * 4, special, current, inside, a5, a6) == expected
                flags += 1
    for mask, old_last in itertools.product(range(256), [-2147483648, -123, -1, 0, 7, 2147483647]):
        out, count, last = model.collect(mask, old_last)
        selected = [i for i in range(8) if (mask >> i) & 1]
        assert out == [int(i in selected) for i in range(8)] and count == len(selected)
        assert last == (selected[-1] if selected else old_last)
        masks += 1
    for world_x, world_y, camera_x, camera_y in [
            (0, 0, 0, 0), (1000, -1000, -32768, 32767), (-1000, 1000, 32767, -32768)]:
        right, bottom = world_x - camera_x, world_y - camera_y
        interior = 0
        for x, y in itertools.product(range(right - 65, right + 1), range(bottom - 97, bottom + 1)):
            actual = not (x <= right - 64 or x >= right or y <= bottom - 96 or y >= bottom)
            expected = x in range(right - 63, right) and y in range(bottom - 95, bottom)
            assert actual == expected
            interior += int(actual)
            geometry += 1
        assert interior == 5985
    return dict(signed_state_cases=signed_state_cases, flag_low_byte_cases=flags,
                output_mask_and_old_last_cases=masks, rectangle_cases=geometry,
                integer_interior_points_per_rectangle=5985, failures=0,
                limitation='布尔谓词与稳定参数的静态契约；非原机器码执行，不含指针别名、并发与32位溢出。')


if __name__ == '__main__':
    result = audit()
    (HERE / 'independent_local_review.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result, ensure_ascii=True))
