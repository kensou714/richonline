"""独立复核第28批大厅列表；不导入作者验证器，不调用IDA，不执行游戏。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_REG, CS_OP_MEM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
DOCS = HERE.parents[2]
ROOT = DOCS.parents[1]
EXE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '80caf7a717f3f67d960f14bd0749df7ef1a74e9c5150593fd34dfb7f307a881d'
TABLE_SHA = '6852de278eb9d3dad391b0f5b5f60a2c1cf5c4a102a340f368ea2ad417b9bb20'
FRESH = {0x69F6D0, 0x6A0B50, 0x6B8980, 0x6B8A00}
REUSED = {0x6B8A60, 0x69F750, 0x6A0130}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(final=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXE_SHA
    nt = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt + 4)[0] == 0x14C
    assert struct.unpack_from('<H', image, nt + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, nt + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    ranges, sites, bodies, sources, anchors = {}, {}, {}, {}, []

    def disk(va, size):
        offsets = [off + va - base - rva for _, rva, count, off in sections
                   if 0 <= va - base - rva and va - base - rva + size <= count]
        offset, = offsets
        result = image[offset:offset + size]
        assert len(result) == size
        return result

    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        data = disk(va, row['size'])
        assert row.get('matching', row.get('equal')) is True
        assert data.hex() == row['disk_hex'] == row.get('idb_hex', row.get('ida_hex'))
        h = hashlib.sha256(data).hexdigest()
        assert 'sha256' not in row or row['sha256'] == h
        ranges[(va, len(data))] = h
        return data

    def decode(row):
        va = int(row.get('start_va', row.get('va')), 16)
        data = audit(row)
        result = list(cs.disasm(data, va))
        assert sum(i.size for i in result) == len(data)
        cursor = va
        for ins in result:
            assert ins.address == cursor
            cursor += ins.size
            assert ins.address not in sites or sites[ins.address].bytes == ins.bytes
            sites[ins.address] = ins
        return result

    def walk(node):
        if isinstance(node, dict):
            if 'disk_hex' in node and 'size' in node and ('va' in node or 'start_va' in node):
                audit(node)
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    tables = json.loads((HERE / 'type_tables/bounded_raw.json').read_bytes())
    assert digest(HERE / 'bounded_raw.json') == RAW_SHA
    assert digest(HERE / 'type_tables/bounded_raw.json') == TABLE_SHA
    assert raw['disk_sha256'] == tables['disk_sha256'] == EXE_SHA
    core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    assert digest(core) == raw['exporter_sha256'] == tables['exporter_sha256']
    walk(raw)
    walk(tables)
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    assert {int(f['seed_va'], 16) for f in raw['reused_seeds']} == REUSED
    assert {int(f['seed_va'], 16) for f in raw['current_chunk_audits']} == FRESH | REUSED
    assert not tables['functions'] and len(tables['data_windows']) == 7
    assert sum(row['size'] for row in tables['data_windows']) == 66
    measurements = []
    for f in raw['current_chunk_audits']:
        va = int(f['seed_va'], 16)
        body = [i for row in f['chunk_byte_ranges'] for i in decode(row)]
        bodies[va] = body
        measurements.append(dict(va=hex(va), bytes=sum(r['size'] for r in f['chunk_byte_ranges']),
                                 chunks=len(f['chunk_byte_ranges']), instructions=len(body), new=va in FRESH))
    assert sum(row['bytes'] for row in measurements) == 5333
    assert sum(row['instructions'] for row in measurements) == 1242
    assert sum(row['bytes'] for row in measurements if row['new']) == 443
    for f in raw['functions']:
        va = int(f['seed_va'], 16)
        assert [int(r['site_va'], 16) for r in f['assembly']] == [i.address for i in bodies[va]]
        assert isinstance(f['pseudocode'], str) and not f['decompile_error']
    for ref in raw['reuse_sources']:
        path = (DOCS / ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve()) and digest(path) == ref['source_sha256']
        sources[ref['path']] = ref['source_sha256']
    lobby_path = '专题/大厅区域频道配置/证据/lobby_regions_ida_raw.json'
    old = json.loads((DOCS / lobby_path).read_bytes())
    old_records = {}
    for index, va in ((1, 0x69F750), (2, 0x6A0130)):
        original = old['functions'][index]
        assert int(original['va'], 16) == va
        old_ins = [i for r in original['chunks'] for i in decode(r)]
        assert [(i.address, i.bytes) for i in old_ins] == [(i.address, i.bytes) for i in bodies[va]]
        assert [(r['va'], r['hex']) for r in original['instructions']] == [
            (hex(i.address), i.bytes.hex()) for i in old_ins]
        old_records[hex(va)] = dict(path=lobby_path, pointer=f'/functions/{index}',
                                  sha256=digest(DOCS / lobby_path), chunks=len(original['chunks']))
    ui_path = '专题/界面系统/ida_ui_chain_raw.json'
    ui = json.loads((DOCS / ui_path).read_bytes())['functions']['0x6b8a60']
    assert len(ui['disassembly']) == len(bodies[0x6B8A60])
    old_records['0x6b8a60'] = dict(path=ui_path, pointer='/functions/0x6b8a60',
                                 sha256=digest(DOCS / ui_path), boundary='旧源纯文本无指令VA/字节；当前root块独立核验')
    bridges = {}
    for r in raw['verified_direct_bridges']:
        va, target = int(r['start_va'], 16), int(r['target_va'], 16)
        data = audit(r)
        assert len(data) == 5 and data[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        bridges[va] = target
    assert len(bridges) == 34
    for call in raw['calls']:
        ins = sites[int(call['site_va'], 16)]
        assert ins.mnemonic in ('call', 'jmp') and ins.operands[0].type == CS_OP_IMM
        target = ins.operands[0].imm & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        for hop in call['bridges']:
            assert target == int(hop, 16)
            target = bridges[target]
        assert target == int(call['implementation_va'], 16)
    window_records = raw['explicit_owner_windows'] + [r['owner_window'] for rows in raw['incoming'].values()
                                                       for r in rows if 'owner_window' in r]
    windows, ownerless = {}, []
    for win in window_records:
        if win['owner_va'] is None:
            assert not win['assembly']
            ownerless.append(win['site_va'])
            continue
        ids = []
        for row in win['assembly']:
            ins, = decode(row['bytes'])
            assert hex(ins.address) == row['site_va']
            if ids:
                assert sites[ids[-1]].address + sites[ids[-1]].size == ins.address
            ids.append(ins.address)
        assert int(win['site_va'], 16) in ids and ids == sorted(set(ids))
        windows[(win['owner_va'], win['site_va'])] = len(ids)
    def anchor(va, mnemonic, operands):
        ins = sites[va]
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(va), ins.mnemonic, ins.op_str)
        anchors.append(dict(va=hex(va), mnemonic=mnemonic, operands=operands, bytes=ins.bytes.hex()))
    for row in (
        (0x69F6EB, 'mov', 'dword ptr [ebp - 4], 0'),
        (0x69F6F6, 'call', '0x61032d'), (0x69F6FE, 'mov', 'dword ptr [ebp - 8], eax'),
        (0x69F713, 'cmp', 'dword ptr [ebp - 0xc], 4'), (0x69F717, 'jae', '0x69f73e'),
        (0x69F71C, 'mov', 'eax, dword ptr [edx*4 + 0xa673a4]'),
        (0x69F728, 'call', '0x61038c'), (0x69F732, 'jne', '0x69f73c'),
        (0x69F737, 'mov', 'dword ptr [ebp - 4], edx'), (0x69F73E, 'mov', 'eax, dword ptr [ebp - 4]'),
        (0x6B899A, 'mov', 'dword ptr [eax], 0'), (0x6B89A6, 'mov', 'dword ptr [ecx + 4], edx'),
        (0x6B89AF, 'mov', 'dword ptr [eax + 8], ecx'), (0x6B89B8, 'shl', 'eax, 2'),
        (0x6B89CD, 'mov', 'dword ptr [ecx + 0xc], edx'), (0x6B89DD, 'ret', '8'),
        (0x6B8A1A, 'cmp', 'dword ptr [eax + 0xc], 0'), (0x6B8A38, 'mov', 'dword ptr [ecx + 0xc], 0'),
        (0x6B8A82, 'cmp', 'edx, dword ptr [ecx + 4]'), (0x6B8A85, 'jl', '0x6b8b02'),
        (0x6B8A99, 'add', 'eax, dword ptr [ecx + 8]'), (0x6B8A9C, 'shl', 'eax, 2'),
        (0x6B8AB1, 'mov', 'dword ptr [edx + 0xc], eax'),
        (0x6B8AB7, 'mov', 'edx, dword ptr [ecx + 4]'), (0x6B8ABA, 'shl', 'edx, 2'),
        (0x6B8AC9, 'call', '0x60e3e8'), (0x6B8AE1, 'call', '0x601cd3'),
        (0x6B8AFF, 'mov', 'dword ptr [edx + 4], eax'),
        (0x6B8B10, 'mov', 'dword ptr [eax + ecx*4], edx'),
        (0x6B8B1E, 'mov', 'dword ptr [edx], ecx'), (0x6B8B25, 'sub', 'eax, 1'),
        (0x6A0B88, 'mov', 'dword ptr [ecx + 0x5c], 0'), (0x6A0B92, 'mov', 'dword ptr [edx + 0x60], 0'),
        (0x69F791, 'call', '0x60d1be'), (0x69F817, 'call', '0x609af5'),
        (0x69F81E, 'je', '0x69ffec'), (0x69F8B1, 'jne', '0x69f8e9'),
        (0x6A01A7, 'call', '0x609af5'), (0x6A01AE, 'je', '0x6a09cc'),
        (0x6A0241, 'jne', '0x6a0279'), (0x6A027C, 'call', '0x60d1be'),
        (0x69FE78, 'mov', 'dword ptr [edx + ecx + 0x130], eax'),
        (0x6A0858, 'mov', 'dword ptr [edx + ecx + 0x130], eax'),
        (0x69FE91, 'mov', 'dword ptr [eax + edx], 0'), (0x6A0871, 'mov', 'dword ptr [eax + edx], 0'),
        (0x69FF09, 'ja', '0x69ff72'), (0x6A08E9, 'ja', '0x6a0952'),
        (0x69FF11, 'jmp', 'dword ptr [eax*4 + 0x6a0083]'),
        (0x6A08F1, 'jmp', 'dword ptr [eax*4 + 0x6a0a63]'),
    ):
        anchor(*row)
    for va, offset in ((0x6A0B9C, 0x198), (0x6A0BAA, 0x1A8), (0x6A0BB8, 0x1B8), (0x6A0BC6, 0x1C8)):
        anchor(va, 'add', f'ecx, {hex(offset)}')
    for first in (0x69F796, 0x6A0281):
        for k in range(4):
            anchor(first + 18 * k, 'push', '0x10')
            anchor(first + 18 * k + 2, 'push', '0x20')
    data = {int(row['start_va'], 16): audit(row) for row in tables['data_windows']}
    ptrs = struct.unpack('<4I', data[0xA673A4])
    assert ptrs == (0xA237BC, 0xA237B4, 0xA237B0, 0xA237AC)
    types = [data[p] for p in ptrs]
    assert types == [b'CHU\0', b'ZHONG\0', b'GAO\0', b'XIN\0']
    for address, expected in ((0x6A0083, (0x69FF18, 0x69FF2F, 0x69FF46, 0x69FF5D)),
                              (0x6A0A63, (0x6A08F8, 0x6A090F, 0x6A0926, 0x6A093D))):
        assert struct.unpack('<4I', data[address]) == expected
        for k, target in enumerate(expected):
            ins = sites[target]
            assert ins.mnemonic == 'mov' and ins.op_str.endswith('dword ptr [ebp - 0x1c8]')
            anchor(target + 10, 'add', f'ecx, {hex(0x198 + k * 16)}')

    # strcmp旧完整块只复核当前所需的逐字节/NUL比较契约；不新增本专题审阅入口。
    cmp_path = DOCS / '专题/名称查找与等待消费者/证据/supplement_raw.json'
    assert digest(cmp_path) == '5211fcf04136f28f57a91453be58a22d8f01304f98393371726d06a4ef9770bf'
    cmp_record = json.loads(cmp_path.read_bytes())['functions'][2]
    assert cmp_record['seed_va'] == '0x922830'
    cmp_body = [i for row in cmp_record['chunk_byte_ranges'] for i in decode(row)]
    assert [r['site_va'] for r in cmp_record['assembly']] == [hex(i.address) for i in cmp_body]
    assert all(i.mnemonic != 'call' for i in cmp_body)
    sources[cmp_path.relative_to(DOCS).as_posix()] = digest(cmp_path)
    for row in ((0x922842, 'cmp', 'al, byte ptr [ecx]'),
                (0x92284A, 'cmp', 'ah, byte ptr [ecx + 1]'),
                (0x922856, 'cmp', 'al, byte ptr [ecx + 2]'),
                (0x92285F, 'cmp', 'ah, byte ptr [ecx + 3]'),
                (0x922870, 'xor', 'eax, eax'), (0x922874, 'sbb', 'eax, eax'),
                (0x69F82F, 'test', 'eax, eax'), (0x69F831, 'jbe', '0x69f842'),
                (0x6A01BF, 'test', 'eax, eax'), (0x6A01C1, 'jbe', '0x6a01d2'),
                (0x69FECF, 'add', 'esp, 4'), (0x6A08AF, 'add', 'esp, 4')):
        anchor(*row)

    def finite_run(start, args=(), initial=None, string=None, alloc_null=False):
        """仅本专题四个无EH短体的已核指令；库函数以明确桩隔离，不模拟真实堆。"""
        mem, regs, events = {}, dict(eax=0, ebx=0, ecx=0x1000, edx=0, esi=0, edi=0,
                                     ebp=0, esp=0x100000), []
        def put(address, value, size=4):
            for k in range(size):
                mem[(address + k) & 0xFFFFFFFF] = (value >> (8 * k)) & 255
        def get(address, size=4):
            assert all(((address + k) & 0xFFFFFFFF) in mem for k in range(size)), ('未初始化读取', hex(address), size)
            return sum(mem[(address + k) & 0xFFFFFFFF] << (8 * k) for k in range(size))
        put(regs['esp'], 0xFFFFFFFF)
        for k, arg in enumerate(args):
            put(regs['esp'] + 4 + k * 4, arg)
        for k, value in enumerate(initial or [0, 0, 0, 0]):
            put(0x1000 + k * 4, value)
        if string is not None:
            for va, blob in data.items():
                for k, value in enumerate(blob):
                    put(va + k, value, 1)
            for k, value in enumerate(string + b'\0'):
                put(0x2000 + k, value, 1)
        def address(op):
            m = op.mem
            return (regs.get(cs.reg_name(m.base), 0) + regs.get(cs.reg_name(m.index), 0) * m.scale + m.disp) & 0xFFFFFFFF
        def read(op):
            if op.type == CS_OP_IMM:
                return op.imm & 0xFFFFFFFF
            if op.type == CS_OP_REG:
                return regs[cs.reg_name(op.reg)]
            assert op.type == CS_OP_MEM
            return get(address(op), op.size)
        def write(op, value):
            value &= (1 << (op.size * 8)) - 1
            if op.type == CS_OP_REG:
                regs[cs.reg_name(op.reg)] = value
            else:
                assert op.type == CS_OP_MEM
                put(address(op), value, op.size)
        def cstring(address):
            values = []
            for _ in range(128):
                value = get(address, 1)
                if value == 0:
                    return bytes(values)
                values.append(value)
                address += 1
            raise AssertionError('有限字符串桩超界')
        flags = dict(zf=False, cf=False, signed_lt=False)
        pc = start
        steps = 0
        while steps < 1000:
            steps += 1
            ins = sites[pc]
            ops, op = ins.operands, ins.mnemonic
            nxt = pc + ins.size
            if op == 'push':
                value = read(ops[0])
                regs['esp'] = (regs['esp'] - 4) & 0xFFFFFFFF
                put(regs['esp'], value)
            elif op == 'pop':
                write(ops[0], get(regs['esp']))
                regs['esp'] += 4
            elif op == 'mov':
                write(ops[0], read(ops[1]))
            elif op in ('add', 'sub', 'shl'):
                a, b = read(ops[0]), read(ops[1])
                write(ops[0], a + b if op == 'add' else a - b if op == 'sub' else a << b)
            elif op in ('cmp', 'test'):
                a, b = read(ops[0]), read(ops[1])
                flags['zf'] = (a == b) if op == 'cmp' else ((a & b) == 0)
                flags['cf'] = a < b if op == 'cmp' else False
                signed = lambda v: v if v < 0x80000000 else v - 0x100000000
                flags['signed_lt'] = signed(a) < signed(b)
            elif op in ('je', 'jne', 'jl', 'jae', 'jbe'):
                take = {'je': flags['zf'], 'jne': not flags['zf'], 'jl': flags['signed_lt'],
                        'jae': not flags['cf'], 'jbe': flags['cf'] or flags['zf']}[op]
                if take:
                    nxt = read(ops[0])
            elif op == 'jmp':
                nxt = read(ops[0])
            elif op == 'call':
                target = bridges[read(ops[0])]
                if target == 0x91F6D0:
                    assert flags['zf'], '有限正常路径要求RTC栈平衡'
                elif target == 0x91BD80:
                    size = get(regs['esp'])
                    events.append(dict(kind='allocate', size=size))
                    regs['eax'] = 0 if alloc_null else 0x4000
                elif target == 0x91F7E0:
                    events.append(dict(kind='delete', pointer=get(regs['esp'])))
                elif target == 0x9213A0:
                    events.append(dict(kind='copy', dst=get(regs['esp']), src=get(regs['esp'] + 4),
                                       size=get(regs['esp'] + 8)))
                    regs['eax'] = get(regs['esp'])
                elif target == 0x91FB00:
                    regs['eax'] = len(cstring(get(regs['esp'])))
                elif target == 0x922830:
                    a, b = cstring(get(regs['esp'])), cstring(get(regs['esp'] + 4))
                    regs['eax'] = 0 if a == b else (1 if a > b else 0xFFFFFFFF)
                else:
                    raise AssertionError(('不支持依赖', hex(target)))
            elif op == 'ret':
                assert get(regs['esp']) == 0xFFFFFFFF
                regs['esp'] += 4 + (read(ops[0]) if ops else 0)
                return dict(eax=regs['eax'], esp=regs['esp'], fields=[get(0x1000 + k * 4) for k in range(4)],
                            events=events, steps=steps)
            else:
                raise AssertionError(('不支持指令', hex(pc), op))
            pc = nxt
        raise AssertionError('有限指令模型超步数')

    model_cases = []
    for value, expected in ((b'CHU', 0), (b'ZHONG', 1), (b'GAO', 2), (b'XIN', 3),
                            (b'chu', 0), (b'zhong', 0), (b'gao', 0), (b'xin', 0),
                            (b'', 0), (b'GAO ', 0), (b' GAO', 0), (b'OTHER', 0), (b'GAO\0XIN', 2)):
        actual = finite_run(0x69F6D0, (0x2000,), string=value)
        assert actual['eax'] == expected and actual['esp'] == 0x100004
        model_cases.append(dict(kind='classify', input_hex=value.hex(), expected=expected, execution=actual))
    for cap, growth in ((32, 16), (0, 0), (0x40000000, 1), (0xFFFFFFFF, 16)):
        actual = finite_run(0x6B8980, (cap, growth), initial=[9, 20, 4, 0x3000])
        assert actual['fields'] == [0, cap, growth, 0x4000]
        assert actual['events'] == [dict(kind='allocate', size=(cap * 4) & 0xFFFFFFFF)]
        assert actual['esp'] == 0x10000C
        model_cases.append(dict(kind='initialize', capacity=cap, growth=growth, execution=actual))
    for pointer in (0, 0x3000):
        actual = finite_run(0x6B8A00, initial=[9, 32, 16, pointer])
        assert actual['fields'] == [9, 32, 16, 0]
        assert actual['events'] == ([] if pointer == 0 else [dict(kind='delete', pointer=pointer)])
        model_cases.append(dict(kind='clear', pointer=pointer, execution=actual))
    for count, cap, growth, expanded in ((0, 32, 16, False), (31, 32, 16, False),
                                       (32, 32, 16, True), (48, 48, 16, True),
                                       (0xFFFFFFFF, 32, 16, False), (32, 32, 0, True)):
        actual = finite_run(0x6B8A60, (777,), initial=[count, cap, growth, 0x3000])
        assert actual['eax'] == count and actual['esp'] == 0x100008
        assert actual['fields'] == [(count + 1) & 0xFFFFFFFF,
                                    ((cap + growth) & 0xFFFFFFFF) if expanded else cap,
                                    growth, 0x4000 if expanded else 0x3000]
        if expanded:
            assert actual['events'] == [dict(kind='allocate', size=((cap + growth) * 4) & 0xFFFFFFFF),
                                        dict(kind='copy', dst=0x4000, src=0x3000, size=cap * 4),
                                        dict(kind='delete', pointer=0x3000)]
        else:
            assert not actual['events']
        model_cases.append(dict(kind='append', count=count, capacity=cap, growth=growth, execution=actual))
    assert len(model_cases) == 25

    result = dict(schema='richonline-lobby-lists-independent-28-1', result='PRECHECK_ONLY',
                  disk_sha256=EXE_SHA, raw_sha256=RAW_SHA, tables_sha256=TABLE_SHA,
                  ranges=len(ranges), functions=measurements, bridges=len(bridges), calls=len(raw['calls']),
                  window_records=len(window_records), unique_windows=len(windows), ownerless=ownerless,
                  sources=sources, old_records=old_records, semantic_anchors=anchors,
                  finite_instruction_cases=model_cases,
                  classification_strings=[x[:-1].decode('ascii') for x in types],
                  boundary='当前PE静态范围；旧parser仅深化列表语义；未运行游戏或联调服务器')
    if final:
        bindings_path = HERE / 'author_bindings.json'
        expected_bindings_sha = 'de75cf9e3c89308b3adda2a0fd44cd611cf31dfea51d045dafcc95f82572482f'
        assert digest(bindings_path) == expected_bindings_sha, '作者终稿指纹尚未最终绑定'
        bindings = json.loads(bindings_path.read_bytes())['files']
        bindings += [dict(path='证据/export_type_tables.py',
                          sha256='fa927afb48afbc3deda40e912cd0dc0d9a82313ed0e2c7c8bd87bac8bafc85e1')]
        for ref in bindings:
            path = (TOPIC / ref['path']).resolve()
            assert path.is_relative_to(TOPIC.resolve()) and digest(path) == ref['sha256'], ref['path']
        formal = json.loads((HERE / 'formal_functions.json').read_bytes())
        manifest = json.loads((TOPIC / '函数审阅清单.json').read_bytes())
        assert formal['disk_sha256'] == EXE_SHA and formal['raw_sha256'] == RAW_SHA
        assert {int(f['va'], 16) for f in formal['functions']} == FRESH | REUSED
        assert len(formal['functions']) == len(manifest['functions']) == 7
        assert {int(f['va'], 16) for f in manifest['functions']} == FRESH | REUSED
        expected_status = {**{va: '静态函数语义已审阅' for va in FRESH}, 0x6B8A60: '既有函数契约复核',
                           0x69F750: '局部语义已审阅', 0x6A0130: '局部语义已审阅'}
        for reviewed in manifest['functions']:
            assert reviewed['status'] == expected_status[int(reviewed['va'], 16)]
        for adapted in formal['functions']:
            va = int(adapted['va'], 16)
            if va in FRESH:
                original = next(f for f in raw['functions'] if int(f['seed_va'], 16) == va)
                expected_source = 'bounded_raw.json'
            elif va == 0x6B8A60:
                original = ui
                expected_source = ui_path
            else:
                original = old['functions'][1 if va == 0x69F750 else 2]
                expected_source = lobby_path
            assert isinstance(adapted['source_record_json'], str)
            assert json.loads(adapted['source_record_json']) == original
            assert adapted['source']['path'] == expected_source
            assert adapted['source']['source_sha256'] == (RAW_SHA if va in FRESH else sources[expected_source])
            assert adapted['chunk_byte_ranges'] == next(f['chunk_byte_ranges'] for f in raw['current_chunk_audits']
                                                        if int(f['seed_va'], 16) == va)
            assert adapted['assembly'] == [dict(va=hex(i.address), size=i.size,
                                                text=i.mnemonic + (' ' + i.op_str if i.op_str else ''),
                                                hex=i.bytes.hex()) for i in bodies[va]]
        author = json.loads((HERE / 'author_validation.json').read_bytes())
        assert author['result'] == 'PASS' and author['instructions'] == 1242 and author['chunk_bytes'] == 5333
        assert author['direct_bridges'] == 34 and author['new_functions'] == 4 and author['reused_functions'] == 3
        assert author['semantic_anchors'] == 49
        assert all(not line.strip() or line.startswith('//') for p in TOPIC.glob('*.txt')
                   for line in p.read_text(encoding='utf-8').splitlines())
        doc = (TOPIC / '03_两种重载时序与失败状态.txt').read_text(encoding='utf-8')
        assert '长度不正' not in doc
        result.update(result='PASS', author_bindings=bindings, author_bindings_sha256=expected_bindings_sha,
                      independent_script_sha256=digest(Path(__file__)),
                      supplementary_cmp=dict(va='0x922830', bytes=136, instructions=len(cmp_body),
                                             boundary='旧函数本次只复核比较/NUL契约，不登记新review'))
        (HERE / 'independent_final_audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        report = [
            '// ============================================================================',
            '// 大厅分类与索引列表生命周期 / 第28批独立审阅结论',
            '// ============================================================================',
            '// 判定：PASS；不修改作者原证与历史专题，不调用IDA，不执行游戏或网络请求。',
            '// 当前PE SHA256：' + EXE_SHA + '。',
            '// 四新主块443字节/131指令；三旧当前块4890字节/1111指令；合计5333字节/1242指令。',
            '// 两parser各含2291字节主块与46字节异常尾；逐项核旧原始hex与当前PE。',
            '// 6B8A60旧源仅纯文本，不能冒称旧字节已核；当前216字节块来自root本轮IDA原证。',
            '// 34个E9桥、177个直接调用、55原窗口记录去重35个窗口均核验；桥不列业务review。',
            '// 七个数据窗66字节绑定四类型、四指针及两switch表；本体数据共341去重范围。',
            '// 额外复核旧strcmp136字节范围，合计342范围；不新增该函数覆盖。',
            '// CHU/ZHONG/GAO/XIN精确ASCII比较，未知/空串/小写/空白均归0；首NUL结束。',
            '// cdecl分类体ret无立即数，调用点ADD ESP,4；初始化ret8、追加ret4，调用约定不混用。',
            '// 列表count/capacity/growth/base四DWORD；32/16以元素计，初始128字节。',
            '// 追加signed比较，复制旧capacity而非count；先覆base再复制/释放，不保证坏状态安全。',
            '// 清理只清base，计数/容量/增长保留；再次append不属于有效空容器保证。',
            '// M+5C频道308字节记录数组与四索引列表分开；元素是跨area累计索引，不是ChannelID。',
            '// 69F750先清旧再读取；6A0130在URL/非零正文/area门之后才清旧。',
            '// 已促成勘误：TEST EAX,EAX清CF后JBE只拒绝零；原“长度不正”会误导为signed<=0。',
            '// 25组有限实际主体指令模型已执行：分类13、初始化4、清理2、追加6；库函数明确桩隔离。',
            '// 模型包括NUL后缀、大小写、容量乘4回绕、负count、零growth，结果只解释指令，不代表输入合法。',
            '// 旧parser机械全范围通过不代表完整字段/异常状态表语义闭合；只认可列表与重载时序。',
            '// 未证：网络真实内容、异常/资源耗尽、并发、其他借用者、底层分配失败策略及动态热重载。',
            '// IDB输入指纹与PE不同，仅本报告逐范围匹配有效，不宣称整个IDB同版。',
            '// 重放：在证据目录运行 python -X utf8 independent_review.py --final。',
            '// 证据/independent_final_audit.json保留指令锚、来源SHA、模型结果和全部作者终稿绑定。',
        ]
        report.extend('// 作者终稿 SHA256 ' + ref['path'] + '：' + ref['sha256'] + '。' for ref in bindings)
        (TOPIC / '独立审阅结论.txt').write_text('\n'.join(report) + '\n', encoding='utf-8')
        print(json.dumps(dict(result='PASS', author_bindings=len(bindings), ranges=len(ranges),
                              anchors=len(anchors), model_cases=len(model_cases)), ensure_ascii=False))
        return
    (HERE / 'independent_precheck.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('sources', 'semantic_anchors', 'old_records', 'finite_instruction_cases')}, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--final', action='store_true')
    main(parser.parse_args().final)
