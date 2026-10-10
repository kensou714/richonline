"""资源分组生产独立离线审阅；只读 PE 与原证，不调用作者程序或 IDA。"""
import argparse
import hashlib
import json
import struct
import re
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'b54d51310320c1d05b44407c76fd02177ad3f196b87f8175ef00dc24df8e75fa'
FORMAL_SHA = 'b345aaeee058d3413b7ca71d6bdedcc9884488aaf0a21d3582a9d218c73458b3'
REUSED_SHA = '57c301382bdda7f30ee7fb3eea5df35c425ccc6da9dc5e096ad419726a4ddf0e'
LEDGER_SHA = '9df720488d88d7561f747fba3a1fd3a5232a3c0279e6b6128c914892960260e0'
NEW = ('0x6dfa10', '0x6d76c0', '0x6d7c00', '0x6d7c30')
REUSED = ('0x6d7660', '0x6dfd10')
OWNER_SITES = (0x6D7DF2, 0x6D803F, 0x6DA25F, 0x6DA2C8,
               0x6DA316, 0x6DA394, 0x6DA3F9, 0x6DA457)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--show', nargs=2)
    parser.add_argument('--final', action='store_true')
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    hashes, counts, decoded, ranges = {}, {}, {}, {}

    def load(path):
        payload = path.read_bytes()
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(payload).hexdigest()
        return json.loads(payload)

    def pointer(data, location):
        assert location.startswith('/')
        for key in location[1:].split('/'):
            key = key.replace('~1', '/').replace('~0', '~')
            data = data[int(key)] if isinstance(data, list) else data[key]
        return data

    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == PE_SHA
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    start = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, start + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True

    def disk(ea, size):
        assert size > 0
        hits = [(rva, offset) for _, rva, length, offset in sections
                if base + rva <= ea and ea + size <= base + rva + length]
        assert len(hits) == 1, (hex(ea), size)
        rva, offset = hits[0]
        payload = image[offset + ea - base - rva:offset + ea - base - rva + size]
        assert len(payload) == size
        return payload

    def audit(row, ea=None):
        ea = ea if ea is not None else int(row.get('start_va', row.get('va')), 16)
        payload = disk(ea, row['size'])
        assert payload.hex() == row['disk_hex'].lower()
        assert payload.hex() == row.get('idb_hex', row.get('ida_hex')).lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row:
            assert hashlib.sha256(payload).hexdigest() == row['sha256']
        ranges[(ea, len(payload))] = hashlib.sha256(payload).hexdigest()
        return payload

    def decode_record(row, chunks=None):
        chunks = chunks if chunks is not None else row.get('chunk_byte_ranges',
            row.get('byte_ranges', row.get('chunks')))
        assembly = row.get('assembly', row.get('instructions'))
        addresses = []
        for chunk in chunks:
            payload = audit(chunk)
            ea = int(chunk.get('start_va', chunk.get('va')), 16)
            instructions = list(decoder.disasm(payload, ea))
            assert sum(i.size for i in instructions) == len(payload), hex(ea)
            for ins in instructions:
                decoded[ins.address] = ins
                addresses.append(hex(ins.address))
        if assembly is not None:
            assert addresses == [i.get('site_va', i.get('va')) for i in assembly], row.get('va', row.get('seed_va'))
        return len(addresses)

    raw = load(HERE / 'bounded_raw.json')
    assert hashes[(HERE / 'bounded_raw.json').relative_to(ROOT).as_posix()] == RAW_SHA
    assert raw['disk_sha256'] == PE_SHA
    assert tuple(x['seed_va'] for x in raw['functions']) == NEW
    assert tuple(x['seed_va'] for x in raw['reused_seeds']) == REUSED
    assert tuple(x['seed_va'] for x in raw['seeds']) == NEW + REUSED
    current = {x['seed_va']: x['chunk_byte_ranges'] for x in raw['current_chunk_audits']}
    counts['new_functions'] = len(NEW)
    counts['new_instructions'] = sum(decode_record(x) for x in raw['functions'])
    counts['new_bytes'] = sum(x['size'] for f in raw['functions'] for x in f['chunk_byte_ranges'])
    for row in raw['functions']:
        assert current[row['seed_va']] == row['chunk_byte_ranges']
    old_path = DOCS / '专题/图像资源/证据/20261009_图像加载函数群.json'
    old = load(old_path)
    assert hashes[old_path.relative_to(ROOT).as_posix()] == 'c7249d72dc7468b4cac66977ccdd34cbcf7051519df538f8b597ee0d2cd3efd5'
    counts['reused_seed_instructions'] = 0
    for idx, va in zip((18, 19), REUSED):
        original = old['functions'][idx]
        assert original['va'] == va
        counts['reused_seed_instructions'] += decode_record(original, current[va])
    bridges = {}
    for row in raw['verified_direct_bridges']:
        payload = audit(row)
        ea = int(row['start_va'], 16)
        assert len(payload) == 5 and payload[0] == 0xE9
        target = ea + 5 + struct.unpack_from('<i', payload, 1)[0]
        assert target == int(row['target_va'], 16)
        assert ea not in bridges or bridges[ea] == target
        bridges[ea] = target
    counts['formal_bridges'] = len(bridges)
    for row in raw['calls']:
        ins = decoded[int(row['site_va'], 16)]
        assert ins.mnemonic in ('call', 'jmp') and ins.operands[0].type == X86_OP_IMM
        target = ins.operands[0].imm
        assert target == int(row['target_va'], 16)
        for bridge in row['bridges']:
            assert int(bridge, 16) == target
            target = bridges[target]
        assert target == int(row['implementation_va'], 16)
    counts['seed_calls'] = len(raw['calls'])
    assert tuple(int(x['site_va'], 16) for x in raw['explicit_owner_windows']) == OWNER_SITES
    windows = raw['explicit_owner_windows'] + [e['owner_window']
        for edges in raw['incoming'].values() for e in edges if 'owner_window' in e]
    counts['window_records'] = len(windows)
    counts['window_items'] = 0
    for window in windows:
        assert window['owner_va'] is not None and window['site_va'] in [i['site_va'] for i in window['assembly']]
        assert len(window['assembly']) <= 11
        previous_end = None
        for row in window['assembly']:
            ea = int(row['site_va'], 16)
            payload = audit(row['bytes'], ea)
            assert previous_end is None or ea == previous_end
            previous_end = ea + len(payload)
            if row['is_code']:
                ins = list(decoder.disasm(payload, ea))
                assert len(ins) == 1 and ins[0].size == len(payload)
                decoded[ea] = ins[0]
            counts['window_items'] += 1
    assert not raw['strings']
    for row, expected in zip(raw['data_windows'], (b'OTHER_%d\0', b'O_%d_S_%d\0', b'npid\0')):
        payload = audit(row)
        assert payload == expected and payload.find(b'\0') == len(payload) - 1
    assert len(raw['data_windows']) == 3
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
    loader_path = DOCS / '专题/4019系列事件/证据/resource_loader_scope.json'
    loader = load(loader_path)['functions'][0]
    assert hashes[loader_path.relative_to(ROOT).as_posix()] == '27806e010c6173904c9741240f89360e9f251b36a25664f3ea4b8c0f331cc0d3'
    assert loader['va'] == '0x6d8130'
    counts['loader_mechanical_instructions'] = decode_record(loader)
    counts['loader_mechanical_bytes'] = sum(x['size'] for x in loader['byte_ranges'])
    # 大 loader 仅以完整原证保障字节闭包；业务审阅仅 OTHER 区段。
    vector_path = DOCS / '专题/124字节共享数组生命周期/证据/reused_raw.json'
    vector_row = load(vector_path)['records'][4]
    assert vector_row['va'] == '0x622d50'
    source = vector_row['source']
    vector_source_path = (vector_path.parent / source['path']).resolve()
    vector_source = load(vector_source_path)
    assert hashlib.sha256(vector_source_path.read_bytes()).hexdigest() == source['sha256']
    assert pointer(vector_source, source['pointer']) == vector_row['original_record']
    counts['vector_instructions'] = decode_record(vector_row['original_record'])
    mouse = load(DOCS / '专题/SysRes鼠标资源加载/证据/bounded_raw.json')
    counts['mouse_consumer_instructions'] = decode_record(next(x for x in mouse['functions'] if x['seed_va'] == '0x6db9d0'))
    role = load(DOCS / '专题/角色文本选择与控件消费/证据/reused_functions.json')
    role_row = next(x for x in role['functions'] if x['va'] == '0x6dba40')
    # 该旧记录尾部含 switch 表；按声明的逐项边界核代码，不将数据解码成指令。
    role_chunks = role_row['byte_ranges']
    for chunk in role_chunks:
        payload = audit(chunk)
        lo = int(chunk.get('va', chunk.get('start_va')), 16)
        hi = lo + len(payload)
        items = [x for x in role_row['assembly'] if lo <= int(x.get('va', x.get('site_va')), 16) < hi]
        for i, item in enumerate(items):
            ea = int(item.get('va', item.get('site_va')), 16)
            end = int(items[i + 1].get('va', items[i + 1].get('site_va')), 16) if i + 1 < len(items) else hi
            if item['text'].split()[0].lower() in ('db', 'dw', 'dd', 'dq'):
                continue
            instructions = list(decoder.disasm(disk(ea, end - ea), ea))
            assert len(instructions) == 1 and instructions[0].size == end - ea
            decoded[ea] = instructions[0]
    # 独立验证作者最终适配：逐字段回指原证，不接受只看计数的“形式通过”。
    formal_path = HERE / 'formal_functions.json'
    reused_path = HERE / 'reused_functions.json'
    ledger_path = TOPIC / '函数审阅清单.json'
    assert hashlib.sha256(formal_path.read_bytes()).hexdigest() == FORMAL_SHA
    assert hashlib.sha256(reused_path.read_bytes()).hexdigest() == REUSED_SHA
    assert hashlib.sha256(ledger_path.read_bytes()).hexdigest() == LEDGER_SHA
    formal = load(formal_path)
    reused = load(reused_path)
    ledger = load(ledger_path)
    assert formal['disk_sha256'] == reused['disk_sha256'] == ledger['disk_sha256'] == PE_SHA
    assert tuple(x['va'] for x in formal['functions']) == NEW
    assert tuple(x['va'] for x in reused['functions']) == ('0x6d7660', '0x6dfd10', '0x6d8130', '0x622d50', '0x91f7e0', '0x91f6d0', '0x6db9d0')
    assert tuple(x['va'] for x in ledger['functions']) == NEW
    assert tuple(x['va'] for x in ledger['historical_contracts']) == tuple(x['va'] for x in reused['functions'])
    raw_functions = {x['seed_va']: x for x in raw['functions']}
    for row in formal['functions']:
        source = load(DOCS / row['source_path'])
        assert row['source_sha256'] == RAW_SHA and row['source_pointer'].startswith('/functions/')
        original = pointer(source, row['source_pointer'])
        assert all(row[k] == v for k, v in original.items())
        assert row['source_field_pointers'] == {key: row['source_pointer'] + '/' + key for key in original}
        assert row['va'] == original['seed_va'] and row['seed_va'] == original['seed_va']
        assert row['pseudocode'] == original['pseudocode']
        assert row['normalized_chunks'] == original['chunk_byte_ranges']
        assert len(row['normalized_assembly']) == len(original['assembly'])
        assert all(n['site_va'] == o['site_va'] and n['text'] == o['text'] and n['original'] == o
                   for n, o in zip(row['normalized_assembly'], original['assembly']))
        assert row['declared_chunks'] == [dict(start_va=x['start_va'], end_va=hex(int(x['start_va'], 16) + x['size']), is_main=True) for x in original['chunk_byte_ranges']]
        assert raw_functions[row['va']]['chunk_byte_ranges'] == original['chunk_byte_ranges']
    expected_reused_sources = {
        '0x6d7660': ('专题/图像资源/证据/20261009_图像加载函数群.json', '/functions/18'),
        '0x6dfd10': ('专题/图像资源/证据/20261009_图像加载函数群.json', '/functions/19'),
        '0x6d8130': ('专题/4019系列事件/证据/resource_loader_scope.json', '/functions/0'),
        '0x622d50': ('专题/124字节共享数组生命周期/证据/reused_raw.json', '/records/4/original_record'),
        '0x91f7e0': ('专题/124字节共享数组生命周期/证据/reused_raw.json', '/records/9/original_record'),
        '0x91f6d0': ('专题/4060系列事件/证据/callees.json', '/functions/10'),
        '0x6db9d0': ('专题/SysRes鼠标资源加载/证据/bounded_raw.json', '/functions/1'),
    }
    for row in reused['functions']:
        path, location = expected_reused_sources[row['va']]
        source_path = DOCS / path
        source = load(source_path)
        original = pointer(source, location)
        assert row['source_path'] == path and row['source_pointer'] == location
        assert row['source_sha256'] == hashlib.sha256(source_path.read_bytes()).hexdigest()
        assert row['va'] == original.get('va', original.get('seed_va'))
        assert all(row[k] == v for k, v in original.items())
        assert row['source_field_pointers'] == {key: location + '/' + key for key in original}
        old_chunks = original.get('chunk_byte_ranges', original.get('byte_ranges', original.get('chunks')))
        if old_chunks is None:
            old_chunks = current[row['va']]
            src = row['current_bytes_source']
            assert src['source_path'] == '专题/资源配置分组记录生产/证据/bounded_raw.json'
            assert pointer(raw, src['source_pointer'])['chunk_byte_ranges'] == old_chunks
        assert row['normalized_chunks'] == [dict(start_va=x.get('start_va', x.get('va')),
            **{k: v for k, v in x.items() if k not in ('start_va', 'va', 'address')})
            for x in old_chunks]
        assert row['declared_chunks'] == original.get('declared_chunks', [dict(start_va=x['start_va'],
            end_va=hex(int(x['start_va'], 16) + x['size']), is_main=x['start_va'] == row['va']) for x in row['normalized_chunks']])
        if row['va'] in ('0x91f7e0', '0x91f6d0'):
            decode_record(row, row['normalized_chunks'])
        assert len(row['normalized_assembly']) == len(original.get('assembly', original.get('instructions')))
        assert all(n['site_va'] == o.get('site_va', o.get('va')) and n['text'] == o['text'] and n['original'] == o
                   for n, o in zip(row['normalized_assembly'], original.get('assembly', original.get('instructions'))))
        if row['va'] in REUSED:
            assert row.get('current_bytes_source', {}).get('source_sha256') == RAW_SHA
    historical_calls = 0
    offline_bridges = set()
    for row in reused['functions']:
        for call in row.get('calls', []):
            site = int(call.get('site', call.get('site_va')), 16)
            ins = decoded[site]
            assert ins.mnemonic in ('call', 'jmp') and ins.operands[0].type == X86_OP_IMM
            target = ins.operands[0].imm
            assert target == int(call.get('target', call.get('target_va')), 16)
            for thunk in call.get('thunks', call.get('bridges', [])):
                assert int(thunk, 16) == target
                value = disk(target, 5)
                assert value[0] == 0xe9
                offline_bridges.add(target)
                target += 5 + struct.unpack_from('<i', value, 1)[0]
            assert target == int(call.get('implementation', call.get('implementation_va')), 16)
            historical_calls += 1
    counts.update(historical_direct_calls=historical_calls, offline_navigation_bridges=len(offline_bridges))
    counts['author_formal_records'] = len(formal['functions'])
    counts['author_reused_records'] = len(reused['functions'])
    counts['ledger_anchors'] = sum(len(x['semantic_anchors']) for x in ledger['functions'] + ledger['historical_contracts'])
    for item in ledger['functions'] + ledger['historical_contracts']:
        collection = formal if item['evidence_ref']['file'] == 'formal_functions.json' else reused
        row = pointer(collection, item['evidence_ref']['pointer'])
        assert item['va'] == row['va'] and item['declared_chunks'] == row['declared_chunks']
        assert item['source_path'] == row['source_path'] and item['source_pointer'] == row['source_pointer']
        assert item['source_sha256'] == row['source_sha256'] and item['mechanical_items'] == len(row['normalized_assembly'])
        assembly_map = {i['site_va']: i['text'] for i in row['normalized_assembly']}
        for anchor in item['semantic_anchors']:
            assert anchor['va'] in assembly_map and assembly_map[anchor['va']] == anchor['original_text']
            assert int(anchor['va'], 16) in decoded
    assert ledger['historical_contracts'][2]['status'] == '部分分析'
    assert all(x['status'] == '完整局部分析' for x in ledger['functions'])
    if args.show:
        lo, hi = (int(s, 0) for s in args.show)
        print('\n'.join(f'{ea:#x}: {ins.mnemonic} {ins.op_str}' for ea, ins in sorted(decoded.items()) if lo <= ea < hi))
        return
    anchors = {
        0x6DFA1E: ('push', '0x6053f6'), 0x6DFA23: ('push', '0x64'),
        0x6DFA25: ('push', '0xc'), 0x6DFA2B: ('call', '0x607e5d'),
        0x6D76D1: ('mov', 'dword ptr [eax + 8], 0xffffffff'),
        0x6D76DB: ('mov', 'dword ptr [ecx + 4], 0xffffffff'),
        0x6D76E5: ('mov', 'dword ptr [edx], 0xffffffff'),
        0x6D7C11: ('mov', 'dword ptr [eax], 0'),
        0x6D7C1A: ('mov', 'dword ptr [ecx + 4], 0'),
        0x6D7C4A: ('cmp', 'dword ptr [eax + 4], 0'),
        0x6D7C4E: ('je', '0x6d7c6f'), 0x6D7C5D: ('call', '0x601cd3'),
        0x6D7C68: ('mov', 'dword ptr [ecx + 4], 0'),
        0x6DFD21: ('mov', 'ecx, dword ptr [eax + 8]'),
        0x6DFD24: ('sub', 'ecx, 1'), 0x6DFD2A: ('mov', 'dword ptr [edx + 8], ecx'),
        0x6DFD38: ('mov', 'eax, dword ptr [eax + ecx*4]'),
        0x6D7DEC: ('add', 'ecx, 0x3abfc'), 0x6D7DF2: ('call', '0x60906e'),
        0x6D8039: ('add', 'ecx, 0x3abfc'), 0x6D803F: ('call', '0x612b5f'),
        0x622D57: ('sub', 'eax, 1'), 0x622D5D: ('js', '0x622d79'),
        0x622D64: ('call', 'dword ptr [ebp + 0x14]'),
        0x622D71: ('add', 'ecx, dword ptr [ebp + 0xc]'), 0x622D82: ('ret', '0x10'),
        0x6DA215: ('mov', 'dword ptr [ebp - 0x1c], 0'),
        0x6DA23E: ('push', '0xa23ef4'), 0x6DA264: ('test', 'eax, eax'),
        0x6DA266: ('jne', '0x6da26a'), 0x6DA268: ('jmp', '0x6da281'),
        0x6DA273: ('add', 'edx, 1'),
        0x6DA279: ('mov', 'dword ptr [eax + 0x3abfc], edx'),
        0x6DA284: ('cmp', 'dword ptr [ecx + 0x3abfc], 0'),
        0x6DA28B: ('jle', '0x6da31c'), 0x6DA2A6: ('imul', 'ecx, ecx, 0x4b0'),
        0x6DA2BF: ('cmp', 'dword ptr [ebp - 0x308], 0'),
        0x6DA2C6: ('je', '0x6da2f3'), 0x6DA2C8: ('push', '0x601b20'),
        0x6DA2D4: ('push', '0x4b0'), 0x6DA2E0: ('call', '0x607e5d'),
        0x6DA2F3: ('mov', 'dword ptr [ebp - 0x370], 0'),
        0x6DA316: ('mov', 'dword ptr [eax + 0x3ac00], ecx'),
        0x6DA334: ('cmp', 'ecx, dword ptr [eax + 0x3abfc]'),
        0x6DA33A: ('jge', '0x6da468'), 0x6DA361: ('cmp', 'dword ptr [ebp - 0x20], 0x64'),
        0x6DA365: ('jge', '0x6da463'), 0x6DA373: ('push', '0xa23f00'),
        0x6DA399: ('test', 'eax, eax'), 0x6DA39B: ('jne', '0x6da3a2'),
        0x6DA39D: ('jmp', '0x6da463'), 0x6DA3A2: ('push', '0xa23f0c'),
        0x6DA3AD: ('call', '0x609528'), 0x6DA3B2: ('push', '0x80'),
        0x6DA3C4: ('call', '0x60fde2'), 0x6DA3D0: ('call', '0x60c813'),
        0x6DA3DB: ('imul', 'ecx, ecx, 0x4b0'), 0x6DA3ED: ('imul', 'edx, edx, 0xc'),
        0x6DA3F0: ('mov', 'dword ptr [ecx + edx], eax'),
        0x6DA3F6: ('add', 'ecx, 0x40'), 0x6DA3F9: ('call', '0x601896'),
        0x6DA416: ('mov', 'dword ptr [ecx + edx + 4], eax'),
        0x6DA450: ('mov', 'eax, dword ptr [eax + ecx + 4]'),
        0x6DA457: ('mov', 'dword ptr [ecx + eax*4 + 0x580cc], edx'),
        0x6DA463: ('jmp', '0x6da325'),
        0x6DBA10: ('mov', 'edx, dword ptr [ecx + 0x3ac00]'),
        0x6DBA19: ('imul', 'eax, eax, 0xc'),
        0x6DBA1C: ('cmp', 'dword ptr [edx + eax + 0x12c4], -1'),
        0x6DBABD: ('cmp', 'dword ptr [ebp + 0xc], 0'),
        0x6DBAC9: ('cmp', 'ecx, dword ptr [eax + 0x3abfc]'),
        0x6DBAD1: ('cmp', 'dword ptr [ebp + 0x10], 0'),
        0x6DBAD7: ('cmp', 'dword ptr [ebp + 0x10], 0x64'),
        0x6DBAE0: ('imul', 'edx, edx, 0x4b0'),
        0x6DBAE9: ('add', 'edx, dword ptr [eax + 0x3ac00]'),
        0x6DBAF2: ('imul', 'ecx, ecx, 0xc'),
        0x6DBAF5: ('mov', 'edx, dword ptr [edx + ecx + 4]'),
    }
    for ea, expected in anchors.items():
        assert (decoded[ea].mnemonic, decoded[ea].op_str) == expected, (hex(ea), decoded[ea].op_str)
    counts['semantic_anchors'] = len(anchors)
    # 独立执行器只支持这六个短函数用到的指令，不加载、不运行客户端。
    # 存储映射故意在越界地址缺项时抛错；空池测试显式提供 pool[-1]，仅证明实际访问。
    def simulate(entry, fields, pool=None):
        regs = dict(eax=0, ecx=0x200000, edx=0, ebp=0, esp=0x100000)
        memory = {0x200000 + off: value & 0xffffffff for off, value in fields.items()}
        memory[0x100000] = 0xBAD000
        if pool:
            memory.update(pool)
        calls, writes = [], []
        equal = False
        def address(op):
            return (regs.get(decoder.reg_name(op.mem.base), 0) +
                regs.get(decoder.reg_name(op.mem.index), 0) * op.mem.scale + op.mem.disp) & 0xffffffff
        def read(op):
            if op.type == X86_OP_IMM:
                return op.imm & 0xffffffff
            if op.type == X86_OP_REG:
                return regs[decoder.reg_name(op.reg)]
            assert op.type == X86_OP_MEM and op.size == 4
            return memory[address(op)]
        def write(op, value):
            value &= 0xffffffff
            if op.type == X86_OP_REG:
                regs[decoder.reg_name(op.reg)] = value
            else:
                assert op.type == X86_OP_MEM and op.size == 4
                where = address(op)
                memory[where] = value
                writes.append(where)
        pc = entry
        for _ in range(200):
            ins = decoded[pc]
            op = ins.operands
            next_pc = pc + ins.size
            if ins.mnemonic == 'push':
                value = read(op[0]); regs['esp'] -= 4; memory[regs['esp']] = value
            elif ins.mnemonic == 'pop':
                write(op[0], memory[regs['esp']]); regs['esp'] += 4
            elif ins.mnemonic == 'mov':
                write(op[0], read(op[1]))
            elif ins.mnemonic in ('add', 'sub'):
                a, b = read(op[0]), read(op[1])
                write(op[0], a + b if ins.mnemonic == 'add' else a - b)
            elif ins.mnemonic == 'cmp':
                equal = read(op[0]) == read(op[1])
            elif ins.mnemonic == 'je':
                if equal: next_pc = read(op[0])
            elif ins.mnemonic == 'call':
                target = read(op[0])
                if target == 0x60B576:
                    pass  # RTC 通道按正常返回契约建模，非重审运行库。
                elif target == 0x601CD3:
                    calls.append(('delete', memory[regs['esp']]))
                elif target == 0x607E5D:
                    arguments = [memory[regs['esp'] + j * 4] for j in range(4)]
                    calls.append(('vector', arguments))
                    regs['esp'] += 16
                elif target == 0x6044EC:
                    # 进入已核机器码的 pool pop，并由原 ret 回到 wrapper。
                    regs['esp'] -= 4; memory[regs['esp']] = next_pc; next_pc = 0x6DFD10
                else:
                    raise AssertionError(hex(target))
            elif ins.mnemonic == 'ret':
                next_pc = memory[regs['esp']]; regs['esp'] += 4
                if next_pc == 0xBAD000:
                    return regs, memory, calls, writes
            else:
                raise AssertionError((hex(pc), ins.mnemonic))
            pc = next_pc
        raise AssertionError('短函数执行步数越界')
    cases = 0
    for initial in (0, 1, 0x87654321):
        fields = {-4: 0x1234, 0: initial, 4: initial, 8: initial, 12: 0x5678}
        regs, memory, calls, writes = simulate(0x6D76C0, fields)
        assert [memory[0x200000 + k] for k in (0, 4, 8)] == [0xffffffff] * 3
        assert memory[0x1ffffc] == 0x1234 and memory[0x20000c] == 0x5678
        assert regs['eax'] == 0x200000 and not calls
        regs, memory, calls, writes = simulate(0x6D7C00, fields)
        assert [memory[0x200000 + k] for k in (0, 4)] == [0, 0]
        assert memory[0x200008] == initial and regs['eax'] == 0x200000
        cases += 2
    for count in (0, 1, 0xffffffff):
        for ptr in (0, 0x300000):
            regs, memory, calls, writes = simulate(0x6D7C30, {0: count, 4: ptr, 8: 0x9876})
            assert memory[0x200000] == count and memory[0x200004] == 0 and memory[0x200008] == 0x9876
            assert calls == ([('delete', ptr)] if ptr else [])
            cases += 1
    for count in (0, 1, 3):
        for entry in (0x6DFD10, 0x6D7660):
            index = (count - 1) & 0xffffffff
            access = (0x300000 + 4 * index) & 0xffffffff
            regs, memory, calls, writes = simulate(entry, {0: 0x300000, 4: 0x9999, 8: count}, {access: 0x4567})
            assert regs['eax'] == 0x4567 and memory[0x200008] == index
            assert memory[0x200004] == 0x9999 and not calls
            cases += 1
    regs, memory, calls, writes = simulate(0x6DFA10, {0: 0x1234})
    assert calls == [('vector', [0x200000, 12, 100, 0x6053F6])]
    assert regs['eax'] == 0x200000 and memory[0x200000] == 0x1234
    cases += 1
    counts['finite_instruction_cases'] = cases
    # 用原包逐行重建节与项，不调用作者 resource_audit.inspect。
    import lzokay
    package = (ROOT / 'Tex/other.dat').read_bytes()
    assert hashlib.sha256(package).hexdigest() == 'cce42c1439edfc1aa3e0a0c6ec7437b35628523dc2c70212a60bef68de0fe6e6'
    key = package[0]
    decoded_package = bytes((v - key) & 255 for v in package[1:])
    plain_size, packed_size = struct.unpack_from('<II', decoded_package)
    assert key == 120 and packed_size == 54826 and len(package) == 54835 and plain_size == 169979
    plain = lzokay.decompress(decoded_package[8:], plain_size)
    assert len(plain) == plain_size and hashlib.sha256(plain).hexdigest() == '84ebfcf29879012389c86aa9dcb14cbcc3d0a8bdd1bc3ba20d54732ac5ecde04'
    assert plain.decode('cp950').encode('cp950') == plain
    resource = load(HERE / 'resource_audit.json')
    assert resource['source'] == 'Tex/other.dat' and resource['source_sha256'] == hashlib.sha256(package).hexdigest()
    assert resource['key'] == key and resource['packed_bytes'] == packed_size and resource['plain_bytes'] == plain_size
    assert resource['plain_sha256'] == hashlib.sha256(plain).hexdigest()
    source_lines, line_offsets, cursor = [], [], 0
    for line in plain.splitlines(keepends=True):
        source_lines.append(line.rstrip(b'\r\n'))
        line_offsets.append(cursor)
        cursor += len(line)
    assert cursor == plain_size
    parsed_sections, active, parsed_entries = {}, None, 0
    for number, line in enumerate(source_lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(b'//'):
            continue
        if stripped.startswith(b'['):
            assert stripped.endswith(b']')
            name = stripped[1:-1].decode('ascii')
            assert name not in parsed_sections
            active = dict(name=name, line=number, offset=line_offsets[number - 1], raw_hex=line.hex(), entries=[])
            parsed_sections[name] = active
        else:
            assert active is not None and b'=' in line
            name, value = line.split(b'=', 1)
            active['entries'].append(dict(key=name.strip().decode('ascii'), value=value.strip().decode('cp950'),
                line=number, offset=line_offsets[number - 1], raw_hex=line.hex()))
            parsed_entries += 1
    assert resource['sections'] == list(parsed_sections.values())
    groups = sorted(int(name[6:]) for name in parsed_sections if name.startswith('OTHER_'))
    assert groups == list(range(76)) and resource['group_count'] == 76 and resource['group_allocation_bytes'] == 91200
    expected_records = []
    total = 0
    for group in groups:
        indices = sorted(int(m.group(1)) for name in parsed_sections
            if (m := re.fullmatch('O_' + str(group) + '_S_([0-9]+)', name)))
        assert indices == list(range(len(indices))) and len(indices) <= 100
        items = []
        for index in indices:
            section = parsed_sections[f'O_{group}_S_{index}']
            fields = {entry['key']: entry for entry in section['entries']}
            assert len(fields) == len(section['entries']) and re.fullmatch('-?[0-9]+', fields['npid']['value'])
            value = fields['npid']
            items.append(dict(index=index, npid=int(value['value']), source_line=value['line'], source_offset=value['offset']))
        expected_records.append(dict(group=group, loaded_prefix_count=len(indices), configured_indices=indices,
                                     ignored_after_gap_or_limit=[], items=items))
        total += len(indices)
    assert resource['groups'] == expected_records and total == 6575 and len(parsed_sections) == 6651
    assert expected_records[4]['loaded_prefix_count'] == 39
    assert (expected_records[4]['items'][0]['npid'], expected_records[4]['items'][-1]['npid']) == (13396, 16034)
    assert expected_records[47]['loaded_prefix_count'] == 100
    counts.update(resource_sections=len(parsed_sections), resource_entries=parsed_entries, resource_groups=76, resource_items=total)
    # 只把 other.dat 文件名作为当前磁盘观察；不伪造 IDA 字符串声明。
    assert decoded[0x6DA1A1].mnemonic == 'push' and decoded[0x6DA1A1].operands[0].imm == 0xA23EE0
    assert disk(0xA23EE0, 10) == b'other.dat\0'
    for path in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    author_files = sorted(p for p in TOPIC.rglob('*') if p.is_file() and '__pycache__' not in p.parts
        and not p.name.startswith('independent_') and p.name != '独立审阅结论.txt')
    final_bindings = {p.relative_to(TOPIC).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in author_files}
    final_bindings['证据/独立审阅结论.txt'] = hashlib.sha256((HERE / '独立审阅结论.txt').read_bytes()).hexdigest()
    final_bindings['证据/independent_review.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    binding_path = HERE / 'independent_final_bindings.json'
    if args.freeze:
        assert not binding_path.exists(), '禁止重写冻结指纹'
        binding_path.write_text(json.dumps(final_bindings, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.final or args.freeze:
        assert json.loads(binding_path.read_text(encoding='utf-8')) == final_bindings, '终稿发生变化，必须重新人工审阅'
    result = dict(status='EVIDENCE_PASS', disk_sha256=PE_SHA,
        full_idb_identity_claimed=False, counts=counts,
        unique_byte_ranges=len(ranges), source_hashes=hashes,
        limitations=['未执行游戏；未知运行时池容量与归还生命周期',
                     '旧 loader 机械全块核验不等于全函数业务审阅'])
    output = HERE / 'independent_evidence_validation.json'
    if args.final or args.freeze:
        result.update(status='PASS', author_final_files=len(author_files), final_bindings=final_bindings)
        output = HERE / 'independent_validation.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
