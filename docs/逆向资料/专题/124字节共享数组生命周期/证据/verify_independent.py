"""独立核当前 PE、完整块及共享数组局部生命周期，不导入作者脚本。"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '9975b7054c435b35bb53826528b218f80c43c5852d80876adba4d98e460ec28d'
SUPPLEMENT_SHA = 'ddbf83a1e09e062ebaf5dbe06e6418c5ae02b55cd723f0219d6fc93d91eda0b2'
SUPPLEMENT = {0x6B7C60, 0x6A76E0, 0x6B9AF0, 0x6A1190}
FRESH = {0x6A4A80, 0x6A4860, 0x6B7CB0}
OLD = {0x69E600, 0x6AB5F0}
FIXED = (
    ('邮件与礼物分组/证据/functions.json', '/functions/1', 0x69E600,
     '12d7ba17dc41cfcacc096c4bd24793fe59606f4dbc9ddc34354f4ec1d4fb30f4'),
    ('游戏时间与计时调度/证据/functions.json', '/functions/5', 0x6AB5F0,
     'ddebd0cf95aef329a7749e27aad8bf6f968029e50df18d0b7b092b28113d964b'),
    ('TeachMode状态与序号来源/证据/producers_raw.json', '/functions/0', 0x69DF50,
     '06cc3158681987faa7b122997b9435bde2d2f851d462e9e22fc32aa56635661c'),
    ('TeachMode状态与序号来源/证据/closure_raw.json', '/functions/0', 0x628270,
     'de7cbac38a2508db330f6fba2de59879c2a734ac55d737377fa06ea59f7f8a97'),
    ('MapView配置记录与预览消费/证据/functions_raw.json', '/functions/0', 0x622D50,
     '027d4e07571910bece1b5348be77dcbd940f59b606a8097bc6290e95e06f2101'),
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pointer(node, path):
    for token in path.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def verify(preflight=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 4)[0] == 0x14C
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    saved, sites, sources, bodies = {}, {}, {}, {}

    def disk(va, size):
        positions = [off + va - base - rva for _, rva, length, off in sections
                     if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(positions) == 1, (hex(va), size)
        data = image[positions[0]:positions[0] + size]
        assert len(data) == size
        return data

    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        data = disk(va, row['size'])
        assert data.hex() == row['disk_hex'] == row['idb_hex'], hex(va)
        assert row['matching'] is True
        digest = hashlib.sha256(data).hexdigest()
        if 'sha256' in row:
            assert digest == row['sha256'], hex(va)
        saved[(va, len(data))] = digest
        return data

    def decode(row):
        va = int(row.get('start_va', row.get('va')), 16)
        data = audit(row)
        decoded = list(cs.disasm(data, va))
        cursor = va
        for instruction in decoded:
            assert instruction.address == cursor
            cursor += instruction.size
            sites[instruction.address] = instruction
        assert cursor == va + len(data), hex(va)
        return decoded

    def recursive(node):
        if isinstance(node, dict):
            if 'idb_hex' in node and 'size' in node and ('va' in node or 'start_va' in node):
                audit(node)
            for value in node.values():
                recursive(value)
        elif isinstance(node, list):
            for value in node:
                recursive(value)

    def source(ref, origin):
        path = (origin / ref['path']).resolve()
        assert path.is_relative_to(DOCS.resolve())
        digest = ref.get('sha256', ref.get('source_sha256'))
        assert sha(path) == digest, str(path)
        sources[str(path.relative_to(DOCS)).replace('\\', '/')] = digest
        data = json.loads(path.read_bytes())
        location = ref.get('pointer', ref.get('json_pointer', ''))
        return pointer(data, location) if location else data

    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    callback = json.loads((HERE / 'callback_bridge.json').read_bytes())
    assert sha(HERE / 'bounded_raw.json') == RAW_SHA
    assert raw['disk_sha256'] == callback['disk_sha256'] == EXPECTED
    assert sha(TOPIC.parent / '四类型辅助请求与队列/证据/export_preparation_core.py') == raw['exporter_sha256']
    assert {int(r['seed_va'], 16) for r in raw['seeds']} == FRESH | OLD
    assert {int(r['seed_va'], 16) for r in raw['functions']} == FRESH
    assert {int(r['seed_va'], 16) for r in raw['reused_seeds']} == OLD
    for node in (raw, callback):
        recursive(node)
    fixed = {}
    for name, loc, va, digest in FIXED:
        record = source(dict(path='专题/' + name, sha256=digest, pointer=loc), DOCS)
        assert int(record['va'], 16) == va
        fixed[va] = record
        recursive(record)
        decoded = [i for block in record['chunk_byte_ranges'] for i in decode(block)]
        assert [i.address for i in decoded] == [int(a['va'], 16) for a in record['assembly']]
        bodies[va] = decoded
    for ref in raw['reuse_sources']:
        source(ref, DOCS)
    audits = {r['seed_va']: r['chunk_byte_ranges'] for r in raw['current_chunk_audits']}
    measurements, fresh_ranges = [], []
    for function in raw['functions'] + [fixed[v] for v in sorted(OLD)]:
        va = function.get('seed_va', function.get('va'))
        chunks = function['chunk_byte_ranges']
        assert len(chunks) == len(audits[va])
        for actual, declared in zip(audits[va], chunks):
            assert int(actual['start_va'], 16) == int(declared.get('start_va', declared.get('va')), 16)
            assert actual['size'] == declared['size'] and actual['disk_hex'] == declared['disk_hex']
        decoded = [i for block in chunks for i in decode(block)]
        assert [i.address for i in decoded] == [int(a.get('site_va', a.get('va')), 16)
                                               for a in function['assembly']]
        assert all(a.get('is_code', True) for a in function['assembly'])
        bodies[int(va, 16)] = decoded
        fresh = int(va, 16) in FRESH
        if fresh:
            fresh_ranges.extend((int(c['start_va'], 16), c['size']) for c in chunks)
        measurements.append(dict(va=va, fresh=fresh, bytes=sum(c['size'] for c in chunks),
                                 instructions=len(decoded)))
    assert sum(size for _, size in fresh_ranges) == 1411
    for a, b in zip(sorted(fresh_ranges), sorted(fresh_ranges)[1:]):
        assert a[0] + a[1] <= b[0]
    bridges = {}
    for row in raw['verified_direct_bridges'] + callback['bridges']:
        va = int(row['start_va'], 16)
        data = audit(row)
        target = int(row['target_va'], 16)
        assert len(data) == 5 and data[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        assert va not in bridges or bridges[va] == target
        bridges[va] = target
    assert callback['seed_va'] == '0x60d34e' and callback['endpoint_seed_va'] == '0x6b7c60'
    assert len(callback['bridges']) == 1 and bridges[0x60D34E] == 0x6B7C60
    for call in raw['calls']:
        instruction = sites[int(call['site_va'], 16)]
        assert instruction.mnemonic in ('call', 'jmp'), (call['site_va'], instruction.mnemonic)
        operand = instruction.operands[0]
        if operand.type == CS_OP_IMM:
            target = operand.imm & 0xFFFFFFFF
        else:
            assert operand.type == CS_OP_MEM and not operand.mem.base and not operand.mem.index
            target = operand.mem.disp & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert target == int(bridge, 16)
            target = bridges[target]
        assert target == int(call['implementation_va'], 16)
    assert len(raw['calls']) == 85
    for ref in raw['data_references']:
        instruction = sites[int(ref['site_va'], 16)]
        values = [(op.imm & 0xFFFFFFFF) for op in instruction.operands if op.type == CS_OP_IMM]
        values += [(op.mem.disp & 0xFFFFFFFF) for op in instruction.operands if op.type == CS_OP_MEM]
        assert int(ref['target_va'], 16) in values
    assert len(raw['data_references']) == 6 and not raw['strings'] and not raw['data_windows']
    windows = raw['explicit_owner_windows'] + [r['owner_window'] for rows in raw['incoming'].values()
                                              for r in rows if 'owner_window' in r]
    window_heads = 0
    for window in windows:
        addresses = []
        assert len(window['assembly']) <= 11
        for row in window['assembly']:
            instruction, = decode(row['bytes'])
            assert instruction.address == int(row['site_va'], 16)
            addresses.append(instruction.address)
            window_heads += 1
        assert addresses == sorted(set(addresses)) and int(window['site_va'], 16) in addresses

    result = dict(schema='richonline-independent-shared-array-lifecycle-1',
                  result='PRECHECK_ONLY' if preflight else 'PASS', disk_sha256=EXPECTED,
                  raw_sha256=RAW_SHA, functions=measurements, unique_byte_records=len(saved),
                  unique_bridges=len(bridges), calls=len(raw['calls']),
                  data_references=len(raw['data_references']), owner_window_heads=window_heads,
                  sources=sources)
    supplement = json.loads((HERE / 'supplement_raw.json').read_bytes())
    assert sha(HERE / 'supplement_raw.json') == SUPPLEMENT_SHA
    assert supplement['disk_sha256'] == EXPECTED
    assert sha(DOCS / '全量分析/export_supplements25.py') == supplement['exporter_sha256']
    assert {int(v, 16) for v in supplement['seeds']} == SUPPLEMENT
    assert {int(f['seed_va'], 16) for f in supplement['functions']} == SUPPLEMENT
    supplement_measurements = []
    for function in supplement['functions']:
        va = int(function['seed_va'], 16)
        decoded = [i for block in function['chunk_byte_ranges'] for i in decode(block)]
        assert [i.address for i in decoded] == [int(a['site_va'], 16) for a in function['assembly']]
        assert all(a['is_code'] for a in function['assembly'])
        bodies[va] = decoded
        supplement_measurements.append(dict(va=hex(va), bytes=sum(i.size for i in decoded),
                                            instructions=len(decoded)))
    for row in supplement['verified_direct_bridges']:
        va = int(row['start_va'], 16)
        data = audit(row)
        target = int(row['target_va'], 16)
        assert len(data) == 5 and data[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        assert va not in bridges or bridges[va] == target
        bridges[va] = target
    for call in supplement['calls']:
        instruction = sites[int(call['site_va'], 16)]
        assert instruction.mnemonic == 'call' and instruction.operands[0].type == CS_OP_IMM
        target = instruction.operands[0].imm & 0xFFFFFFFF
        assert target == int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert target == int(bridge, 16)
            target = bridges[target]
        assert target == int(call['implementation_va'], 16)
    assert len(supplement['calls']) == 12
    assert len(supplement['verified_direct_bridges']) == 5
    assert not supplement['data_references'] and not supplement['data_windows']
    assert [(r['bytes'], r['instructions']) for r in supplement_measurements] == [
        (52, 17), (356, 87), (36, 13), (69, 18)]
    result.update(supplement_sha256=SUPPLEMENT_SHA, supplement_functions=supplement_measurements,
                  supplement_calls=12, supplement_unique_bridges=5)
    if preflight:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return result
    formal = json.loads((HERE / 'formal_functions.json').read_bytes())
    reused = json.loads((HERE / 'reused_raw.json').read_bytes())
    review = json.loads((TOPIC / 'function_review.json').read_bytes())
    assert formal['disk_sha256'] == review['disk_sha256'] == EXPECTED
    assert formal['source_sha256'] == RAW_SHA
    assert len(formal['functions']) == 3
    for n, (f, g) in enumerate(zip(raw['functions'], formal['functions'])):
        assert g['source'] == dict(path='证据/bounded_raw.json', sha256=RAW_SHA,
                                   json_pointer='/functions/' + str(n))
        assert g['va'] == f['seed_va'] and g['end_va'] == f['end_va']
        assert all(g[k] == f[k] for k in ('name', 'pseudocode', 'decompile_error'))
        assert g['assembly'] == [dict(va=a['site_va'], text=a['text'], is_code=a['is_code'])
                                 for a in f['assembly']]
        assert g['chunk_byte_ranges'] == [dict(va=b['start_va'], **{k: v for k, v in b.items()
                                           if k != 'start_va'}) for b in f['chunk_byte_ranges']]
        assert g['declared_chunks'] == [dict(start_va=b['start_va'],
                                             end_va=hex(int(b['start_va'], 16) + b['size']),
                                             is_main=b['start_va'] == f['seed_va'])
                                        for b in f['chunk_byte_ranges']]
    assert len(reused['records']) == len(review['reused']) == 14
    supplement_formal = json.loads((HERE / 'supplement_formal.json').read_bytes())
    assert supplement_formal['disk_sha256'] == EXPECTED
    assert supplement_formal['source_sha256'] == SUPPLEMENT_SHA
    assert len(supplement_formal['functions']) == 4
    for n, (f, g) in enumerate(zip(supplement['functions'], supplement_formal['functions'])):
        assert g['source'] == dict(path='证据/supplement_raw.json', sha256=SUPPLEMENT_SHA,
                                   json_pointer='/functions/' + str(n))
        assert g['va'] == f['seed_va'] and g['end_va'] == f['end_va']
        assert all(g[k] == f[k] for k in ('name', 'pseudocode', 'decompile_error'))
        assert g['assembly'] == [dict(va=a['site_va'], text=a['text'], is_code=a['is_code'])
                                 for a in f['assembly']]
        assert g['chunk_byte_ranges'] == [dict(va=b['start_va'], **{k: v for k, v in b.items()
                                           if k != 'start_va'}) for b in f['chunk_byte_ranges']]
        assert g['declared_chunks'] == [dict(start_va=b['start_va'],
                                             end_va=hex(int(b['start_va'], 16) + b['size']),
                                             is_main=b['start_va'] == f['seed_va'])
                                        for b in f['chunk_byte_ranges']]
    old_records = {}
    for row in reused['records']:
        original = source(row['source'], HERE)
        assert original == row['original_record']
        va = int(row['va'], 16)
        assert int(original['va'], 16) == va
        recursive(original)
        old_records[va] = original
        if 'chunk_byte_ranges' in original:
            decoded = [i for block in original['chunk_byte_ranges'] for i in decode(block)]
            assert [i.address for i in decoded] == [int(a['va'], 16) for a in original['assembly']]
            bodies[va] = decoded
        elif va == 0x91F7E0:
            decoded = []
            for block in original['chunks']:
                assert block['equal'] is True and block['ida_hex'] == block['disk_hex']
                adapted = dict(block, idb_hex=block['ida_hex'], matching=block['equal'])
                decoded.extend(decode(adapted))
            assert [i.address for i in decoded] == [int(a['va'], 16) for a in original['instructions']]
            bodies[va] = decoded
        else:
            assert va == 0x6A1190 and all(isinstance(a, str) for a in original['assembly'])
            assert not any(k in original for k in ('chunks', 'chunk_byte_ranges', 'declared_chunks'))
    assert {int(r['va'], 16) for r in review['functions']} == FRESH
    assert {int(r['va'], 16) for r in review['reused_reviews']} == OLD
    assert {int(r['va'], 16) for r in review['dependency_reviews']} == {
        0x622D50, 0x6A2350, 0x91BD80, 0x91BD30, 0x91F7E0}
    assert {int(r['va'], 16) for r in review['supplement_reviews']} == SUPPLEMENT
    anchors = 0
    for row in (review['functions'] + review['reused_reviews'] + review['dependency_reviews']
                + review['supplement_reviews']):
        assert row['status'] == '局部语义已审阅' and row['conclusion'] and row['unknown']
        assert row['fresh_evidence'] == (int(row['va'], 16) in FRESH | (SUPPLEMENT - {0x6A1190}))
        ref, = row['source_records']
        record = source(ref, TOPIC)
        chunks = record.get('declared_chunks', record.get('chunks'))
        ranges = record.get('chunk_byte_ranges', record.get('chunks'))
        assert row['declared_chunks'] == chunks and row['original_byte_ranges'] == ranges
        assembly = record.get('assembly', record.get('instructions'))
        assert len(row['anchors']) == len(assembly)
        for anchor, head in zip(row['anchors'], assembly):
            assert anchor['path'] == ref['path'] and anchor['pointer'].startswith(ref['pointer'] + '/')
            assert source(dict(ref, pointer=anchor['pointer']), TOPIC) == anchor['value'] == head['text']
            assert anchor['site_va'] == head['va'] and int(anchor['site_va'], 16) in sites
            anchors += 1
    assert anchors == 1077

    semantic = []

    def anchor(va, mnemonic, operands):
        instruction = sites[va]
        assert (instruction.mnemonic, instruction.op_str) == (mnemonic, operands), (
            hex(va), instruction.mnemonic, instruction.op_str)
        semantic.append(dict(va=hex(va), mnemonic=mnemonic, operands=operands,
                             disk_hex=instruction.bytes.hex()))

    checks = (
        (0x6A4AB3, 'call', '0x6118f9'), (0x6A4ABB, 'call', '0x603d7b'),
        (0x6A4AC3, 'mov', 'dword ptr [ecx + 0x5dc], eax'),
        (0x6A4ACC, 'mov', 'dword ptr [edx + 0x5e0], 0xffffffff'),
        (0x6A4AE5, 'imul', 'edx, edx, 0x7c'), (0x6A4AE9, 'call', '0x609997'),
        (0x6A4AF4, 'mov', 'dword ptr [ebp - 4], 0'),
        (0x6A4AFF, 'je', '0x6a4b1d'), (0x6A4B01, 'push', '0x60d34e'),
        (0x6A4B09, 'push', 'eax'), (0x6A4B0A, 'push', '0x7c'),
        (0x6A4B0F, 'push', 'ecx'), (0x6A4B10, 'call', '0x607e5d'),
        (0x6A4B2A, 'mov', 'dword ptr [ebp - 4], 0xffffffff'),
        (0x6A4B37, 'mov', 'dword ptr [ecx + 0x5d8], edx'),
        (0x6A4D76, 'jge', '0x6a4da6'), (0x6A4D7B, 'imul', 'ecx, ecx, 0x7c'),
        (0x6A4D8A, 'mov', 'dword ptr [ecx + eax], edx'),
        (0x6A4D9C, 'mov', 'dword ptr [edx + eax + 0x78], 0'),
        (0xA12079, 'mov', 'eax, dword ptr [ebp - 0x20]'),
        (0xA1207D, 'call', '0x601cd3'),
        (0x6B7CC1, 'mov', 'eax, dword ptr [eax + 0x4d0]'),
        (0x69E4CC, 'mov', 'dword ptr [ecx + 0x5f4], 0'),
        (0x69E50D, 'mov', 'dword ptr [eax + 0x608], 0'),
        (0x69E658, 'call', '0x6118f9'), (0x6AB62D, 'mov', 'ecx, dword ptr [ebp - 4]'),
        (0x6AB630, 'call', '0x607345'),
        (0x622D57, 'sub', 'eax, 1'), (0x622D5D, 'js', '0x622d79'),
        (0x622D61, 'mov', 'ecx, dword ptr [ebp + 8]'),
        (0x622D64, 'call', 'dword ptr [ebp + 0x14]'),
        (0x622D71, 'add', 'ecx, dword ptr [ebp + 0xc]'), (0x622D82, 'ret', '0x10'),
        (0x91BD87, 'call', '0x601274'), (0x91BD47, 'jne', '0x91bd60'),
        (0x91BD57, 'jne', '0x91bd5e'), (0x91BD5E, 'jmp', '0x91bd34'),
        (0x6B7C6E, 'mov', 'ecx, dword ptr [ebp - 4]'),
        (0x6B7C71, 'add', 'ecx, 8'), (0x6B7C74, 'call', '0x60a99b'),
        (0x6B7C7C, 'mov', 'dword ptr [eax + 4], 0'),
        (0x6B7C83, 'mov', 'eax, dword ptr [ebp - 4]'), (0x6B7C93, 'ret', ''),
        (0x6B9AFE, 'mov', 'ecx, dword ptr [ebp - 4]'),
        (0x6B9B01, 'call', '0x609bb8'), (0x6B9B13, 'ret', ''),
        (0x6A119E, 'call', '0x608024'),
        (0x6A11A6, 'mov', 'dword ptr [eax + 0x5e0], 0xffffffff'),
        (0x6A11B3, 'mov', 'dword ptr [ecx + 0x4f0], 0xffffffff'),
        (0x6A11C0, 'mov', 'byte ptr [edx + 0x258], 0'), (0x6A11D4, 'ret', ''),
    )
    for check in checks:
        anchor(*check)
    supplement_zeroes = []
    for instruction in bodies[0x6A76E0]:
        assert not any(op.type == CS_OP_MEM and op.mem.disp in (0x5F4, 0x608)
                       for op in instruction.operands)
        if (instruction.mnemonic == 'mov' and instruction.operands[0].type == CS_OP_MEM
                and instruction.operands[0].mem.disp >= 0x640):
            assert instruction.operands[0].size == 4
            assert instruction.operands[1].type == CS_OP_IMM and instruction.operands[1].imm == 0
            supplement_zeroes.append(instruction.operands[0].mem.disp)
    assert supplement_zeroes == list(range(0x640, 0x668, 4))
    for n in range(5):
        va = 0x6A771C + n * 0x31
        anchor(va, 'call', '0x601cd3')
        gate = sites[0x6A7703 + n * 0x31]
        assert gate.mnemonic == 'cmp' and gate.operands[0].type == CS_OP_MEM
        assert gate.operands[0].mem.disp == 0x640 + n * 4
        assert gate.operands[1].type == CS_OP_IMM and gate.operands[1].imm == 0
    assert bridges[0x60A99B] == 0x6B7BB0
    assert bridges[0x609BB8] == 0x6BA4A0 and bridges[0x608024] == 0x82C4E0
    alloc_fields = [0x5E4, 0x5E8, 0x5EC, 0x5F0, 0x5F4, 0x5F8,
                    0x5FC, 0x600, 0x604, 0x608, 0x60C]
    alloc_calls = [0x6A4B4A + 0x24 * i for i in range(11)]
    alloc_stores = [0x6A4B5B + 0x24 * i for i in range(11)]
    freed_fields = [0x5D8, 0x5E4, 0x5E8, 0x5EC, 0x5F0,
                    0x5F8, 0x5FC, 0x600, 0x604, 0x60C]
    free_calls = [0x6A4897 + 0x31 * i for i in range(10)]
    free_stores = [0x6A48A2 + 0x31 * i for i in range(10)]
    for index, (field, call, store) in enumerate(zip(alloc_fields, alloc_calls, alloc_stores)):
        shift = sites[call - 4]
        assert shift.mnemonic == 'shl' and shift.operands[1].imm == 2
        anchor(call, 'call', '0x609997')
        instruction = sites[store]
        assert instruction.mnemonic == 'mov' and instruction.operands[0].type == CS_OP_MEM
        assert instruction.operands[0].mem.disp == field and instruction.operands[0].size == 4
        assert instruction.operands[1].type != CS_OP_IMM
    for field, call, store in zip(freed_fields, free_calls, free_stores):
        anchor(call, 'call', '0x601cd3')
        instruction = sites[store]
        assert instruction.mnemonic == 'mov' and instruction.operands[0].type == CS_OP_MEM
        assert instruction.operands[0].mem.disp == field and instruction.operands[0].size == 4
        assert instruction.operands[1].type == CS_OP_IMM and instruction.operands[1].imm == 0
    assert set(alloc_fields) - set(freed_fields) == {0x5F4, 0x608}
    for instruction in bodies[0x6A4860]:
        assert not any(op.type == CS_OP_MEM and op.mem.disp in (0x5F4, 0x608, 0x5DC, 0x5E0)
                       for op in instruction.operands)
    count_stores = [(i.address, i.operands[0].mem.disp) for i in bodies[0x6A4A80]
                    if i.mnemonic == 'mov' and i.operands[0].type == CS_OP_MEM
                    and 0x610 <= i.operands[0].mem.disp <= 0x638]
    assert [field for _, field in count_stores] == list(range(0x610, 0x639, 4))
    assert 0xFFFFFFFF // 124 == 34636833
    assert ((0x80000000 - 1) & 0xFFFFFFFF) == 0x7FFFFFFF
    # 旧薄包装的局部桥另核，原证准备批33桥计量保持独立。
    contract_bridges = []
    for va, target in ((0x601274, 0x91BD30),):
        data = disk(va, 5)
        assert data[0] == 0xE9 and va + 5 + struct.unpack_from('<i', data, 1)[0] == target
        contract_bridges.append(dict(va=hex(va), target=hex(target), disk_hex=data.hex()))
    auxiliary = json.loads((HERE / 'reused_auxiliary.json').read_bytes())
    aux, = auxiliary['records']
    original = source(aux['source'], HERE)
    assert original == aux['original_record']
    assert original['va'] == '0x601274' and original['target'] == '0x91bd30'
    assert audit(original).hex() == contract_bridges[0]['disk_hex']
    documents = {}
    for path in sorted(TOPIC.glob('*.txt')):
        text = path.read_text('utf-8-sig')
        assert all(not line.strip() or line.startswith('//') for line in text.splitlines()), str(path)
        documents[path.name] = sha(path)
    assert len(documents) == 8
    author = json.loads((HERE / 'author_validation.json').read_bytes())
    assert author['status'] == 'PASS' and author['disk_sha256'] == EXPECTED
    assert author['documents'] == documents
    assert (author['fresh_functions'], author['fresh_declared_bytes'],
            author['fresh_instruction_entries'], author['reviewed_instruction_anchors']) == (3, 1411, 370, 1077)
    assert (author['supplemental_functions'], author['supplemental_declared_bytes'],
            author['supplemental_instruction_entries']) == (4, 513, 135)
    assert (author['total_new_functions'], author['total_new_declared_bytes'],
            author['total_new_instruction_entries']) == (6, 1855, 487)
    assert len(saved) == author['unique_saved_ranges'] == 139
    assert len(bridges) + 1 == author['unique_verified_e9_bridges'] == 37
    result.update(reused_records=14, review_records=14, review_anchors=anchors,
                  semantic_anchors=semantic, allocation_fields=[hex(f) for f in alloc_fields],
                  free_fields=[hex(f) for f in freed_fields], local_unpaired_fields=['0x5f4', '0x608'],
                  contract_bridges=contract_bridges, final_documents=documents,
                  final_artifacts={name: sha(HERE / name) for name in (
                      'formal_functions.json', 'reused_raw.json', 'build_artifacts.py',
                      'validate_author.py', 'export_bounded.py', 'reused_auxiliary.json',
                      'author_validation.json', 'supplement_raw.json', 'supplement_formal.json')},
                  reused_auxiliary_records=1, total_verified_bridges=len(bridges) + 1,
                  final_unique_byte_records=len(saved),
                  review_sha256=sha(TOPIC / 'function_review.json'),
                  verifier_sha256=sha(Path(__file__)),
                  unknown=['6B7BB0/6BA4A0/82C4E0仅桥端点；根深清理及外部owner未闭合。',
                           '上游4D0值域、运行时异常行为、动态泄漏及网络可达性未验证。'])
    report = HERE / '独立审阅.txt'
    assert report.is_file(), '独立人工审阅报告尚未落盘'
    result['independent_report_sha256'] = sha(report)
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('sources', 'semantic_anchors',
                     'final_documents', 'final_artifacts')}, ensure_ascii=False, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--preflight', action='store_true')
    verify(parser.parse_args().preflight)
