"""基础边框与派生绘制独审：不访问IDA，当前PE与原证独立重解码。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs/逆向资料'
HERE = Path(__file__).resolve().parent
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'da3aa15cabf76aa2ee3a30600dca3691491d1dedd57b62c23398e3fdf5fc3fd2'
SEEDS = (0x8E41D0, 0x90C070, 0x902180, 0x90A430, 0x8E46E0)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def pointer(node, path):
    for part in path.strip('/').split('/'):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def authored_bundle(raw):
    """独立重建允许的适配字段，并把作者断言和逐指令锚绑定回原记录。"""
    topic = HERE.parent
    formal_path = HERE / 'formal_functions.json'
    formal = json.loads(formal_path.read_bytes())
    assert formal['schema'] == 'richonline-formal-bounded-adaptation-1'
    assert formal['disk_sha256'] == EXPECTED and formal['source_sha256'] == RAW_SHA
    assert len(formal['functions']) == 4
    for index, (adapted, original) in enumerate(zip(formal['functions'], raw['functions'])):
        ranges = [dict(va=block['start_va'], **{key:value for key,value in block.items()
                   if key != 'start_va'}) for block in original['chunk_byte_ranges']]
        expected = dict(va=original['seed_va'], end_va=original['end_va'], name=original['name'],
            status='机械适配；语义见function_review.json',
            assembly=[dict(va=line['site_va'], text=line['text'], is_code=line['is_code'])
                      for line in original['assembly']],
            pseudocode=original['pseudocode'], decompile_error=original['decompile_error'],
            declared_chunks=[dict(start_va=block['va'], end_va=hex(int(block['va'], 16)+block['size']),
                                  is_main=block['va'] == original['seed_va']) for block in ranges],
            chunk_byte_ranges=ranges, bytes_match_disk=all(block['matching'] is True for block in ranges),
            source=dict(path='证据/bounded_raw.json', sha256=RAW_SHA,
                        json_pointer='/functions/' + str(index)))
        assert adapted == expected, ('formal无损适配', index)
    reuse_path = HERE / 'reused_raw.json'
    reused = json.loads(reuse_path.read_bytes())
    assert reused['schema'] == 'richonline-exact-reused-records-1' and len(reused['records']) == 3
    origins = (
        ('../../控件回调与事件表/证据/基础消费者.json', '/functions/1', '0x8e46e0',
         'bed92071c520393edc61bc7e99edc66da79be25ea92ade749a848c0e7915f2e4'),
        ('../../文本宽度到字符位置/证据/width_position.json', '/functions/1', '0x924fc0',
         'c77307433a8d92f8f8ddf4d75751d306475c8c24fd44b509691290b6fd1933b6'),
        ('../../文本宽度到字符位置/证据/width_position.json', '/functions/4', '0x8e0a00',
         'c77307433a8d92f8f8ddf4d75751d306475c8c24fd44b509691290b6fd1933b6'))
    for record, (path, where, va, digest) in zip(reused['records'], origins):
        assert record['source'] == dict(path=path, sha256=digest, pointer=where)
        source_path = (HERE / path).resolve()
        assert source_path.is_relative_to(DOCS.resolve()) and sha(source_path.read_bytes()) == digest
        assert record['va'] == va and record['original_record'] == pointer(json.loads(source_path.read_bytes()), where)
    review_path = topic / 'function_review.json'
    review = json.loads(review_path.read_bytes())
    assert review['schema'] == 'richonline-function-review-1' and review['disk_sha256'] == EXPECTED
    assert len(review['functions']) == 4 and len(review['reused_reviews']) == 1
    expected_rows = [(row, '证据/formal_functions.json', '/functions/' + str(index), True,
                      '局部语义已审阅') for index,row in enumerate(formal['functions'])]
    expected_rows.append((reused['records'][0]['original_record'], '证据/reused_raw.json',
                          '/records/0/original_record', False, '部分分析'))
    anchor_count = 0
    for row, (source, path, where, fresh, status) in zip(review['functions']+review['reused_reviews'], expected_rows):
        assert row['va'] == source['va'] and row['name'] == source['name']
        assert row['fresh_evidence'] is fresh and row['status'] == status
        assert row['full_dependency_closure'] is False and row['unknown'] and row['conclusion']
        assert row['declared_chunks'] == source.get('declared_chunks', source.get('chunks', []))
        assert row['original_byte_ranges'] == source.get('chunk_byte_ranges', source.get('byte_ranges', []))
        assert row['source_records'] == [dict(path=path, sha256=sha((topic/path).read_bytes()), pointer=where)]
        expected_anchors = [dict(path=path, pointer=where+'/assembly/'+str(index)+'/text',
                                site_va=line['va'], value=line['text'])
                            for index,line in enumerate(source['assembly'])]
        assert row['anchors'] == expected_anchors
        anchor_count += len(expected_anchors)
    history_path = DOCS / '专题/控件回调与事件表/function_review.json'
    history = pointer(json.loads(history_path.read_bytes()), '/functions/17')
    assert history['va'] == '0x8e46e0' and history['review_status'] == '部分分析'
    docs = sorted(topic.glob('*.txt'))
    assert [path.name[:2] for path in docs] == ['00', '01', '02', '03', '04', '05', '06']
    assert all(not line.strip() or line.startswith('//') for path in docs
               for line in path.read_text(encoding='utf-8').splitlines())
    validation_path = HERE / 'author_validation.json'
    author = json.loads(validation_path.read_bytes())
    assert author['status'] == 'PASS' and author['disk_sha256'] == EXPECTED
    assert author['bounded_raw_sha256'] == RAW_SHA
    assert author['fresh_functions'] == 4 and author['fresh_declared_bytes'] == 4459
    assert author['fresh_instruction_entries'] == 1422 and author['reused_subject_reviews'] == 1
    assert author['reused_records'] == 3
    author_docs = {path.name:sha(path.read_bytes()) for path in docs if path.name[:2] != '06'}
    assert author['documents'] == author_docs
    artifacts = [formal_path, reuse_path, review_path, HERE/'build_artifacts.py',
                 HERE/'validate_author.py', validation_path, history_path]
    return dict(instruction_anchors=anchor_count, fresh_reviews=4, historical_partial_reviews=1,
                documents={path.name:sha(path.read_bytes()) for path in docs},
                artifacts={str(path.relative_to(DOCS)).replace('\\', '/'):sha(path.read_bytes())
                           for path in artifacts}, final_supplements_bound=False)


def audit(final=False):
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert sha(image) == EXPECTED
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe+24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe+52)[0]
    section_at = pe + 24 + struct.unpack_from('<H', image, pe+20)[0]
    sections = [dict(name=image[section_at+i*40:section_at+i*40+8].rstrip(b'\0').decode('ascii'),
                     virtual_size=vsize, rva=rva, raw_size=count, raw_offset=off)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])
                for vsize, rva, count, off in [struct.unpack_from('<4I', image, section_at+i*40+8)]]

    def read(va, size):
        matches = [s for s in sections if s['rva'] <= va-base and
                   va-base+size <= s['rva']+s['raw_size']]
        assert len(matches) == 1, (hex(va), size)
        s = matches[0]
        offset = s['raw_offset'] + va-base-s['rva']
        blob = image[offset:offset+size]
        assert len(blob) == size
        return blob

    def bridge(va):
        blob = read(va, 5)
        assert blob[0] == 0xE9
        return va + 5 + struct.unpack_from('<i', blob, 1)[0]

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    count = 0

    def walk(node):
        nonlocal count
        if isinstance(node, dict):
            payload = node.get('idb_hex', node.get('ida_hex'))
            if payload is not None and node.get('disk_hex') is not None:
                va = int(node.get('start_va', node.get('va')), 16)
                blob = bytes.fromhex(payload)
                assert len(blob) == node['size']
                assert blob == bytes.fromhex(node['disk_hex']) == read(va, len(blob))
                assert node.get('matching', node.get('equal')) is True
                if node.get('sha256'):
                    assert sha(blob) == node['sha256']
                count += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    raw_path = HERE / 'bounded_raw.json'
    assert sha(raw_path.read_bytes()) == RAW_SHA
    raw = json.loads(raw_path.read_bytes())
    assert raw['schema'] == 'richonline-bounded-preparation-1' and raw['disk_sha256'] == EXPECTED
    assert tuple(int(s['seed_va'], 16) for s in raw['seeds']) == SEEDS
    assert tuple(int(f['seed_va'], 16) for f in raw['functions']) == SEEDS[:4]
    walk(raw)
    transcript = ['// 当前PE独立重解码；原证调用窗不登记owner完整完成。']
    subjects, decoded, calls = [], {}, {}
    for row in raw['current_chunk_audits']:
        va = int(row['seed_va'], 16)
        instructions = []
        for block in row['chunk_byte_ranges']:
            chunk = list(decoder.disasm(bytes.fromhex(block['idb_hex']), int(block['start_va'], 16)))
            assert sum(i.size for i in chunk) == block['size']
            instructions.extend(chunk)
        assert len({i.address for i in instructions}) == len(instructions)
        decoded[va] = instructions
        transcript.append('// 主体 ' + hex(va))
        transcript.extend('// %08X %s %s %s' % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
                          for i in instructions)
        original = next((f for f in raw['functions'] if int(f['seed_va'], 16) == va), None)
        if original:
            assert original['chunk_byte_ranges'] == row['chunk_byte_ranges']
            assert {i.address for i in instructions} == {int(i['site_va'], 16)
                for i in original['assembly'] if i['is_code']}
        for i in instructions:
            if i.mnemonic == 'call' and i.operands[0].type == capstone.x86.X86_OP_IMM:
                calls[(va, i.address)] = i.operands[0].imm
        subjects.append(dict(va=hex(va), bytes=sum(b['size'] for b in row['chunk_byte_ranges']),
                             instructions=len(instructions), chunks=len(row['chunk_byte_ranges']),
                             origin='新主体' if va in SEEDS[:4] else '旧局部消费者完整字节重核'))
    assert tuple(decoded) == SEEDS
    assert calls == {(int(c['seed_va'], 16), int(c['site_va'], 16)):int(c['target_va'], 16)
                     for c in raw['calls']}
    for call in raw['calls']:
        target = int(call['target_va'], 16)
        for step in call['bridges']:
            assert target == int(step, 16)
            target = bridge(target)
        assert target == int(call['implementation_va'], 16)
    for row in raw['verified_direct_bridges']:
        assert row['size'] == 5
        assert bridge(int(row['start_va'], 16)) == int(row['target_va'], 16)
    windows, incoming = {}, []

    def window(row):
        owner, site = row['owner_va'], int(row['site_va'], 16)
        assert owner is not None and '完整' in row['pending_status']
        key = (owner, site)
        assert len(row['assembly']) <= 11
        addresses = []
        for instruction in row['assembly']:
            va, block = int(instruction['site_va'], 16), instruction['bytes']
            items = list(decoder.disasm(read(va, block['size']), va))
            assert len(items) == 1 and items[0].size == block['size']
            addresses.append(va)
        assert site in addresses and len(addresses) == len(set(addresses))
        if key in windows:
            assert windows[key] == row['assembly']
        windows[key] = row['assembly']

    for seed, entries in raw['incoming'].items():
        assert int(seed, 16) in SEEDS
        for row in entries:
            site, target = int(row['site_va'], 16), int(row['target_va'], 16)
            if row['is_code']:
                i = next(decoder.disasm(read(site, 5), site))
                assert i.mnemonic in ('call', 'jmp')
                assert i.operands[0].type == capstone.x86.X86_OP_IMM and i.operands[0].imm == target
            else:
                assert struct.unpack('<I', read(site, 4))[0] == target
            if row['verified_bridge']:
                assert bridge(site) == int(row['final_implementation_va'], 16)
            if row.get('owner_window'):
                window(row['owner_window'])
            incoming.append(dict(seed_va=seed, site_va=row['site_va'], is_code=row['is_code']))
    assert len(raw['explicit_owner_windows']) == 9
    for row in raw['explicit_owner_windows']:
        window(row)
    sources = []
    for source in raw['reuse_sources']:
        path = (DOCS / source['path']).resolve()
        assert path.is_relative_to(DOCS.resolve()) and sha(path.read_bytes()) == source['source_sha256']
        sources.append(dict(path=source['path'], sha256=source['source_sha256']))
    old_path = DOCS / '专题/控件回调与事件表/证据/基础消费者.json'
    old = json.loads(old_path.read_bytes())['functions'][1]
    assert old['va'] == '0x8e46e0'
    walk(old)
    assert {int(i['va'], 16) for i in old['assembly']} == {i.address for i in decoded[0x8E46E0]}
    assert [(int(b['va'], 16), b['size'], b['disk_hex']) for b in old['byte_ranges']] == [
        (int(b['start_va'], 16), b['size'], b['disk_hex'])
        for b in raw['current_chunk_audits'][-1]['chunk_byte_ranges']]
    width_path = DOCS / '专题/文本宽度到字符位置/证据/width_position.json'
    width = json.loads(width_path.read_bytes())
    dependencies = []
    for index, va in ((1, 0x924FC0), (4, 0x8E0A00)):
        record = width['functions'][index]
        assert int(record['va'], 16) == va
        walk(record)
        instructions = []
        for block in record['chunks']:
            blob = bytes.fromhex(block['ida_hex'])
            items = list(decoder.disasm(blob, int(block['va'], 16)))
            assert sum(i.size for i in items) == len(blob)
            instructions.extend(items)
        assert {i.address for i in instructions} == {int(i['va'], 16) for i in record['instructions']}
        transcript.append('// 旧短辅助完整字节重核 ' + hex(va))
        transcript.extend('// %08X %s %s %s' % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
                          for i in instructions)
        if va == 0x8E0A00:
            locator = {i.address:i for i in instructions}
            assert [locator[site].operands[1].mem.disp - 12 for site in
                    (0x8E0A12, 0x8E0A1D, 0x8E0A21)] == [4, 8, 12]
            assert all(i.mnemonic != 'ret' or len(i.operands) == 0 for i in instructions)
            caller = {i.address:i for i in decoded[0x90C070]}
            assert caller[0x90C146].mnemonic == caller[0x90C7EA].mnemonic == 'push'
            assert caller[0x90C146].op_str == caller[0x90C7EA].op_str == 'ebx'
            assert caller[0x90C154].op_str == caller[0x90C7FC].op_str == 'esp, 0x10'
        dependencies.append(dict(va=hex(va), path=str(width_path.relative_to(DOCS)).replace('\\', '/'),
            sha256=sha(width_path.read_bytes()), json_pointer='/functions/' + str(index),
            bytes=sum(i.size for i in instructions), instructions=len(instructions),
            scope='仅旧短辅助字节和调用契约；不计新增或本批完整主体'))
    slot, = raw['data_windows']
    assert slot['start_va'] == '0xacc3c8' and slot['size'] == 4
    assert slot['disk_hex'] is None and slot['matching'] is None
    assert slot['idb_hex'] == 'ffffffff' and slot['sha256'] == sha(bytes.fromhex(slot['idb_hex']))
    assert not [s for s in sections if s['rva'] <= 0xACC3C8-base and
                0xACC3CC-base <= s['rva']+s['raw_size']]
    virtual, = [s for s in sections if s['rva'] <= 0xACC3C8-base and
                0xACC3CC-base <= s['rva']+s['virtual_size']]
    indirect = [dict(seed_va=hex(va), site_va=hex(i.address), operand=i.op_str, bytes=i.bytes.hex())
                for va, instructions in decoded.items() for i in instructions
                if i.mnemonic == 'call' and i.operands[0].type != capstone.x86.X86_OP_IMM]
    jump_blob = read(0x8E4330, 16)
    border = {i.address:i for i in decoded[0x8E41D0]}

    def border_model(args, callback_mask=(True,)*8):
        # 有限离线指令解释：只执行已核完整边框块，外部CALL仅记录实参并扰动易失寄存器。
        registers = {name:0 for name in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')}
        registers['esp'] = 0x20000000
        start_sp = registers['esp']
        memory = {start_sp:0xDEAD0000, 0xACC3C8:0x30000000}
        memory.update({start_sp+4*(i+1):value & 0xFFFFFFFF for i, value in enumerate(args)})
        memory.update({0x8E4330+4*i:value for i,value in enumerate(struct.unpack('<4I', jump_blob))})
        sites = (0x8E42AC, 0x8E42CD, 0x8E42F0, 0x8E430D)
        comparisons = (False, False)
        visits, output, pc, steps = [], [], 0x8E41D0, 0

        def address(operand):
            value = operand.mem.disp
            for register, scale in ((operand.mem.base, 1), (operand.mem.index, operand.mem.scale)):
                if register:
                    value += registers[border[pc].reg_name(register)] * scale
            return value & 0xFFFFFFFF

        def value(operand):
            if operand.type == capstone.x86.X86_OP_IMM:
                return operand.imm & 0xFFFFFFFF
            if operand.type == capstone.x86.X86_OP_REG:
                return registers[border[pc].reg_name(operand.reg)]
            assert operand.type == capstone.x86.X86_OP_MEM and operand.size == 4
            at = address(operand)
            if at == 0x30000004:
                index = len(visits)
                assert index < len(callback_mask)
                visits.append(pc)
                return 0x40000000 if callback_mask[index] else 0
            assert at in memory, (hex(pc), hex(at))
            return memory[at]

        def store(operand, number):
            number &= 0xFFFFFFFF
            if operand.type == capstone.x86.X86_OP_REG:
                registers[border[pc].reg_name(operand.reg)] = number
            else:
                assert operand.type == capstone.x86.X86_OP_MEM and operand.size == 4
                memory[address(operand)] = number

        while True:
            assert pc in border and steps < 512
            steps += 1
            instruction = border[pc]
            operation, operands = instruction.mnemonic, instruction.operands
            next_pc = pc + instruction.size
            if operation == 'mov':
                store(operands[0], value(operands[1]))
            elif operation == 'lea':
                store(operands[0], address(operands[1]))
            elif operation in ('add', 'sub'):
                store(operands[0], value(operands[0]) + value(operands[1]) * (1 if operation == 'add' else -1))
            elif operation in ('inc', 'dec'):
                number = (value(operands[0]) + (1 if operation == 'inc' else -1)) & 0xFFFFFFFF
                store(operands[0], number)
                comparisons = (number == 0, comparisons[1])
            elif operation == 'push':
                number = value(operands[0])
                registers['esp'] -= 4
                memory[registers['esp']] = number
            elif operation == 'pop':
                store(operands[0], memory[registers['esp']])
                registers['esp'] += 4
            elif operation in ('cmp', 'test'):
                left, right = value(operands[0]), value(operands[1])
                comparisons = ((left == right, left < right) if operation == 'cmp' else ((left & right) == 0, False))
            elif operation == 'jmp':
                next_pc = value(operands[0])
            elif operation in ('ja', 'je', 'jne'):
                zero, carry = comparisons
                take = (not zero and not carry) if operation == 'ja' else zero if operation == 'je' else not zero
                if take:
                    next_pc = value(operands[0])
            elif operation == 'call':
                assert pc in sites and value(operands[0]) == 0x40000000
                output.append(dict(site_va=hex(pc), args=[memory[registers['esp']+4*i] for i in range(6)]))
                for register in ('eax', 'ecx', 'edx'):
                    registers[register] = 0x1234ABCD
            elif operation == 'ret':
                assert registers['esp'] == start_sp and memory[start_sp] == 0xDEAD0000
                assert operands[0].imm == 20
                return dict(calls=output, callback_loads=len(visits), return_eax=registers['eax'], steps=steps)
            else:
                raise AssertionError((hex(pc), operation))
            pc = next_pc

    colors = ((0xFFFFFFFF, 0xFFD6D3CE, 0xFF000000, 0xFF848284),
              (0xFF848284, 0xFF000000, 0xFFFFFFFF, 0xFFD6D3CE),
              (0xFF848284, 0xFFD6D3CE, 0xFF848284, 0xFFD6D3CE),
              (0xFF000000, 0xFF848284, 0xFF000000, 0xFF848284))
    models = []
    for mode in range(1, 5):
        args = (11, 23, 41, 59, mode)
        model = border_model(args)
        expected_calls = []
        for layer in range(2):
            left, top, right, bottom = 11+layer, 23+layer, 41-layer, 59-layer
            expected_calls.extend([
                [left, top, right, top, colors[mode-1][layer], 0],
                [left, top, left, bottom, colors[mode-1][layer], 0],
                [right, top, right, bottom, colors[mode-1][layer+2], 0],
                [left, bottom, right, bottom, colors[mode-1][layer+2], 0]])
        assert [c['args'] for c in model['calls']] == expected_calls
        assert model['callback_loads'] == 8 and model['return_eax'] == 0
        for mask in ((False,)*8, tuple(i % 2 == 0 for i in range(8))):
            partial = border_model(args, mask)
            assert [c['args'] for c in partial['calls']] == [c for c, keep in zip(expected_calls, mask) if keep]
        models.append(dict(mode=mode, args=args, full_callback_case=model))
    for mode in (0, 5, -1, 0x80000001):
        model = border_model((11, 23, 41, 59, mode))
        assert model['calls'] == [] and model['callback_loads'] == 0
        assert model['return_eax'] == (mode-1) & 0xFFFFFFFF
    result = dict(status='独立字节初核；人工语义与终稿待核，不是PASS', disk_sha256=EXPECTED,
        raw_sha256=sha(raw_path.read_bytes()), subjects=subjects, equal_byte_records=count,
        direct_calls=len(calls), indirect_calls=indirect, bridges=len(raw['verified_direct_bridges']),
        incoming_records=len(incoming), incoming_data_records=sum(not r['is_code'] for r in incoming),
        unique_navigation_windows=len(windows), navigation_owners=len({owner for owner, _ in windows}),
        reuse_sources=sources, old_consumer_source=dict(path=str(old_path.relative_to(DOCS)).replace('\\', '/'),
            json_pointer='/functions/1', sha256=sha(old_path.read_bytes()), historical_status='部分分析'),
        old_short_dependencies=dependencies,
        callback_pointer_slot=dict(va='0xacc3c8', idb_hex='ffffffff', disk_supported=False,
            virtual_section=virtual, runtime_target_verified=False),
        independent_disk_jump_table=dict(va='0x8e4330', size=16, disk_hex=jump_blob.hex(),
            targets=[hex(v) for v in struct.unpack('<4I', jump_blob)], idb_verified=False),
        authored_bundle=authored_bundle(raw),
        border_instruction_model=dict(scope='仅边框有限离线解释；CALL仅采实参，不执行渲染',
            valid_modes=models, callback_masks_per_mode=3, rejected_modes=(0, 5, -1, 0x80000001)))
    if final:
        raise AssertionError('尚未绑定跳表补证、人工语义、作者终稿与分级清单，禁止PASS')
    (HERE / 'independent_assembly.txt').write_text('\n'.join(transcript)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--final', action='store_true')
    result = audit(parser.parse_args().final)
    (HERE / 'independent_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True, indent=2))
