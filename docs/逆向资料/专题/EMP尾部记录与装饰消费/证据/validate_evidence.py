"""独立从当前磁盘 PE 复核原证；不依赖 IDA、不写游戏文件。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
EXPORTS = ('consumers_raw.json', 'rechecked_raw.json', 'dependencies_raw.json',
           'tail_picker_raw.json')
WINDOWS = ('windows_and_incoming.json', 'window_roots_raw.json')


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    errors = []
    if digest != EXPECTED_SHA:
        errors.append('当前 EXE 不是专题目标版本')
    if blob[:2] != b'MZ':
        raise ValueError('不是 MZ 文件')
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    if blob[pe:pe + 4] != b'PE\0\0':
        raise ValueError('不是 PE 文件')
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    if struct.unpack_from('<H', blob, pe + 24)[0] != 0x10B:
        raise ValueError('本验证只接受 PE32')
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional_size + index * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((image_base + rva, raw_size, raw_offset))

    def disk(ea, size):
        for start, length, offset in sections:
            relative = ea - start
            if 0 <= relative and relative + size <= length:
                return blob[offset + relative:offset + relative + size]
        raise ValueError(f'VA 不在磁盘节内：{ea:#x}/{size}')

    checked_ranges = 0
    bridge_rows = 0
    unique_bridges = set()

    def check_range(row, label):
        nonlocal checked_ranges
        ea, size = int(row['va'], 16), row['size']
        actual = disk(ea, size)
        if not row['matching'] or row['idb_hex'] != actual.hex() or row['disk_hex'] != actual.hex():
            errors.append(label + ': 字节不一致')
        checked_ranges += 1
        return actual

    def check_bridge(row, label):
        nonlocal bridge_rows
        raw = check_range(row, label)
        if len(raw) != 5 or raw[0] != 0xE9:
            errors.append(label + ': 非 E9 rel32 桥')
        elif int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True) != int(row['target'], 16):
            errors.append(label + ': E9 目标不一致')
        bridge_rows += 1
        unique_bridges.add(row['va'])

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    checked_calls = 0

    def check_call(row, label):
        nonlocal checked_calls
        site, target = int(row['site'], 16), int(row['target'], 16)
        instruction = next(decoder.disasm(disk(site, 15), site, count=1), None)
        operand = instruction.operands[0] if instruction and instruction.operands else None
        direct = operand and operand.type == X86_OP_IMM and operand.imm == target
        imported = (operand and operand.type == X86_OP_MEM and operand.mem.base == 0 and
                    operand.mem.index == 0 and operand.mem.disp == target)
        if instruction is None or instruction.mnemonic != 'call' or not (direct or imported):
            errors.append(label + ': call 目标或导入槽地址不一致')
        final, seen = target, set()
        while final not in seen and len(seen) < 16:
            raw = disk(final, 5)
            if raw[0] != 0xE9:
                break
            seen.add(final)
            final = final + 5 + int.from_bytes(raw[1:], 'little', signed=True)
        if final != int(row['implementation'], 16):
            errors.append(label + ': 直接桥链终点不一致')
        checked_calls += 1

    function_reports = []
    for name in EXPORTS:
        data = json.loads((HERE / name).read_text(encoding='utf-8'))
        if data['disk_sha256'] != digest:
            errors.append(name + ': EXE 哈希不一致')
        for function in data['functions']:
            label = name + '/' + function['va']
            for kind in ('byte_ranges', 'chunk_byte_ranges'):
                for row in function[kind]:
                    check_range(row, label + '/' + kind)
            for chunk, row in zip(function['declared_chunks'], function['chunk_byte_ranges']):
                if (row['va'] != chunk['start_va'] or row['size'] !=
                        int(chunk['end_va'], 16) - int(chunk['start_va'], 16)):
                    errors.append(label + ': 声明块范围不一致')
            if len(function['declared_chunks']) != len(function['chunk_byte_ranges']):
                errors.append(label + ': 声明块数量不一致')
            for call in function['calls']:
                check_call(call, label + '/' + call['site'])
            function_reports.append(dict(source=name, va=function['va'],
                                         declared_chunks=len(function['declared_chunks']),
                                         instruction_range_bytes=sum(r['size'] for r in function['byte_ranges']),
                                         assembly_rows=len(function['assembly'])))
        for bridge in data['thunks']:
            check_bridge(bridge, name + '/' + bridge['va'])

    window_reports = []
    sources = []
    for name in WINDOWS:
        data = json.loads((HERE / name).read_text(encoding='utf-8'))
        if 'disk_sha256' in data and data['disk_sha256'] != digest:
            errors.append(name + ': EXE 哈希不一致')
        for bridge in data['bridges']:
            check_bridge(bridge, name + '/' + bridge['va'])
        for window in data['windows']:
            label = name + '/' + window['start_va']
            check_range(window['raw_range'], label + '/raw')
            start, end = int(window['start_va'], 16), int(window['end_va'], 16)
            if window['raw_range']['va'] != window['start_va'] or window['raw_range']['size'] != end - start:
                errors.append(label + ': 原始窗口范围不一致')
            instruction_count, non_code = 0, []
            cursor = start
            for row in window['items']:
                raw = check_range(row, label + '/' + row['va'])
                ea = int(row['va'], 16)
                if ea != cursor or ea + row['size'] > end:
                    errors.append(label + ': items 不连续或越界')
                cursor = ea + row['size']
                if row['declared_owner'] is not None:
                    errors.append(label + ': 窗口出现声明函数归属，需重新审阅')
                if row['is_code']:
                    instructions = list(decoder.disasm(raw, ea))
                    if len(instructions) != 1 or instructions[0].size != len(raw):
                        errors.append(label + ': CPU 解码长度不符 ' + row['va'])
                    instruction_count += len(instructions)
                else:
                    non_code.append(dict(va=row['va'], size=row['size'], text=row['text']))
            if cursor != end:
                errors.append(label + ': items 未覆盖窗口末尾')
            for call in window['calls']:
                check_call(call, label + '/' + call['site'])
            window_reports.append(dict(source=name, start_va=window['start_va'],
                                       end_va=window['end_va'], ida_items=len(window['items']),
                                       cpu_instructions=instruction_count, non_code_items=non_code))
        sources.extend(data.get('reused_sources', []))
    sources.extend(json.loads((HERE / 'dependency_sources.json').read_text(encoding='utf-8'))['sources'])
    for source in sources:
        actual = hashlib.sha256((ROOT / source['path']).read_bytes()).hexdigest()
        if actual != source['sha256']:
            errors.append(source['path'] + ': 复用原证哈希已变化')

    # RTC 数据与相邻填充留在非代码分类，不能用反汇编凑指令数。
    descriptor_count, descriptor_pointer = struct.unpack('<II', disk(0x7E13FA, 8))
    stack_offset, stack_size, name_pointer = struct.unpack('<iII', disk(0x7E1402, 12))
    local_name = disk(name_pointer, 10).split(b'\0', 1)[0].decode('ascii')
    local_array = dict(descriptor_va='0x7e13fa', count=descriptor_count,
                       descriptor_pointer=hex(descriptor_pointer), stack_offset=stack_offset,
                       size=stack_size, name_pointer=hex(name_pointer), name=local_name)
    if (descriptor_count, descriptor_pointer, stack_offset, stack_size, name_pointer, local_name) != (
            1, 0x7E1402, -0x414, 0x400, 0x7E140E, 'iRatioAry'):
        errors.append('RTC 临时数组描述符不符')

    discovery = json.loads((HERE / 'discovery_candidates.json').read_text(encoding='utf-8'))
    if discovery['disk_sha256'] != digest:
        errors.append('候选扫描 EXE 哈希不一致')
    for bridge in discovery['bridges']:
        check_bridge(bridge, 'discovery/' + bridge['va'])
    manifest_path = HERE.parent / '函数审阅清单.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    for group in ('functions', 'rechecked_sources', 'code_windows', 'reused_producers'):
        for row in manifest[group]:
            if any(not row.get(key) for key in ('va', 'status', 'conclusion', 'unknown', 'evidence')):
                errors.append(group + ': 缺少清单字段')
            reference, _, pointer = row['evidence'].partition('#')
            document = HERE.parent / row['document']
            if not document.is_file():
                errors.append(row['va'] + ': 文档不存在')
            target = HERE.parent / reference
            if not target.is_file():
                errors.append(row['va'] + ': 原证不存在')
            elif pointer:
                selected = json.loads(target.read_text(encoding='utf-8'))
                for token in pointer.strip('/').split('/'):
                    selected = selected[int(token)] if isinstance(selected, list) else selected[token]
                if selected.get('va', selected.get('start_va')) != row['va']:
                    errors.append(row['va'] + ': 清单指针地址不符')
    for document in HERE.parent.glob('*.txt'):
        for index, line in enumerate(document.read_text(encoding='utf-8').splitlines(), 1):
            if line.strip() and not line.startswith('//'):
                errors.append(f'{document.name}:{index} 未按 C++ 注释排版')
    report = dict(disk_sha256=digest, success=not errors, checked_range_rows=checked_ranges,
                  bridge_rows=bridge_rows, unique_bridge_count=len(unique_bridges),
                  checked_call_sites=checked_calls, rtc_local_array=local_array,
                  functions=function_reports, windows=window_reports, reused_sources=sources,
                  new_reviewed_declared_functions=len(manifest['functions']),
                  complete_new_functions=sum(r['status'] == '完整函数静态审阅' for r in manifest['functions']),
                  partial_new_functions=sum(r['status'] == '字段或调用路径局部审阅' for r in manifest['functions']),
                  errors=errors)
    (HERE / 'validation_report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(success=report['success'], checked_range_rows=checked_ranges,
                          unique_bridge_count=len(unique_bridges), errors=errors), ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == '__main__':
    raise SystemExit(main())
