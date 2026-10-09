"""在IDA-MCP租约内exec运行；只读构造器、调用者和RTC，不修改IDB或EXE。"""
import hashlib
import json
import re
import struct
from pathlib import Path
import idc

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/本地消息构造契约'


def export_contracts(db):
    # 候选仅覆盖当前已定义函数中的直接WORD立即数写入；不把未命中当作不存在。
    candidates = []
    for function in db.functions.get_all():
        if not 0x620000 <= function.start_ea <= 0x900000:
            continue
        for ins in db.functions.get_instructions(function):
            line = db.instructions.get_disassembly(ins)
            match = re.search(r'\bmov\s+word ptr \[[^\]]+\], (60[0-9A-F]{2})h\b', line)
            if match and 0x6000 <= int(match[1], 16) <= 0x6090:
                candidates.append(dict(function=hex(function.start_ea), site=hex(ins.ea),
                                       opcode=hex(int(match[1], 16)), text=line))
    sites, thunk_set = [], {}
    for item in candidates:
        pending, seen = [int(item['function'], 16)], set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for ref in db.xrefs.to_ea(target):
                if ref.type == 19 and db.bytes.get_bytes_at(ref.from_ea, 1) == b'\xe9':
                    pending.append(ref.from_ea)
                    thunk_set[hex(ref.from_ea)] = dict(va=hex(ref.from_ea), target=hex(target),
                                                      idb_hex=db.bytes.get_bytes_at(ref.from_ea, 5).hex(), size=5)
                elif ref.type in (16, 17):
                    function = db.functions.get_at(ref.from_ea)
                    sites.append(dict(opcode=item['opcode'], constructor=item['function'],
                                      target=hex(target), site=hex(ref.from_ea),
                                      caller=hex(function.start_ea) if function else None))
    callers = {int(item['caller'], 16) for item in sites if item['caller']}
    rtc_by_function, ranges, insn_cache = {}, {}, {}

    def capture(ea, size):
        key = (ea, size)
        if key not in ranges:
            ranges[key] = dict(va=hex(ea), size=size, idb_hex=db.bytes.get_bytes_at(ea, size).hex())
        return ranges[key]

    def stack_offset(ea, operand=1):
        # 只接受直接EBP寻址，不对复杂表达式或寄存器别名进行推测。
        text = idc.print_operand(ea, operand)
        if not re.match(r'^\[ebp[+-]', text):
            return None
        value = idc.get_operand_value(ea, operand) & 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    for address in sorted(callers):
        instructions = list(db.functions.get_instructions(db.functions.get_at(address)))
        insn_cache[address] = instructions
        descriptions = []
        for index, ins in enumerate(instructions):
            if idc.print_insn_mnem(ins.ea) != 'call' or 'RTC_CheckStackVars' not in db.instructions.get_disassembly(ins):
                continue
            setup = None
            for prior in reversed(instructions[max(0, index - 5):index]):
                if idc.print_insn_mnem(prior.ea) == 'lea' and idc.print_operand(prior.ea, 0) == 'edx':
                    setup = prior
                    break
            if setup is None:
                continue
            header = idc.get_operand_value(setup.ea, 1)
            count, table = struct.unpack('<II', db.bytes.get_bytes_at(header, 8))
            if not 0 < count < 1000:
                raise ValueError('RTC描述不合预期：' + hex(ins.ea))
            capture(header, 8)
            capture(table, count * 12)
            entries = []
            for slot in range(count):
                offset, size, name = struct.unpack('<iII', db.bytes.get_bytes_at(table + 12 * slot, 12))
                raw_name = bytearray()
                for delta in range(256):
                    value = db.bytes.get_bytes_at(name + delta, 1)
                    raw_name.extend(value)
                    if value == b'\x00':
                        break
                capture(name, len(raw_name))
                entries.append(dict(offset=offset, size=size, name=bytes(raw_name[:-1]).decode('ascii', errors='backslashreplace'),
                                    descriptor=hex(table + 12 * slot)))
            descriptions.append(dict(check_site=hex(ins.ea), setup_site=hex(setup.ea), header=hex(header), entries=entries))
        rtc_by_function[hex(address)] = descriptions

    for site in sites:
        if not site['caller']:
            site['rtc_status'] = '调用点未归入已定义函数'
            continue
        instructions = insn_cache[int(site['caller'], 16)]
        index = next(i for i, ins in enumerate(instructions) if ins.ea == int(site['site'], 16))
        # 只认紧邻构造call之前的lea ecx,[ebp+局部]。
        previous = instructions[index - 1] if index else None
        offset = None
        if previous and idc.print_insn_mnem(previous.ea) == 'lea' and idc.print_operand(previous.ea, 0) == 'ecx':
            offset = stack_offset(previous.ea)
        site['this_stack_offset'] = offset
        site['rtc_matches'] = [dict(header=description['header'], **entry)
                               for description in rtc_by_function[site['caller']]
                               for entry in description['entries'] if entry['offset'] == offset]
        site['rtc_status'] = '直接EBP对象与RTC描述精确对应' if site['rtc_matches'] else '未建立RTC对象对应，不能推定容量'
        site['queue_prefix_candidates'] = []
        # 纯opcode临时对象常在Size已经压栈后构造，随后push返回的this。
        if index >= 2 and index + 3 < len(instructions):
            size_ins, source_push, owner_mov, queue_call = instructions[index-2], instructions[index+1], instructions[index+2], instructions[index+3]
            if (offset is not None and idc.print_insn_mnem(size_ins.ea) == 'push'
                    and idc.get_operand_type(size_ins.ea, 0) == 5
                    and idc.print_insn_mnem(source_push.ea) == 'push' and idc.print_operand(source_push.ea, 0) == 'eax'
                    and idc.print_insn_mnem(owner_mov.ea) == 'mov' and idc.print_operand(owner_mov.ea, 0) == 'ecx'
                    and idc.print_insn_mnem(queue_call.ea) == 'call' and idc.get_operand_value(queue_call.ea, 0) == 0x609D34):
                site['queue_prefix_candidates'].append(dict(site=hex(queue_call.ea), size=idc.get_operand_value(size_ins.ea, 0),
                                                            source_lea=hex(previous.ea), size_push=hex(size_ins.ea),
                                                            form='Size预压栈，构造返回this经EAX压栈'))
        # 后继基本直线片段内，识别64FA50调用的Size与Src；遇另一构造或分支即停止。
        # 这只是可审核的候选映射，非完整控制流/数据流证明。
        for cursor in range(index + 1, min(len(instructions), index + 90)):
            ins = instructions[cursor]
            mnemonic = idc.print_insn_mnem(ins.ea)
            if mnemonic.startswith('j') or mnemonic.startswith('ret'):
                break
            if mnemonic != 'call':
                continue
            target = idc.get_operand_value(ins.ea, 0)
            seen = set()
            while target not in seen and db.bytes.get_bytes_at(target, 1) == b'\xe9':
                seen.add(target)
                raw = db.bytes.get_bytes_at(target, 5)
                target += 5 + int.from_bytes(raw[1:], 'little', signed=True)
            if target in {int(item['function'], 16) for item in candidates}:
                break
            if target != 0x64FA50:
                continue
            before = instructions[max(index + 1, cursor - 9):cursor]
            pushes = [i for i in before if idc.print_insn_mnem(i.ea) == 'push']
            if len(pushes) < 2 or idc.get_operand_type(pushes[-2].ea, 0) != 5:
                break
            source_register = idc.print_operand(pushes[-1].ea, 0)
            source_leas = [i for i in before if i.ea < pushes[-1].ea and idc.print_insn_mnem(i.ea) == 'lea'
                           and idc.print_operand(i.ea, 0) == source_register]
            if source_leas and offset is not None and stack_offset(source_leas[-1].ea) == offset:
                site['queue_prefix_candidates'].append(dict(site=hex(ins.ea), size=idc.get_operand_value(pushes[-2].ea, 0),
                                                            source_lea=hex(source_leas[-1].ea), size_push=hex(pushes[-2].ea)))
            break

    output = dict(method='直接WORD构造扫描、递归E9调用关系、精确EBP/RTC对应；不进行寄存器数据流猜测',
                  scan_scope='0x620000..0x900000当前已定义函数中的mov word ptr立即数6000..6090',
                  candidates=candidates, callsites=sites, rtc=rtc_by_function,
                  metadata_ranges=list(ranges.values()), constructor_thunks=list(thunk_set.values()))
    (BASE / '证据').mkdir(parents=True, exist_ok=True)
    (BASE / '候选扫描.json').write_text(json.dumps(candidates, ensure_ascii=False, indent=2), encoding='utf-8')
    (BASE / '证据/contract_links.json').write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    shared_exporter = {}
    exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), shared_exporter)
    shared_exporter['export_group'](db, [int(item['function'], 16) for item in candidates], BASE/'证据/constructors.json')
    shared_exporter['export_group'](db, callers, BASE/'证据/callers.json')
    print(dict(constructors=len(candidates), callsites=len(sites), callers=len(callers),
               rtc_matches=sum(bool(item.get('rtc_matches')) for item in sites),
               queue_candidates=sum(bool(item.get('queue_prefix_candidates')) for item in sites)))


# IDA租约中exec此文件后显式调用export_contracts(db)。
