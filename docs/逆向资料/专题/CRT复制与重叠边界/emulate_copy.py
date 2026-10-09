"""Unicorn执行当前PE原机器码；离线CPU仿真，不启动游戏或调用宿主CRT。"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from verify_copy import HERE, load_pe

# 依赖由调用者提供；可用 --dependency-dir 指向临时目录，避免改项目依赖。
if '--dependency-dir' in sys.argv:
    sys.path.insert(0, sys.argv[sys.argv.index('--dependency-dir') + 1])
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

DATA, STACK, STOP = 0x3000000, 0x2000000, 0x1000000
LENGTHS = list(range(130)) + [255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097]


def main():
    blob, base, sections = load_pe()
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    limit = max(rva + max(vsize, rawsize) for vsize, rva, rawsize, _ in sections)
    machine.mem_map(base, (limit + 4095) & ~4095)
    for _, rva, rawsize, off in sections:
        machine.mem_write(base + rva, blob[off:off + rawsize])
    machine.mem_map(DATA, 0x10000)
    machine.mem_map(STACK, 0x10000)
    machine.mem_map(STOP, 0x1000)
    visited = set()
    state = dict(check=False)
    tables = json.loads((HERE / '证据/跳表原证.json').read_text(encoding='utf-8'))['tables']
    table_slots = {int(t['va'],16)+offset for t in tables for offset in range(0,t['size'],4)}
    def on_code(uc, address, size, _):
        if 0x9213A0 <= address < 0x921AED:
            visited.add(address)
    def on_memory(uc, access, address, size, value, _):
        if not state['check']:
            return
        reading = access == unicorn.UC_MEM_READ
        start = state['src'] if reading else state['dst']
        in_data = start <= address and address + size <= start + state['n']
        # 核心只压入EBP/EDI/ESI三个DWORD；读允许保存寄存器、返回地址及三参数。
        in_stack = (size == 4 and address % 4 == 0 and
                    esp - 12 <= address and address + size <= esp + (16 if reading else 0))
        in_table = reading and size == 4 and address in table_slots
        assert in_data or in_stack or in_table, (hex(address),size,access,state)
    machine.hook_add(UC_HOOK_CODE, on_code)
    machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_memory)
    esp = STACK + 0x8000
    preserved = {UC_X86_REG_ESI:0x11111111, UC_X86_REG_EDI:0x22222222,
                 UC_X86_REG_EBP:0x33333333, UC_X86_REG_EBX:0x44444444}
    arena = bytes(((i * 73 + (i >> 3)) & 255) for i in range(0x6000))
    def invoke(entry, args, this=0, df=0, callee_pop=0):
        machine.mem_write(esp, struct.pack('<' + 'I' * (len(args)+1), STOP, *args))
        machine.reg_write(UC_X86_REG_ESP, esp)
        machine.reg_write(UC_X86_REG_ECX, this)
        machine.reg_write(UC_X86_REG_EFLAGS, 2 | (df << 10))
        for reg, value in preserved.items():
            machine.reg_write(reg, value)
        machine.emu_start(entry, STOP, count=100000)
        assert machine.reg_read(UC_X86_REG_EIP) == STOP, '指令预算耗尽'
        assert machine.reg_read(UC_X86_REG_ESP) == esp + 4 + callee_pop
        assert all(machine.reg_read(reg) == val for reg, val in preserved.items())
        return machine.reg_read(UC_X86_REG_EAX), (machine.reg_read(UC_X86_REG_EFLAGS) >> 10) & 1
    counts = {}
    for entry in (0x9213A0, 0x9217B0):
        count = 0
        for n in LENGTHS:
            for alignment in range(4):
                for delta in list(range(-8, 9)) + [-5000, 5000]:
                    src, dst = DATA + 0x2200 + alignment, DATA + 0x2200 + alignment + delta
                    machine.mem_write(DATA, arena)
                    expected = bytearray(arena)
                    expected[dst-DATA:dst-DATA+n] = arena[src-DATA:src-DATA+n]
                    state.update(check=True, src=src, dst=dst, n=n)
                    eax, df = invoke(entry, [dst, src, n])
                    state['check'] = False
                    assert eax == dst and df == 0
                    assert machine.mem_read(DATA, len(arena)) == expected
                    count += 1
        # 零长度允许未映射指针；本实现不得解引用它们。
        for src, dst in [(0,0), (1,2), (0xFFFFFFFC, 0xFFFFFFFE)]:
            state.update(check=True, src=src, dst=dst, n=0)
            eax, df = invoke(entry, [dst, src, 0])
            state['check'] = False
            assert eax == dst and df == 0
            count += 1
        counts[hex(entry)] = count
    # 执行原62BD10整条删除链，合法对象分短缓冲与合成堆缓冲，不需要分配器。
    erase_count = 0
    for length in [0,1,2,3,4,7,14,15,16,17,31,32,33,63,64,65,127,128,129]:
        for pos in range(length + 1):
            for requested in sorted(set([0,1,2,3,length//2,length,length+1,0xFFFFFFFF])):
                obj = DATA + 0x7000
                text = bytes(65 + (i % 26) for i in range(length))
                capacity = 15 if length < 16 else length + 15
                pointer = obj + 4 if capacity < 16 else DATA + 0x8000
                machine.mem_write(obj, bytes(28))
                if capacity >= 16:
                    machine.mem_write(obj+4, struct.pack('<I',pointer))
                machine.mem_write(obj+20, struct.pack('<II',length,capacity))
                machine.mem_write(pointer, text+b'\0')
                count = min(requested, length-pos)
                expected = text[:pos] + text[pos+count:]
                eax, df = invoke(0x62BD10, [pos,requested], this=obj, callee_pop=8)
                assert eax == obj and df == 0
                assert struct.unpack('<I',machine.mem_read(obj+20,4))[0] == len(expected)
                assert machine.mem_read(pointer,len(expected)+1) == expected+b'\0'
                erase_count += 1
    valid_visited = set(visited)
    # 非ABI输入只作边界反证：无REP的小复制不清DF；正向REP依赖调用方DF=0。
    df_probes = []
    for entry in (0x9213A0,0x9217B0):
        for n,delta,expected_df,expected_equal in [(0,64,1,True),(3,64,1,True),
                                                   (32,64,1,False),(32,1,1,True),(64,1,0,True)]:
            src,dst=DATA+0x2200,DATA+0x2200+delta
            machine.mem_write(DATA,arena)
            expected=bytearray(arena)
            expected[dst-DATA:dst-DATA+n]=arena[src-DATA:src-DATA+n]
            eax,df=invoke(entry,[dst,src,n],df=1)
            equal = machine.mem_read(DATA,len(arena)) == expected
            assert eax == dst and df == expected_df and equal == expected_equal
            df_probes.append(dict(entry=hex(entry),n=n,delta=delta,df_in=1,df_out=df,
                                  bytes_equal=equal,returned_dst=eax==dst))
    result = dict(engine='Unicorn '+unicorn.__version__, scope='原机器码离线仿真；非游戏实机',
                  disk_sha256=hashlib.sha256(blob).hexdigest(), copy_cases=counts,
                  copy_total=sum(counts.values()), erase_cases=erase_count, lengths=LENGTHS,
                  src_alignment=list(range(4)), deltas=list(range(-8,9))+[-5000,5000],
                  checked='核心全访存白名单(精确src/dst、12B保存栈/参数读、跳表DWORD读)、全缓冲结果、EAX、ESP、ESI/EDI/EBP/EBX、DF=0；删除链检查结果与寄存器；DF反证断言',
                  df_non_abi_probes=df_probes, visited_core_addresses=[hex(x) for x in sorted(valid_visited)], errors=[])
    (HERE / '离线仿真结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['visited_core_addresses','lengths']},ensure_ascii=False))


if __name__ == '__main__':
    main()
