"""独审核验：不同内存布局及随机内容，执行原码并严格限制每次访问；不写作者产物。"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dependency-dir')
    args = parser.parse_args()
    if args.dependency_dir:
        sys.path.insert(0, args.dependency_dir)
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                                   UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                                   UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP,
                                   UC_X86_REG_EFLAGS)
    from verify_copy import load_pe

    blob, base, sections = load_pe()
    fingerprint = hashlib.sha256(blob).hexdigest()
    raw_evidence = json.loads((HERE / '证据/crt_copy.json').read_text(encoding='utf-8'))
    assert raw_evidence['disk_sha256'] == fingerprint
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    limit = max(rva + max(vsize, rawsize) for vsize, rva, rawsize, _ in sections)
    machine.mem_map(base, (limit + 4095) & ~4095)
    for _, rva, size, offset in sections:
        machine.mem_write(base + rva, blob[offset:offset + size])
    arenas = (0x03000000, 0x90000000)
    arena_size, stack, stop = 0x4000, 0x02000000, 0x01000000
    for address in arenas:
        machine.mem_map(address, arena_size)
    machine.mem_map(stack, 0x1000)
    machine.mem_map(stop, 0x1000)
    esp = stack + 0x800
    tables = json.loads((HERE / '证据/跳表原证.json').read_text(encoding='utf-8'))['tables']
    table_slots = {int(t['va'], 16) + offset for t in tables for offset in range(0, t['size'], 4)}
    decoded_evidence = json.loads((HERE / '证据/独立机器码解码.json').read_text(encoding='utf-8'))
    assert decoded_evidence['disk_sha256'] == fingerprint
    decoded = decoded_evidence['functions']
    allowed_code = {int(f['entry'], 16): {int(i['va'], 16) for i in f['instructions']} for f in decoded}
    visited = {entry: set() for entry in allowed_code}
    observed_slots = set()
    state = {}

    def code_hook(uc, address, size, user):
        assert address in allowed_code[state['entry']], ('意外执行地址', hex(address))
        visited[state['entry']].add(address)

    def memory_hook(uc, access, address, size, value, user):
        read = access == UC_MEM_READ
        if read and address in table_slots and size == 4:
            observed_slots.add(address)
            return
        if esp - 12 <= address and address + size <= (esp + 16 if read else esp):
            return
        start = state['src'] if read else state['dst']
        assert start <= address and address + size <= start + state['n'], (
            '意外读写', read, hex(address), size, state)

    machine.hook_add(UC_HOOK_CODE, code_hook)
    machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory_hook)
    generator = random.Random(0x9219A0)
    saved_regs = (UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP)
    cases = 0

    def one(entry, src, dst, n):
        nonlocal cases
        before = {address: generator.randbytes(arena_size) for address in arenas}
        for address, content in before.items():
            machine.mem_write(address, content)
        expected = {address: bytearray(content) for address, content in before.items()}
        if n:
            source_arena = next(a for a in arenas if a <= src and src + n <= a + arena_size)
            dest_arena = next(a for a in arenas if a <= dst and dst + n <= a + arena_size)
            snapshot = bytes(before[source_arena][src - source_arena:src - source_arena + n])
            expected[dest_arena][dst - dest_arena:dst - dest_arena + n] = snapshot
        machine.mem_write(esp, struct.pack('<4I', stop, dst, src, n))
        machine.reg_write(UC_X86_REG_ESP, esp)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        preserved = {reg: generator.getrandbits(32) for reg in saved_regs}
        for reg, value in preserved.items():
            machine.reg_write(reg, value)
        for reg in (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX):
            machine.reg_write(reg, generator.getrandbits(32))
        state.update(entry=entry, src=src, dst=dst, n=n)
        machine.emu_start(entry, stop, count=100000)
        assert machine.reg_read(UC_X86_REG_EIP) == stop
        assert machine.reg_read(UC_X86_REG_EAX) == dst
        assert machine.reg_read(UC_X86_REG_ESP) == esp + 4
        assert machine.reg_read(UC_X86_REG_EFLAGS) & 0x400 == 0
        assert all(machine.reg_read(reg) == value for reg, value in preserved.items())
        assert machine.mem_read(esp, 16) == struct.pack('<4I', stop, dst, src, n)
        assert all(machine.mem_read(a, arena_size) == content for a, content in expected.items())
        cases += 1

    for entry in allowed_code:
        for n in range(40):
            for alignment in range(4):
                src = arenas[0] + 0x800 + alignment
                for delta in (-4, -1, 0, 1, 4):
                    one(entry, src, src + delta, n)
        for index in range(128):
            n = generator.choice((1, 3, 31, 32, 33, 127, 128, 129, 255, 256, 257, 1023, 4097))
            src = arenas[index % 2] + generator.randrange(64, 512)
            dst = arenas[1 - index % 2] + generator.randrange(64, 512)
            one(entry, src, dst, n)
        for src, dst in ((0, 0), (1, 2), (0xFFFFFFFC, 0xFFFFFFFE)):
            one(entry, src, dst, 0)
    assert all(visited[entry] == instructions for entry, instructions in allowed_code.items())
    assert observed_slots == table_slots
    print(json.dumps({'cases': cases, 'core_instructions': {hex(e): len(v) for e, v in visited.items()},
                      'table_slots': len(observed_slots), 'mismatches': 0,
                      'scope': '独立随机字节、低高地址双区、全部访问白名单、原码离线仿真；非实机。'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
