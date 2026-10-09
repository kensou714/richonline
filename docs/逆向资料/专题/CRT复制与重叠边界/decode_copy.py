"""从PE用Capstone独立解码可达指令；跳表作数据，完全不修改IDA。"""
import hashlib
import json
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM
from verify_copy import HERE, load_pe


def main():
    blob, base, sections = load_pe()
    def disk(va, size):
        for _, rva, rawsize, off in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= rawsize:
                return blob[off+delta:off+delta+size]
        raise ValueError(hex(va))
    tables = json.loads((HERE/'证据/跳表原证.json').read_text(encoding='utf-8'))['tables']
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    runs = []
    visited = {int(a,16) for a in json.loads((HERE/'离线仿真结果.json').read_text(encoding='utf-8'))['visited_core_addresses']}
    for start in (0x9213A0,0x9217B0):
        end = start+829
        local = [t for t in tables if start<=int(t['va'],16)<end]
        table_bytes = {a for t in local for a in range(int(t['va'],16),int(t['va'],16)+t['size'])}
        pending = [start]+[int(a,16) for t in local for a in t['targets']]
        instructions = {}
        while pending:
            a = pending.pop()
            if a in instructions:
                continue
            assert start<=a<end and a not in table_bytes, hex(a)
            ins = next(decoder.disasm(disk(a,min(15,end-a)),a,count=1))
            assert not set(range(a,a+ins.size)) & table_bytes
            instructions[a] = dict(va=hex(a),size=ins.size,raw_hex=ins.bytes.hex(),
                                   text=ins.mnemonic+' '+ins.op_str,emulated=a in visited)
            if ins.mnemonic == 'ret':
                continue
            if ins.mnemonic.startswith('j'):
                if ins.operands[0].type == X86_OP_IMM:
                    pending.append(ins.operands[0].imm)
                if ins.mnemonic == 'jmp':
                    continue
            pending.append(a+ins.size)
        local_visited={a for a in visited if start<=a<end}
        assert local_visited == set(instructions), '仿真实际地址与独立可达指令集合不一致'
        runs.append(dict(entry=hex(start),end=hex(end),instructions=[instructions[a] for a in sorted(instructions)],
                         reachable_instruction_count=len(instructions),emulated_instruction_count=len(local_visited),
                         unexecuted=[hex(a) for a in sorted(set(instructions)-local_visited)]))
    result=dict(decoder='Capstone '+__import__('capstone').__version__,
                method='函数入口与12张跳表目标为种子，追踪条件/直接跳转与顺序边；间接跳表目标单列为种子。',
                disk_sha256=hashlib.sha256(blob).hexdigest(),functions=runs)
    (HERE/'证据/独立机器码解码.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps([{k:v for k,v in f.items() if k!='instructions'} for f in runs]))


if __name__ == '__main__':
    main()
