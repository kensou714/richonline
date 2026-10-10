"""有限物理栈槽复核；引用旧原证，不调用IDA或改写历史报告。"""
import hashlib
import json
import struct
from pathlib import Path

from independent_review import evidence, model_checks
from model_width_position import Node, locate, reference_locate

HERE = Path(__file__).resolve().parent
RESULT = HERE / 'atomic_equal_stack_validation.json'


def verify():
    protected = [p for p in HERE.parent.rglob('*') if p.is_file()
                 and '__pycache__' not in p.parts
                 and p.name not in (Path(__file__).name, RESULT.name,
                                    '05_原子等宽出口物理栈槽复核.txt')]
    hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in protected}
    data, read = evidence()
    rows = {int(i['va'], 16): i for f in data['functions'] for i in f['instructions']}
    anchors = {
        0x90CE80: '83ec0c', 0x90CE83: '53', 0x90CE84: '55',
        0x90CE89: '56', 0x90CE8A: '57', 0x90CEA4: '50',
        0x90CEA5: 'c744241400000000', 0x90CEAD: 'e8d133d0ff',
        0x90CEB9: '83c404', 0x90CEC0: '89442418',
        0x90CF52: '89742424', 0x90CFC4: '89742424',
        0x90CF70: '0f8490000000', 0x90D006: '8b442428',
        0x90D00A: '5f', 0x90D00B: '5e', 0x90D00C: '5d',
        0x90D00D: 'c70000000000', 0x90D013: '8b442418',
        0x90D017: '5b', 0x90D018: '83c40c', 0x90D01B: 'c21000',
        0x90CFFA: '8bc6', 0x924FEA: '8be5',
        0x924FEC: '5d', 0x924FED: 'c3',
    }
    for ea, expected in anchors.items():
        assert rows[ea]['hex'] == expected
        assert read(ea, len(bytes.fromhex(expected))).hex() == expected
    call = bytes.fromhex(anchors[0x90CEAD])
    target = 0x90CEAD + 5 + struct.unpack_from('<i', call, 1)[0]
    assert target == 0x610283
    bridge = next(r for r in data['thunks'] if int(r['va'], 16) == target)
    raw = bytes.fromhex(bridge['ida_hex'])
    assert raw == read(target, 5) == bytes.fromhex(bridge['disk_hex'])
    assert raw[0] == 0xE9 and target + 5 + struct.unpack_from('<i', raw, 1)[0] == 0x924FC0
    jump = bytes.fromhex(anchors[0x90CF70])
    assert 0x90CF70 + 6 + struct.unpack_from('<i', jump, 2)[0] == 0x90D006

    # 只解释明确选定的栈操作；不把该执行片段称为完整函数或指令模拟器。
    esp = 0
    regs = {r: 'saved_' + r for r in ('eax', 'ecx', 'edx', 'ebx', 'ebp', 'esi', 'edi')}
    memory = {0: 'return_address', 4: 'text_record', 8: 9, 12: 'delta_pointer', 16: 0}
    trace = []
    names = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')

    def step(ea):
        nonlocal esp
        raw = bytes.fromhex(anchors[ea])
        address = None
        if raw[:2] == b'\x83\xec':
            esp -= raw[2]
        elif raw[:2] == b'\x83\xc4':
            esp += raw[2]
        elif len(raw) == 1 and 0x50 <= raw[0] <= 0x57:
            esp -= 4
            memory[esp] = regs[names[raw[0] - 0x50]]
        elif len(raw) == 1 and 0x58 <= raw[0] <= 0x5F:
            regs[names[raw[0] - 0x58]] = memory[esp]
            esp += 4
        elif raw[:3] == b'\xc7\x44\x24':
            address = esp + raw[3]
            memory[address] = struct.unpack_from('<I', raw, 4)[0]
        elif raw[:3] in (b'\x89\x44\x24', b'\x89\x74\x24'):
            address = esp + raw[3]
            memory[address] = regs['eax' if raw[1] == 0x44 else 'esi']
        elif raw[:3] == b'\x8b\x44\x24':
            address = esp + raw[3]
            regs['eax'] = memory[address]
        elif raw[:2] == b'\xc7\x00':
            address = regs['eax']
            memory[address] = struct.unpack_from('<I', raw, 2)[0]
        elif raw[0] == 0xC2:
            assert memory[esp] == 'return_address'
            esp += 4 + struct.unpack_from('<H', raw, 1)[0]
        else:
            raise AssertionError(('片段未支持指令', hex(ea), raw.hex()))
        trace.append(dict(va=hex(ea), esp_from_entry=esp, accessed_slot=address))

    for ea in (0x90CE80, 0x90CE83, 0x90CE84, 0x90CE89, 0x90CE8A):
        step(ea)
    assert esp == -28
    regs['eax'] = 'wide_text'
    step(0x90CEA4)
    step(0x90CEA5)
    assert esp == -32 and memory[-12] == 0
    # 保存长度函数的裸retn与caller清参数已经核字节；这里只注入其语义结果n。
    regs['eax'] = 7
    step(0x90CEB9)
    step(0x90CEC0)
    assert esp == -28 and memory[-4] == 7
    regs['esi'] = 0
    step(0x90CF52)
    assert memory[8] == 0
    # 遍历后的B取2，与n及原target不同；不声称模拟了产生B的循环。
    regs['esi'] = 2
    step(0x90CFC4)
    assert memory[8] == 2
    for ea in (0x90D006, 0x90D00A, 0x90D00B, 0x90D00C):
        step(ea)
    assert esp == -16 and regs['eax'] == 'delta_pointer'
    step(0x90D00D)
    step(0x90D013)
    assert memory['delta_pointer'] == 0 and regs['eax'] == 2
    assert trace[-1]['accessed_slot'] == 8 and memory[-4] == 7
    for ea in (0x90D017, 0x90D018, 0x90D01B):
        step(ea)
    assert esp == 20 and regs['eax'] == 2

    nodes = [Node(2, 4, 1), Node(1, 7)]
    cases = [(4, 0, (0, 0)), (4, 1, (2, 0)), (0, 0, (0, 0)),
             (5, 0, (0, -1)), (4, 256, (0, 0)), (4, 257, (2, 0))]
    for target, flag, expected in cases:
        assert locate((4, 0, 7), target, flag, nodes)[:2] == expected
        assert reference_locate((4, 0, 7), target, flag, nodes) == expected
    assert locate((1, 0, 0, 7), 1, 0)[:2] == (1, 0)
    independent_model = model_checks()
    assert all(hashlib.sha256(p.read_bytes()).hexdigest() == sha for p, sha in hashes.items())
    result = dict(status='PASS', scope='保存原证与当前PE的有限栈片段复核；非实时IDA或实机',
                  assembly_byte_anchors=len(anchors), bridge_checks=1,
                  length_slot_from_entry=-4, atomic_start_slot_from_entry=8,
                  before_epilogue_esp=-28, after_three_pops_esp=-16,
                  returned_atomic_start=2, distinct_text_length=7, stack_trace=trace,
                  author_regression_cases=len(cases) + 1, independent_model=independent_model,
                  protected_sha256={str(p.relative_to(HERE.parent)).replace('\\', '/'): sha
                                    for p, sha in sorted(hashes.items())},
                  historical_artifacts_modified=False, ida_called=False, exe_executed=False)
    RESULT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=False, indent=2))
