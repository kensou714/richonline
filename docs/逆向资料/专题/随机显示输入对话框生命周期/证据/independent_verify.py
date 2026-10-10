"""独审：独立 PE 映射和 Capstone 32 位解码，核字段、分支、表、导入及清单。"""
import hashlib
import json
import struct
from pathlib import Path

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == EXPECTED_SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    assert struct.unpack_from('<H', blob, opt)[0] == 0x10B
    base = struct.unpack_from('<I', blob, opt + 28)[0]
    table = opt + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]

    def read(ea, length):
        choices = [(rva, offset) for _, rva, raw, offset in sections
                   if base + rva <= ea and ea + length <= base + rva + raw]
        assert len(choices) == 1, hex(ea)
        rva, offset = choices[0]
        start = offset + ea - base - rva
        return blob[start:start + length]

    def cbytes(ea):
        result = bytearray()
        for i in range(512):
            value = read(ea + i, 1)[0]
            if value == 0:
                return bytes(result)
            result.append(value)
        raise AssertionError(hex(ea))

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True

    def decode(ea):
        instruction = next(decoder.disasm(read(ea, 16), ea, count=1), None)
        assert instruction is not None, hex(ea)
        return instruction

    anchors = []

    def anchor(ea, mnemonic, operands, meaning):
        instruction = decode(ea)
        assert (instruction.mnemonic, instruction.op_str) == (mnemonic, operands), (
            hex(ea), instruction.mnemonic, instruction.op_str)
        anchors.append(dict(va=hex(ea), disk_hex=instruction.bytes.hex(), mnemonic=mnemonic,
                            operands=operands, meaning=meaning))
        return instruction

    anchor(0x912ED0, 'lea', 'eax, [ecx + 0x190]', '返回键盘对象this+400')
    anchor(0x917130, 'lea', 'eax, [ecx + 0x290]', '返回按键对象this+656，this不同')
    anchor(0x913EB9, 'mov', 'ebp, ecx', '软键优化函数保存入口this')
    anchor(0x91422D, 'mov', 'ebp, ecx', '物理键优化函数保存入口this')
    anchor(0x913EFD, 'mov', 'ecx, eax', '软键getter使用映射返回的按键对象')
    anchor(0x913F04, 'call', '0x605248', '按键getter调用桥')
    anchor(0x913F09, 'mov', 'dl, byte ptr [eax]', '读取按键操作首BYTE')
    anchor(0x913F0B, 'cmp', 'dl, 0xf7', '普通字符与特殊操作区分')
    anchor(0x914039, 'cmp', 'eax, 0x40', '软键普通追加长度门')
    anchor(0x91403C, 'jae', '0x914088', '长度达到64跳过普通追加')
    anchor(0x913FE2, 'mov', 'word ptr [edi], dx', 'TAB分支直接写WORD')
    anchor(0x91401F, 'mov', 'word ptr [edi], cx', '空格分支直接写WORD')
    anchor(0x914256, 'test', 'ah, ah', 'SHIFT高位检查')
    anchor(0x914258, 'js', '0x914266', 'SHIFT成立直接进入大写，无需CAPS分支')
    anchor(0x914262, 'test', 'al, 1', 'CAPS低位检查')
    anchor(0x914264, 'je', '0x914269', 'CAPS不成立保留小写')
    anchor(0x914266, 'add', 'bl, 0xe0', '从小写减32回大写，两个条件为OR')
    for site in (0x91427D, 0x9142D9, 0x91434B):
        anchor(site, 'cmp', 'eax, 0x40', '物理三类追加长度门')
    anchor(0x911BE8, 'push', '0x2c4', 'WM_INITDIALOG分配708字节')
    anchor(0x911BB0, 'mov', 'cl, byte ptr [eax]', '提交复制源逐字节读取')
    anchor(0x911BB3, 'mov', 'byte ptr [edx], cl', '提交逐字节写入全局缓冲')
    anchor(0x911BB8, 'jne', '0x911bb0', '复制包含终止NUL')
    anchor(0x911BBE, 'push', '0x64', '提交EndDialog返回100')
    anchor(0x911ED1, 'cmp', 'edi, 0x64', '入口仅100复制结果')
    anchor(0x911EE3, 'mov', 'byte ptr [edx + eax], cl', '向调用者out逐字节复制')
    anchor(0x911EE9, 'jne', '0x911ee1', 'out复制包含终止NUL')
    anchor(0x911D14, 'idiv', 'edi', '水平余量没有本体零除数门控')
    anchor(0x911D3A, 'idiv', 'ebx', '垂直余量没有本体零除数门控')
    anchor(0x9169B4, 'lea', 'esi, [ecx + 0x2b4]', '消息容器对象this+692')
    anchor(0x917043, 'call', '0x5ff19f', '删除包装器先调用析构桥')
    anchor(0x918EF0, 'mov', 'edx, dword ptr [ecx + 0x17c]', '宽字段this+380')
    anchor(0x918EFC, 'mov', 'ecx, dword ptr [ecx + 0x180]', '高字段this+384')

    # API 名称来自当前磁盘导入名称表，独立于 IDA 展示名。
    directory, directory_size = struct.unpack_from('<II', blob, opt + 104)
    imports = {}
    for i in range(0, directory_size, 20):
        original, stamp, forward, name, first = struct.unpack('<5I', read(base + directory + i, 20))
        if not any((original, stamp, forward, name, first)):
            break
        source = original or first
        for j in range(4096):
            value = struct.unpack('<I', read(base + source + j * 4, 4))[0]
            if not value:
                break
            imports[base + first + j * 4] = ('ordinal:' + str(value & 0xFFFF)
                                            if value & 0x80000000 else cbytes(base + value + 2).decode('ascii'))
        else:
            raise AssertionError('未终止导入数组')
    api_checks = {}
    for site, name in ((0x914250, 'GetAsyncKeyState'), (0x91425C, 'GetKeyState'),
                       (0x911E5D, 'LoadLibraryA'), (0x911E9D, 'DialogBoxParamA'),
                       (0x911EAA, 'FreeLibrary'), (0x911BC1, 'EndDialog')):
        ins = decode(site)
        assert ins.mnemonic == 'call' and ins.operands[0].type == X86_OP_MEM
        slot = ins.operands[0].mem.disp
        assert imports[slot] == name
        api_checks[hex(site)] = dict(slot=hex(slot), name=name)

    pointers = struct.unpack('<8I', read(0xA6917C, 32))
    rows = [cbytes(pointer) for pointer in pointers]
    special = sorted({b for row in rows for b in row if b >= 0xF7})
    assert special == [0xF8, 0xFA, 0xFB, 0xFC, 0xFE, 0xFF]
    assert pointers[0] == pointers[4] == 0xA315A4
    assert read(0xA3168C, 2) == b'\x09\x00'
    assert read(0xA2F4F4, 2) == b'\x20\x00'
    assert cbytes(0xA316D0).decode('big5') == '請輸入密碼...'

    navigation = json.loads((HERE / 'seed_navigation.json').read_text('utf-8'))
    closure = json.loads((HERE / 'closure_navigation.json').read_text('utf-8'))
    leaf = json.loads((HERE / 'leaf_navigation.json').read_text('utf-8'))
    bundles = [json.loads((HERE / name).read_text('utf-8')) for name in
               ('functions_raw.json', 'closure_raw.json', 'leaf_raw.json')]
    source_bytes = (ROOT / navigation['source_path']).read_bytes()
    assert hashlib.sha256(source_bytes).hexdigest() == navigation['source_sha256']
    old = {f['va']: f for f in json.loads(source_bytes.decode('utf-8'))['functions']}
    functions = [f for bundle in bundles for f in bundle['functions']]
    functions += [old[f['va']] for f in navigation['reused_functions']]
    assert len({f['va'] for f in functions}) == len(functions) == 20
    def compare(span):
        raw = read(int(span['va'], 16), span['size'])
        assert raw.hex() == span['disk_hex'] == span['idb_hex'] and span['matching']
        return raw

    declared_bytes = 0
    checked_ranges = 0
    for function in functions:
        for span in function['chunk_byte_ranges']:
            declared_bytes += len(compare(span))
            checked_ranges += 1
        for span in function['byte_ranges']:
            compare(span)
            checked_ranges += 1
    assert checked_ranges == 70 and declared_bytes == 8439
    for reused in navigation['reused_functions']:
        assert reused['declared_chunks'] == old[reused['va']]['declared_chunks']
        assert reused['chunk_byte_ranges'] == old[reused['va']]['chunk_byte_ranges']
    bridges = {bridge['va']: bridge for bundle in bundles for bridge in bundle['thunks']}
    bridges.update({entry['bridge']['va']: entry['bridge'] for entry in closure['vtable_entries']})
    assert len(bridges) == 29
    for bridge in bridges.values():
        raw = compare(bridge)
        instruction = decode(int(bridge['va'], 16))
        assert raw[0] == 0xE9 and len(raw) == instruction.size == 5
        assert instruction.mnemonic == 'jmp' and instruction.operands[0].type == X86_OP_IMM
        assert instruction.operands[0].imm == int(bridge['target'], 16)
    incoming_records = 0
    for target in (t for bundle in (navigation, closure, leaf) for t in bundle['incoming']):
        for reference in target['references']:
            if reference['bytes'] is not None:
                compare(reference['bytes'])
                incoming_records += 1
    assert incoming_records == 32
    window_bytes = sum(len(compare(span)) for span in navigation['windows'])
    table = compare(closure['table'])
    window_bytes += len(table)
    assert window_bytes == 324 and len(closure['vtable_entries']) == 13
    for entry in closure['vtable_entries']:
        assert struct.unpack_from('<I', table, entry['offset'])[0] == int(entry['bridge']['va'], 16)
    reviewed = json.loads((HERE.parent / '函数审阅清单.json').read_text('utf-8'))['functions']
    assert {f['va'] for f in functions} == {r['va'] for r in reviewed}
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.lstrip().startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=digest, capstone_version=capstone.__version__,
                  unique_functions=20, declared_bytes=declared_bytes, checked_ranges=checked_ranges,
                  bridges=len(bridges), incoming_records=incoming_records, window_bytes=window_bytes,
                  anchors=anchors,
                  api_checks=api_checks, fixed_rows=[dict(pointer=hex(p), hex=r.hex()) for p, r in zip(pointers, rows)],
                  fixed_row_special_bytes=special,
                  scope='独立磁盘与关键Capstone语义锚点，基础WNDPROC、子控件与树内部未审；未运行游戏')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(status='PASS', functions=20, anchors=len(anchors), declared_bytes=declared_bytes,
                         checked_ranges=checked_ranges, bridges=len(bridges), incoming_records=incoming_records,
                         window_bytes=window_bytes,
                         capstone_version=capstone.__version__)))


if __name__ == '__main__':
    main()
