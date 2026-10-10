"""离线重核已有证据；旧文本、当前磁盘与 IDB 原字节分别记录。"""
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', blob, 60)[0]
    assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
    optional = pe + 24
    assert struct.unpack_from('<H', blob, optional)[0] == 0x10B
    base = struct.unpack_from('<I', blob, optional + 28)[0]
    table = optional + struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<4I', blob, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', blob, pe + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def disk(ea, size):
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if base + rva <= ea and ea + size <= base + rva + length]
        assert len(matches) == 1, hex(ea)
        rva, offset = matches[0]
        at = offset + ea - base - rva
        raw = blob[at:at + size]
        assert len(raw) == size
        return raw

    def load(relative):
        path = ROOT / relative
        return json.loads(path.read_text('utf-8')), hashlib.sha256(path.read_bytes()).hexdigest()

    def decode(ea, raw):
        rows = list(decoder.disasm(raw, ea))
        assert sum(row.size for row in rows) == len(raw)
        return rows

    def instructions(rows):
        return [dict(va=hex(row.address), size=row.size, hex=row.bytes.hex(),
                     mnemonic=row.mnemonic, operands=row.op_str) for row in rows]

    def calls(rows):
        result = []
        for row in rows:
            if row.mnemonic != 'call' or not row.op_str.startswith('0x'):
                continue
            target = int(row.op_str, 16)
            final, chain = target, []
            while final not in chain and len(chain) < 16:
                raw = disk(final, 5)
                if raw[0] != 0xE9:
                    break
                chain.append(final)
                final += 5 + struct.unpack_from('<i', raw, 1)[0]
            result.append(dict(site=hex(row.address), target=hex(target),
                               implementation=hex(final), thunks=[hex(at) for at in chain],
                               origin='当前磁盘解码；不是新 IDB 导出'))
        return result

    current_source = 'docs/逆向资料/专题/大厅URL读取与缓冲契约/证据/functions_raw.json'
    current, current_hash = load(current_source)
    assert current['disk_sha256'] == EXPECTED
    copied = [row for row in current['functions'] if row['va'] == '0x8198e0']
    assert len(copied) == 1
    for row in copied[0]['chunk_byte_ranges']:
        assert disk(int(row['va'], 16), row['size']).hex() == row['disk_hex'] == row['idb_hex']
    provenance = [dict(source=current_source, source_sha256=current_hash, functions=['0x8198e0'])]
    legacy_source = 'docs/逆向资料/专题/文本与容器/证据/parser_kpd_functions.json'
    old, old_hash = load(legacy_source)
    old_function = next(row for row in old['functions'] if row['ea'] == '0x81a090')
    declarations, declaration_hash = load('docs/逆向资料/专题/Grant全局配置与短消费/证据/grant_reuse_declarations_raw.json')
    declaration = next(row for row in declarations['reused_declarations'] if row['va'] == '0x81a090')
    start, end = int(declaration['declared_start'], 16), int(declaration['declared_end'], 16)
    raw = disk(start, end - start)
    decoded = decode(start, raw)
    assert [row.address for row in decoded] == [int(row['ea'], 16) for row in old_function['assembly']]

    def normalize(text):
        text = text.split(';', 1)[0].strip().lower()
        text = re.sub(r'\bshort\s+', '', text)
        text = text.replace('dword ptr ', '').replace('byte ptr ', '')
        text = text.replace('var_4', '-4').replace('arg_0', '8').replace('arg_4', '0xc')
        text = re.sub(r'\bloc_([0-9a-f]+)\b', r'0x\1', text)
        text = re.sub(r'\b([0-9a-f]+)h\b', lambda m: hex(int(m[1], 16)), text)
        text = re.sub(r'\b0x([0-9a-f]+)\b', lambda m: str(int(m[1], 16)), text)
        text = text.replace('jnz ', 'jne ').replace('jmp ', 'jmp ').replace('retn ', 'ret ')
        return re.sub(r'\s+', '', text).replace('+-', '-')

    for old_row, instruction in zip(old_function['assembly'], decoded):
        assert normalize(old_row['text']) == normalize(instruction.mnemonic + ' ' + instruction.op_str), (old_row, instruction.op_str)
    legacy = [dict(va=hex(start), end_va=hex(end), source=legacy_source,
                   source_sha256=old_hash, source_binary_sha256=old['sha256'],
                   declaration_source='grant_reuse_declarations_raw.json',
                   declaration_source_sha256=declaration_hash,
                   declared_chunks=declaration['declared_chunks'],
                   disk_ranges=[dict(va=hex(start), size=len(raw), disk_hex=raw.hex(),
                                     sha256=hashlib.sha256(raw).hexdigest())],
                   old_assembly=old_function['assembly'], instructions=instructions(decoded),
                   normalized_text_matching=True,
                   boundary='旧文本逐指令重核当前磁盘及当前声明；没有旧 IDB 原字节，不记新覆盖')]
    windows = []
    sources = [('docs/逆向资料/专题/道具与卡片操作/ida_cards_raw.json', '0x7113a0', 0x711738, 0x711803),
               ('docs/逆向资料/专题/本地消息构造契约/证据/callers.json', '0x7cdab0', 0x7CDAD0, 0x7CDB3B)]
    for source, owner, start, end in sources:
        payload, source_hash = load(source)
        old_format = isinstance(payload['functions'], dict)
        function = payload['functions'][owner] if old_format else next(row for row in payload['functions'] if row['va'] == owner)
        source_rows = function['instructions'] if old_format else function['assembly']
        assembly = [row for row in source_rows if start <= int(row.get('ea', row.get('va')), 16) < end]
        ranges = function['ranges'] if old_format else function['byte_ranges']
        range_row = next(row for row in ranges if int(row.get('start', row.get('va')), 16) <= start and
                         (int(row['end'], 16) if 'end' in row else int(row['va'], 16) + row['size']) >= end)
        range_start = int(range_row.get('start', range_row.get('va')), 16)
        original = bytes.fromhex(range_row.get('idb_bytes_hex', range_row.get('idb_hex')))
        # 先核来源完整原范围，随后仅保存已选择的消费窗口。
        assert disk(range_start, len(original)) == original
        sliced = original[start - range_start:end - range_start]
        decoded = decode(start, sliced)
        assert [row.address for row in decoded] == [int(row.get('ea', row.get('va')), 16) for row in assembly]
        windows.append(dict(owner=owner, start_va=hex(start), end_va=hex(end), source=source,
                            source_sha256=source_hash,
                            source_binary_sha256=payload.get('disk_sha256', payload.get('idb_input_sha256')),
                            raw_range=dict(va=hex(start), size=len(sliced), idb_hex=sliced.hex(),
                                           disk_hex=sliced.hex(), matching=True),
                            assembly=assembly, instructions=instructions(decoded), calls=calls(decoded),
                            boundary='来源 IDB 字节重核当前磁盘；仅 Grant 消费窗口，不提升整函数覆盖'))
    parser_source = 'docs/逆向资料/专题/文本段键解析与预处理/证据/functions_raw.json'
    parser, parser_hash = load(parser_source)
    assert parser['disk_sha256'] == EXPECTED
    result = dict(disk_sha256=EXPECTED, functions=copied, provenance=provenance,
                  legacy_rechecked_functions=legacy, consumer_windows=windows,
                  reference_sources=[dict(source=parser_source, source_sha256=parser_hash,
                                          functions=['0x8191d0', '0x819250', '0x819470', '0x819660'],
                                          boundary='已审解析契约仅引用；不在本批重新累计函数')])
    literal = declarations['key_literal']
    assert disk(0xA2D500, 4).hex() == literal['idb_hex'] == '6e756d00'
    result['manual_num_literal'] = dict(va='0xa2d500', size=4, hex='6e756d00',
                                        boundary='人工四字节 C 字串门；保留初始 IDA 自动字符串门失败事实')
    (HERE / 'grant_reused_raw.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(copied_functions=len(copied), old_text_rechecked=len(legacy),
                         consumer_windows=len(windows), num_manual_gate=True), ensure_ascii=False))


if __name__ == '__main__':
    main()
