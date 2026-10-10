"""独立核验本专题有限依赖的声明块、桥与机器语义锚点。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == EXPECTED
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True

    def audit(row):
        va, size = int(row['va'], 16), row['size']
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert size > 0 and len(matches) == 1
        rva, offset = matches[0]
        at = offset + va - base - rva
        raw = image[at:at + size]
        assert len(raw) == size and raw.hex() == row['idb_hex'] == row['disk_hex']
        assert row['matching'] is True
        return raw

    functions, by_owner, by_site, files, all_ranges = [], {}, {}, [], []
    for path in sorted(HERE.glob('dependency*_raw.json')):
        source_bytes = path.read_bytes()
        data = json.loads(source_bytes)
        assert data['disk_sha256'] == EXPECTED
        bridges = {int(row['va'], 16): row for row in data['thunks']}
        for va, row in bridges.items():
            raw = audit(row)
            assert len(raw) == 5 and raw[0] == 0xE9
            assert va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(row['target'], 16)
        byte_count, instruction_count, calls = 0, 0, 0
        for function in data['functions']:
            va = int(function['va'], 16)
            assert va not in by_owner
            chunks = function['declared_chunks']
            byte_ranges = function['chunk_byte_ranges']
            assert [(int(row['start_va'], 16), int(row['end_va'], 16) - int(row['start_va'], 16))
                    for row in chunks] == [(int(row['va'], 16), row['size']) for row in byte_ranges]
            assert sum(row['is_main'] for row in chunks) == 1
            assert any(row['start_va'] == function['va'] and row['is_main'] for row in chunks)
            decoded = []
            for row in byte_ranges:
                raw = audit(row)
                at = int(row['va'], 16)
                items = list(cs.disasm(raw, at))
                assert [item.address for item in items] == list(dict.fromkeys(item.address for item in items))
                cursor = at
                for item in items:
                    assert item.address == cursor
                    cursor += item.size
                assert cursor == at + row['size']
                decoded.extend(items)
                all_ranges.append((at, row['size']))
            assert [int(row['va'], 16) for row in function['assembly']] == [item.address for item in decoded]
            for row in function['byte_ranges']:
                audit(row)
            assert function['bytes_match_disk'] is True
            by_owner[va] = decoded
            for item in decoded:
                assert item.address not in by_site
                by_site[item.address] = item
            for call in function['calls']:
                item = by_site[int(call['site'], 16)]
                assert item.mnemonic in ('call', 'jmp')
                operand = item.operands[0]
                if operand.type == CS_OP_IMM:
                    target = operand.imm & 0xFFFFFFFF
                else:
                    assert operand.type == CS_OP_MEM and not operand.mem.base and not operand.mem.index
                    assert not call['thunks']
                    target = operand.mem.disp & 0xFFFFFFFF
                assert target == int(call['target'], 16)
                visited = set()
                for bridge in call['thunks']:
                    va_bridge = int(bridge, 16)
                    assert va_bridge == target and va_bridge not in visited
                    visited.add(va_bridge)
                    target = int(bridges[va_bridge]['target'], 16)
                assert target == int(call['implementation'], 16)
            count = sum(row['size'] for row in byte_ranges)
            byte_count += count
            instruction_count += len(decoded)
            calls += len(function['calls'])
            functions.append(dict(va=function['va'], source=path.name,
                                  chunks=len(chunks), bytes=count, instructions=len(decoded)))
        files.append(dict(path=path.name, sha256=hashlib.sha256(source_bytes).hexdigest(),
                          functions=len(data['functions']), bytes=byte_count,
                          instructions=instruction_count, calls=calls, bridges=len(bridges)))
    assert files
    for first, second in zip(sorted(all_ranges), sorted(all_ranges)[1:]):
        assert first[0] + first[1] <= second[0]
    anchors = {0x8611BB: ('mov', 'eax, dword ptr [eax]'),
               0x8611C0: ('push', '4'), 0x8611C5: ('call', '0x603353'),
               0x8611CA: ('mov', 'eax, dword ptr [ebp - 0x14]'),
               0x8611E0: ('ret', ''),
               0x85D749: ('call', '0x604f73'), 0x85D74E: ('jmp', '0x85d720'),
               0x85AD27: ('test', 'eax, eax'), 0x85AD29: ('jne', '0x85ad37'),
               0x85AD31: ('mov', 'dl, byte ptr [ecx + 4]'),
               0x85AD34: ('mov', 'byte ptr [eax + 0x21], dl'),
               0x85DBF4: ('mov', 'eax, dword ptr [edx]'),
               0x85DBF6: ('mov', 'dword ptr [ecx], eax'),
               0x85DC74: ('ret', ''),
               0x861066: ('mov', 'ecx, dword ptr [eax]'),
               0x861075: ('call', '0x604cfd'),
               0x86139B: ('mov', 'dword ptr [eax + 8], edx')}
    for site, expected in anchors.items():
        item = by_site[site]
        assert (item.mnemonic, item.op_str) == expected, hex(site)
    header_rows = []
    for va, request_type, body in ((0x85A3E0, 0, 64), (0x85A710, 1, 96),
                                   (0x85A9D0, 2, 96), (0x85AC60, 3, 64), (0x85B010, 4, 97)):
        for offset, value in ((2, request_type), (6, body)):
            matches = [item for item in by_owner[va] if item.mnemonic == 'mov' and len(item.operands) == 2
                       and item.operands[0].type == CS_OP_MEM and item.operands[0].mem.disp == offset
                       and item.operands[0].size == 4 and item.operands[1].type == CS_OP_IMM
                       and item.operands[1].imm == value]
            assert len(matches) == 1
            header_rows.append(dict(owner=hex(va), site=hex(matches[0].address), offset=offset, value=value))
    result = dict(schema='richonline-independent-dependencies-1', status='PASS',
                  scope='有限依赖机械核验与指定机器语义；作者终稿另审',
                  disk_sha256=EXPECTED, sources=files, functions=functions,
                  bytes=sum(row['bytes'] for row in files), instructions=sum(row['instructions'] for row in files),
                  anchors={hex(site): list(value) for site, value in anchors.items()}, header_writes=header_rows,
                  callback='861190无栈参且ret；结合6BEF20 ret8和859CC0压栈顺序，错误为callback(type,3)',
                  ownership='85DBB0仅写连接指针slot；85DC50不删pointee；861040显式delete buffer base',
                  caveats=['请求type4确实存在；响应解析仅接受0..3，服务端type4回应未证',
                           '85D700谓词返回值不参与跳转，必须从85ACF0核副作用',
                           '析构深层与clear接口未闭合时只能登记局部责任'])
    (HERE / 'independent_dependency_validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: result[key] for key in ('status', 'scope', 'bytes', 'instructions')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
