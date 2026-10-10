"""独立核验既有网络范围；这里只验复用事实，不给本专题完成结论。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
TARGETS = {0x6BEF20: (119, 39), 0x858FB0: (1620, 441),
           0x859980: (170, 54), 0x859CC0: (744, 230)}


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

    def disk(va, size):
        matches = [(rva, offset) for _, rva, length, offset in sections
                   if 0 <= va - base - rva and va - base - rva + size <= length]
        assert len(matches) == 1, (hex(va), size)
        rva, offset = matches[0]
        at = offset + va - base - rva
        raw = image[at:at + size]
        assert len(raw) == size
        return raw

    reused_path = HERE / 'reused_network.json'
    reused_bytes = reused_path.read_bytes()
    reused = json.loads(reused_bytes)
    assert reused['disk_sha256'] == EXPECTED
    sources = {}
    for source in reused['sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == source['sha256']
        sources[source['path']] = json.loads(raw)
    rows, instructions = [], {}
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for entry in reused['functions']:
        va = int(entry['seed_va'], 16)
        assert va in TARGETS and va not in instructions
        audit, record = entry['current_range_audit'], entry['record']
        assert int(record['va'], 16) == va == int(audit['start_va'], 16)
        size = int(record['end_va'], 16) - va
        assert size == audit['size'] == TARGETS[va][0]
        source = entry['source']
        original = next(row for row in sources[source['path']] if int(row['va'], 16) == va)
        assert original == record
        raw = disk(va, size)
        assert raw.hex() == audit['disk_hex']
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == audit['sha256']
        assert digest == entry['legacy_version_record']['disk_sha256']
        assert digest == entry['legacy_version_record']['idb_sha256']
        decoded = list(cs.disasm(raw, va))
        assert sum(item.size for item in decoded) == size
        cursor = va
        for item in decoded:
            assert item.address == cursor
            cursor += item.size
        assert len(decoded) == len(record['assembly']) == TARGETS[va][1]
        assert all(isinstance(line, str) for line in record['assembly'])
        instructions[va] = {item.address: (item.mnemonic, item.op_str) for item in decoded}
        rows.append(dict(seed_va=hex(va), bytes=size, instructions=len(decoded),
                         sha256=digest, source=source,
                         range_boundary='仅旧单区间原证；不补造IDA声明块'))
    assert instructions.keys() == TARGETS.keys()
    # 栈参数取址及清栈量必须由机器指令证明，不采用旧反编译器类型。
    anchors = {
        0x6BEF20: {
            0x6BEF2B: ('mov', 'eax, dword ptr [ebp + 8]'),
            0x6BEF41: ('mov', 'edx, dword ptr [ebp + 0xc]'),
            0x6BEF94: ('ret', '8'),
        },
        0x859CC0: {
            0x859F21: ('push', '3'),
            0x859F29: ('call', '0x60d4fc'),
            0x859F2E: ('push', 'eax'),
            0x859F2F: ('call', 'dword ptr [0xacb8c0]'),
            0x859F35: ('cmp', 'esi, esp'),
        },
        0x858FB0: {
            0x8590E5: ('cmp', 'dword ptr [ebp - 0x20], 3'),
            0x8590E9: ('ja', '0x8590fa'),
            0x8590F1: ('cmp', 'ecx, dword ptr [eax*4 + 0xa2f7d0]'),
            0x8590F8: ('je', '0x859101'),
            0x8590FA: ('xor', 'al, al'),
        },
    }
    for owner, sites in anchors.items():
        for site, expected in sites.items():
            assert instructions[owner][site] == expected, hex(site)
    bridge = disk(0x60D4FC, 5)
    assert bridge.hex() == 'e98f3c2500'
    assert 0x60D4FC + 5 + struct.unpack_from('<i', bridge, 1)[0] == 0x861190
    output = dict(schema='richonline-independent-network-reuse-1',
                  status='PASS', scope='仅四个复用单区间及十三个语义锚点；不是专题终审',
                  disk_sha256=EXPECTED,
                  reused_source_sha256=hashlib.sha256(reused_bytes).hexdigest(),
                  ranges=rows, byte_count=sum(row['bytes'] for row in rows),
                  instruction_count=sum(row['instructions'] for row in rows),
                  callback_abi='6BEF20读取两个DWORD栈参并ret 8；调用者错误参数待861190 ABI闭合',
                  anchors={hex(owner): {hex(site): list(value) for site, value in sites.items()}
                           for owner, sites in anchors.items()},
                  bridge=dict(va='0x60d4fc', bytes=bridge.hex(), target_va='0x861190',
                              boundary='当前磁盘五字节；独立函数声明须结合全量thunks来源审阅'),
                  pending=['861190读取器真实参数与返回契约', '本批完整声明块原证',
                           '请求生产到连接销毁、节点删除及下一次泵调用的闭环'])
    (HERE / 'independent_legacy_validation.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {key: output[key] for key in ('status', 'scope', 'byte_count', 'instruction_count')}


if __name__ == '__main__':
    print(json.dumps(verify(), ensure_ascii=True))
