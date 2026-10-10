"""独立核本轮重采比较/容器原证；区分四全局新入口与两旧CRT。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW = {
    'supplement_raw.json': ('5211fcf04136f28f57a91453be58a22d8f01304f98393371726d06a4ef9770bf',
                            {0x858e50, 0x858ea0, 0x922830, 0x9228e0}),
    'container_dependency/bounded_raw.json': ('50b81df4ceb2447338eee2df17334ebc7cc75944b9cc725dc30db056d05071cc',
                                              {0x85b800, 0x85b870}),
}
OLD_CRT = (
    ('聊天发送与重复提示契约/证据/chat_contract_discovery.json',
     '644a12d04a84e96ace1feefffca1d9a2e28d9e97d78d606374dd08f57742ae1a', 29, 0x922830, 'chunks'),
    ('文本过滤与字码转换/证据/functions_raw.json',
     '252d6277a508879819b61ddf615d2131b6d3e6380e4d072909741c8a7b147d29', 28, 0x9228e0, 'chunk_byte_ranges'),
)
ANCHORS = {
    0x858e6e: 'mov ecx, 0xacb8e8', 0x858ebe: 'cmp dword ptr [ebp + 8], 0',
    0x858ec2: 'jl 0x858ece', 0x858ec4: 'call 0x610cce',
    0x858ec9: 'cmp dword ptr [ebp + 8], eax', 0x858ecc: 'jl 0x858ed2',
    0x858ece: 'xor eax, eax', 0x858ed6: 'mov ecx, 0xacb8e8',
    0x858edb: 'call 0x606f49', 0x858ee0: 'mov eax, dword ptr [eax]',
    0x858ef5: 'ret', 0x922840: 'mov eax, dword ptr [edx]',
    0x922842: 'cmp al, byte ptr [ecx]', 0x922846: 'or al, al',
    0x922870: 'xor eax, eax', 0x922874: 'sbb eax, eax',
    0x922876: 'shl eax, 1', 0x922878: 'add eax, 1',
    0x92289c: 'mov ax, word ptr [edx]',
    0x9228e6: 'mov ecx, dword ptr [ebp + 0x10]', 0x9228e9: 'jecxz 0x922912',
    0x9228ed: 'mov edi, dword ptr [ebp + 8]',
    0x9228f4: 'repne scasb al, byte ptr es:[edi]',
    0x9228fc: 'mov esi, dword ptr [ebp + 0xc]',
    0x9228ff: 'repe cmpsb byte ptr [esi], byte ptr es:[edi]',
    0x922901: 'mov al, byte ptr [esi - 1]', 0x922906: 'cmp al, byte ptr [edi - 1]',
    0x922909: 'ja 0x922910', 0x92290d: 'sub ecx, 2',
    0x922910: 'not ecx', 0x922912: 'mov eax, ecx',
    0x85b826: 'cmp dword ptr [eax + 4], 0',
    0x85b83e: 'mov eax, dword ptr [ecx + 8]',
    0x85b841: 'sub eax, dword ptr [edx + 4]', 0x85b844: 'sar eax, 2',
    0x85b8a8: 'call 0x606d6e', 0x85b8af: 'call 0x6042b2',
    0x85b8b6: 'call 0x60c87c', 0x85b8ce: 'ret 4',
}


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    assert sha(image) == PE_SHA
    nt = struct.unpack_from('<I', image, 60)[0]
    assert image[nt:nt + 4] == b'PE\0\0' and struct.unpack_from('<H', image, nt + 24)[0] == 0x10b
    base = struct.unpack_from('<I', image, nt + 52)[0]
    table = nt + 24 + struct.unpack_from('<H', image, nt + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', image, nt + 6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    insns, rows, bridges, references, noncode, dump = {}, [], {}, [], [], []
    audited_ranges, reuse_sources = set(), {}

    def read(va, size):
        offsets = [off + va - base - rva for _, rva, length, off in sections
                   if rva <= va - base and va - base + size <= rva + length]
        assert len(offsets) == 1
        return image[offsets[0]:offsets[0] + size]

    def audit(c):
        va = int(c.get('start_va', c.get('va')), 16)
        b = read(va, c['size'])
        assert b.hex() == c['idb_hex'] == c['disk_hex'] and c['matching'] is True
        assert sha(b) == c['sha256']
        audited_ranges.add((va, len(b)))
        return b

    def scan(value):
        if isinstance(value, dict):
            if {'idb_hex', 'disk_hex', 'size'} <= value.keys() and value['disk_hex'] is not None:
                audit(value)
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    for name, (expected, seeds) in RAW.items():
        payload = (HERE / name).read_bytes()
        assert sha(payload) == expected
        raw = json.loads(payload)
        assert raw['disk_sha256'] == PE_SHA
        scan(raw)
        for ref in raw.get('reuse_sources', []):
            path = ROOT / 'docs/逆向资料' / ref['path']
            assert sha(path.read_bytes()) == ref['source_sha256']
            reuse_sources[ref['path']] = ref['source_sha256']
        assert {int(f['seed_va'], 16) for f in raw['functions']} == seeds
        for f in raw['functions']:
            body = []
            for c in f['chunk_byte_ranges']:
                b = audit(c)
                decoded = list(decoder.disasm(b, int(c['start_va'], 16)))
                assert sum(i.size for i in decoded) == len(b)
                body.extend(decoded)
            assert {i.address for i in body} == {int(a['site_va'], 16) for a in f['assembly']}
            assert len(body) == len(f['assembly'])
            data_sites = {int(a['site_va'], 16) for a in f['assembly'] if not a['is_code']}
            for i in body:
                insns[i.address] = i
                dump.append('// ' + hex(i.address) + ' ' + i.bytes.hex() + ' ' + i.mnemonic + ' ' + i.op_str
                            + (' [原证非代码填充]' if i.address in data_sites else ''))
                if i.address in data_sites:
                    noncode.append(dict(site_va=hex(i.address), bytes_hex=i.bytes.hex()))
            calls = {i.address: int(i.op_str, 16) for i in body
                     if i.mnemonic == 'call' and i.op_str.startswith('0x')}
            reported = [c for c in raw['calls'] if c['seed_va'] == f['seed_va']]
            assert set(calls) == {int(c['site_va'], 16) for c in reported}
            for c in reported:
                target = calls[int(c['site_va'], 16)]
                assert target == int(c['target_va'], 16)
                for site in c['bridges']:
                    assert target == int(site, 16)
                    b = read(target, 5)
                    assert b[0] == 0xe9
                    target += 5 + struct.unpack_from('<i', b, 1)[0]
                assert target == int(c['implementation_va'], 16)
            rows.append(dict(seed_va=f['seed_va'], byte_count=sum(c['size'] for c in f['chunk_byte_ranges']),
                             instruction_count=len(body) - len(data_sites), original_entries=len(body)))
        for c in raw['verified_direct_bridges']:
            b = audit(c)
            va = int(c['start_va'], 16)
            target = va + 5 + struct.unpack_from('<i', b, 1)[0]
            assert b[0] == 0xe9 and target == int(c['target_va'], 16)
            assert bridges.setdefault(va, target) == target
        for c in raw.get('current_chunk_audits', []):
            original = next(f for f in raw['functions'] if f['seed_va'] == c['seed_va'])
            assert c['chunk_byte_ranges'] == original['chunk_byte_ranges']
        references.extend(raw.get('data_references', []))
    assert noncode == [dict(site_va='0x922873', bytes_hex='90')]
    old_crt_sources = []
    for name, expected, index, va, key in OLD_CRT:
        payload = (ROOT / 'docs/逆向资料/专题' / name).read_bytes()
        assert sha(payload) == expected
        old = json.loads(payload)['functions'][index]
        assert old['va'] == hex(va)
        chunks = old[key]
        for c in chunks:
            b = read(int(c.get('va', c.get('start_va')), 16), c['size'])
            assert b.hex() == c.get('ida_hex', c.get('idb_hex')) == c['disk_hex']
            assert c.get('equal', c.get('matching')) is True
            assert 'sha256' not in c or sha(b) == c['sha256']
        current = next(f for f in json.loads((HERE / 'supplement_raw.json').read_bytes())['functions']
                       if f['seed_va'] == hex(va))
        assert [(int(c.get('va', c.get('start_va')), 16), c['size'], c['disk_hex']) for c in chunks] == [
            (int(c['start_va'], 16), c['size'], c['disk_hex']) for c in current['chunk_byte_ranges']]
        old_crt_sources.append(dict(owner_va=hex(va), path=name, sha256=expected,
                                    json_pointer='/functions/' + str(index), byte_count=sum(c['size'] for c in chunks)))
    reread_name = '聊天发送与重复提示契约/独审_IDA复读.json'
    reread_payload = (ROOT / 'docs/逆向资料/专题' / reread_name).read_bytes()
    reread_sha = 'eb5798e7281a473cae19a14fc28ff1a25deffe8e71c7a292014939a924dafd73'
    assert sha(reread_payload) == reread_sha
    assert json.loads(reread_payload)['functions'][29] == dict(va='0x922830', chunks=1, instructions=54)
    semantic = []
    for va, expected in ANCHORS.items():
        ins = insns[va]
        actual = (ins.mnemonic + ' ' + ins.op_str).rstrip()
        assert actual == expected, (hex(va), expected, actual)
        semantic.append(dict(site_va=hex(va), text=actual, bytes_hex=ins.bytes.hex()))
    assert all(i.mnemonic != 'cld' for a, i in insns.items() if 0x9228e0 <= a < 0x922919)
    result = dict(status='PASS', scope='六本轮重采依赖：四全局新入口、两旧CRT重采；作者终稿由主独审脚本绑定', pe_sha256=PE_SHA,
                  source_sha256={n: s for n, (s, _) in RAW.items()}, functions=rows,
                  old_crt_sources=old_crt_sources,
                  old_crt_reread=dict(path=reread_name, sha256=reread_sha, json_pointer='/functions/29'),
                  semantic_anchors=semantic, data_references=references,
                  noncode_padding=noncode, unique_bridges=len(bridges),
                  unique_audited_byte_ranges=len(audited_ranges), reused_sources=reuse_sources,
                  boundary='未执行客户端；DF=0是strncmp前提；迭代器深公式及生产/清理未闭合')
    (HERE / 'independent_supplement_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    (HERE / 'independent_supplement_assembly.txt').write_text('\n'.join(dump) + '\n', 'utf-8')
    return result


if __name__ == '__main__':
    print(verify()['status'])
