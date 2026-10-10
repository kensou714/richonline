"""离线核对局部PE字节、近转移、文档状态与明确包装契约；不执行游戏。"""
import ast
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def validate():
    source = HERE / 'wrapper.json'
    data = json.loads(source.read_text(encoding='utf-8'))
    image = Path(data['input']).read_bytes()
    assert hashlib.sha256(image).hexdigest() == data['disk_sha256']
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]
    spans = []

    def disk(ea, size):
        candidates = [(rva, off) for _, rva, raw, off in sections
                      if base + rva <= ea and ea + size <= base + rva + raw]
        assert len(candidates) == 1
        rva, off = candidates[0]
        start = off + ea - base - rva
        return image[start:start + size]

    def check(row):
        va, size = int(row['va'], 16), row['size']
        raw = bytes.fromhex(row['ida_hex'])
        assert len(raw) == size and raw.hex() == row['disk_hex']
        assert disk(va, size) == raw and row['equal'] is True
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        spans.append((va, va + size))
        return raw

    thunks = {}
    for row in data['thunks']:
        raw = check(row)
        ea, target = int(row['va'], 16), int(row['target'], 16)
        assert ea not in thunks and len(raw) == 5 and raw[0] == 0xE9
        assert ea + 5 + struct.unpack_from('<i', raw, 1)[0] == target
        thunks[ea] = target

    def resolve(ea):
        seen = set()
        while ea in thunks:
            assert ea not in seen
            seen.add(ea)
            ea = thunks[ea]
        return ea

    functions, count = {}, 0
    for f in data['functions']:
        assert f['va'] not in functions
        functions[f['va']] = f
        chunks = []
        for c in f['chunks']:
            assert int(c['end'], 16) == int(c['va'], 16) + c['size']
            chunks.append((int(c['va'], 16), check(c)))
        ins = {}
        for i in f['instructions']:
            ea, raw = int(i['va'], 16), bytes.fromhex(i['hex'])
            assert ea not in ins and len(raw) == i['size']
            parts = [(start, content) for start, content in chunks
                     if start <= ea and ea + len(raw) <= start + len(content)]
            assert len(parts) == 1
            start, content = parts[0]
            assert raw == content[ea - start:ea - start + len(raw)]
            ins[ea] = raw
            count += 1
        for call in f['calls']:
            site, target = int(call['site'], 16), int(call['target'], 16)
            raw = ins[site]
            if raw[0] in (0xE8, 0xE9):
                assert len(raw) == 5
                rel = struct.unpack_from('<i', raw, 1)[0]
            else:
                assert raw[0] == 0xEB and len(raw) == 2
                rel = struct.unpack_from('<b', raw, 1)[0]
            assert site + len(raw) + rel == target
            assert resolve(target) == int(call['resolved'], 16)
    assert set(functions) == {data['scope']['main']} | set(data['scope']['selected_functions'])
    for row in data['caller_navigation']:
        assert row['incoming'] in data['incoming']
        raw = check(row['window'])
        start = int(row['window']['va'], 16)
        for i in row['instructions']:
            offset = int(i['va'], 16) - start
            assert 0 <= offset and offset + i['size'] <= len(raw)
            assert raw[offset:offset + i['size']].hex() == i['hex']
    for row in data['incoming']:
        if row['iscode'] and row['caller']:
            site, entry = int(row['site'], 16), int(row['entry'], 16)
            raw = disk(site, 5)
            assert raw[0] == 0xE8
            assert site + 5 + struct.unpack_from('<i', raw, 1)[0] == entry
            assert resolve(entry) == int(row['resolved'], 16) == 0x6FA8E0
    # 七个包装的关键机器指令：固定索引、style地址、恢复原owner到ECX。
    wrappers = ((0x6FA840, 1, 0x8E1C70), (0x6FA890, 2, 0x8E1C70),
                (0x6FA8E0, 3, 0x8E1C70), (0x6FA960, 0, 0x8E1DB0),
                (0x6FA9E0, 1, 0x8E1DB0), (0x6FAA60, 2, 0x8E1DB0),
                (0x6FAAE0, 3, 0x8E1DB0))
    for va, index, callee in wrappers:
        raw = bytes.fromhex(functions[hex(va)]['chunks'][0]['ida_hex'])
        assert raw[0x12:0x21] == bytes([0x6A, index]) + bytes.fromhex('8b4dfc81c1a4000000518b4dfc')
        assert raw[-3:] == bytes.fromhex('c20400')
        assert any(c['resolved'] == hex(callee) for c in functions[hex(va)]['calls'])
    getters = ((0x6FA930, 200), (0x6FA9B0, 240), (0x6FAA30, 280), (0x6FAAB0, 320))
    for va, offset in getters:
        raw = bytes.fromhex(functions[hex(va)]['chunks'][0]['ida_hex'])
        assert raw[0x11:0x17] == b'\x8b\x80' + struct.pack('<I', offset)
        assert raw[-1] == 0xC3
    review = json.loads((HERE / 'function_review.json').read_text(encoding='utf-8'))
    assert set(review) == set(functions)
    for row in review.values():
        assert row['status'] in ('静态局部语义已审阅', '调用消费局部审阅', '相邻候选排除主范围')
        assert row['conclusion'] and row['boundary']
    docs = list(HERE.parent.glob('*.txt'))
    assert len(docs) >= 4
    for path in docs:
        lines = path.read_text(encoding='utf-8').splitlines()
        assert all(not x.strip() or x.startswith('//') for x in lines)
        assert all(x == x.rstrip() for x in lines)
        assert not any(re.match(r'//\s*(?:#{1,6}\s|```|[-*+]\s|\|)', x) for x in lines)
    for path in HERE.glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    merged = []
    for start, end in sorted(set(spans)):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    result = dict(status='PASS', source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  disk_sha256=data['disk_sha256'], idb_input_sha256=data['idb_input_sha256'],
                  whole_idb_identity_claimed=False, functions=len(functions), thunks=len(thunks),
                  instructions=count, incoming=len(data['incoming']),
                  navigation_windows=len(data['caller_navigation']), unique_spans=len(set(spans)),
                  unique_byte_coverage=sum(b - a for a, b in merged),
                  wrapper_instruction_cases=len(wrappers), getter_instruction_cases=len(getters),
                  scope='离线原证与显式指令契约；非机器码执行或实机')
    (HERE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                         encoding='utf-8', newline='\n')
    return result


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=False, indent=2))
