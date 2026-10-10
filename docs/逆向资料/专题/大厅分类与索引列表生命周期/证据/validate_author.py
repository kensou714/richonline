"""大厅分类与索引列表的离线适配、PE核验和语义锚检查；不访问IDA。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
TOPIC = HERE.parent
DOCS = HERE.parents[2]
ROOT = DOCS.parents[1]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def read(relative):
    return json.loads((DOCS / relative).read_text('utf-8'))


def dump(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert sha(image) == EXPECTED
    pe = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    base = struct.unpack_from('<I', image, pe + 52)[0]
    section_at = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, section_at + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk(va, size):
        matches = [(rva, off) for _, rva, raw_size, off in sections
                   if rva <= va - base and va - base + size <= rva + raw_size]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        return image[off + va - base - rva:off + va - base - rva + size]

    raw_path = HERE / 'bounded_raw.json'
    raw = json.loads(raw_path.read_text('utf-8'))
    assert raw['disk_sha256'] == EXPECTED
    verified = {}

    def verify_ranges(node):
        if isinstance(node, dict):
            if all(k in node for k in ('start_va', 'size', 'idb_hex', 'disk_hex')):
                va, size = int(node['start_va'], 16), node['size']
                assert node['matching'] is True
                blob = bytes.fromhex(node['disk_hex'])
                assert len(blob) == size and node['idb_hex'] == node['disk_hex']
                assert disk(va, size) == blob and sha(blob) == node['sha256']
                key = (va, size)
                assert key not in verified or verified[key] == blob
                verified[key] = blob
            for value in node.values():
                verify_ranges(value)
        elif isinstance(node, list):
            for value in node:
                verify_ranges(value)

    verify_ranges(raw)
    table_path = HERE / 'type_table_raw.json'
    if not table_path.exists():
        table_path = HERE / 'type_tables/bounded_raw.json'
    assert table_path.exists(), '等待root类型/跳表IDA数据补证'
    tables = json.loads(table_path.read_text('utf-8'))
    verify_ranges(tables)
    windows = {int(x['start_va'], 16): bytes.fromhex(x['disk_hex']) for x in tables['data_windows']}
    assert len(windows[0xA673A4]) == 16
    pointers = struct.unpack('<4I', windows[0xA673A4])
    assert pointers == (0xA237BC, 0xA237B4, 0xA237B0, 0xA237AC)
    types = [windows[p] for p in pointers]
    assert types == [b'CHU\0', b'ZHONG\0', b'GAO\0', b'XIN\0']
    switch_targets = ((0x69FF18, 0x69FF2F, 0x69FF46, 0x69FF5D),
                      (0x6A08F8, 0x6A090F, 0x6A0926, 0x6A093D))
    for address, targets in zip((0x6A0083, 0x6A0A63), switch_targets):
        assert struct.unpack('<4I', windows[address]) == targets

    source_hashes = {}
    for item in raw['reuse_sources']:
        path = DOCS / item['path']
        assert sha(path.read_bytes()) == item['source_sha256'], item['path']
        source_hashes[item['path']] = item['source_sha256']
    old_lobby_path = '专题/大厅区域频道配置/证据/lobby_regions_ida_raw.json'
    old_ui_path = '专题/界面系统/ida_ui_chain_raw.json'
    lobby = read(old_lobby_path)
    ui = read(old_ui_path)
    old = {
        '0x6b8a60': (old_ui_path, '/functions/0x6b8a60', ui['functions']['0x6b8a60']),
        '0x69f750': (old_lobby_path, '/functions/1', lobby['functions'][1]),
        '0x6a0130': (old_lobby_path, '/functions/2', lobby['functions'][2]),
    }
    new = {x['seed_va']: (i, x) for i, x in enumerate(raw['functions'])}
    assert set(new) == {'0x69f6d0', '0x6a0b50', '0x6b8980', '0x6b8a00'}
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    functions, by_site = [], {}
    for audit in raw['current_chunk_audits']:
        va = audit['seed_va']
        assembly = []
        for block in audit['chunk_byte_ranges']:
            blob = bytes.fromhex(block['disk_hex'])
            decoded = list(decoder.disasm(blob, int(block['start_va'], 16)))
            assert sum(x.size for x in decoded) == len(blob)
            for insn in decoded:
                row = dict(va=hex(insn.address), size=insn.size,
                           text=insn.mnemonic + (' ' + insn.op_str if insn.op_str else ''),
                           hex=insn.bytes.hex())
                assembly.append(row)
                by_site[insn.address] = row
        if va in new:
            index, record = new[va]
            assert [x['site_va'] for x in record['assembly']] == [x['va'] for x in assembly]
            source = dict(path='bounded_raw.json', json_pointer=f'/functions/{index}',
                          source_sha256=sha(raw_path.read_bytes()))
        else:
            path, pointer, record = old[va]
            source = dict(path=path, json_pointer=pointer, source_sha256=source_hashes[path])
            if va == '0x6b8a60':
                # 原文本无地址；只核条数和顺序，地址来自独立当前块解码，绝不给旧文本补造VA。
                assert len(record['disassembly']) == len(assembly)
                aliases = {'retn': 'ret', 'jz': 'je', 'jnz': 'jne', 'jnb': 'jae'}
                old_mnemonics = [aliases.get(x.split()[0], x.split()[0]) for x in record['disassembly']]
                assert old_mnemonics == [x['text'].split()[0] for x in assembly]
            else:
                saved = record['instructions']
                assert [x['va'] for x in saved] == [x['va'] for x in assembly]
                assert all(x['hex'] == y['hex'] for x, y in zip(saved, assembly))
        functions.append(dict(
            va=va, evidence_kind='当前块独立解码；新旧IDA记录无损隔离', source=source,
            source_record_json=json.dumps(record, ensure_ascii=False, separators=(',', ':')),
            assembly=assembly, chunk_byte_ranges=audit['chunk_byte_ranges'],
            note='历史状态/结论被隔离为JSON字符串，不可被中央递归识别成新审阅'))
    assert len(functions) == 7
    manifest = json.loads((TOPIC / '函数审阅清单.json').read_text('utf-8'))
    assert [x['va'] for x in manifest['functions']] == [x['va'] for x in functions]
    assert len({x['va'] for x in manifest['functions']}) == 7
    for note in TOPIC.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in note.read_text('utf-8').splitlines()), note

    anchors = []

    def anchor(va, *parts):
        text = by_site[va]['text']
        assert all(part in text for part in parts), (hex(va), text, parts)
        anchors.append(dict(site_va=hex(va), text=text, expected_fragments=list(parts)))

    anchor(0x69F6EB, 'mov', ', 0')
    anchor(0x69F6F6, 'call', '0x61032d')
    anchor(0x69F713, 'cmp', ', 4')
    anchor(0x69F717, 'jae')
    anchor(0x69F71C, 'mov', '0xa673a4')
    anchor(0x69F728, 'call', '0x61038c')
    anchor(0x69F732, 'jne')
    anchor(0x6B899A, 'mov', '[eax]', ', 0')
    anchor(0x6B89A6, 'mov', '[ecx + 4]')
    anchor(0x6B89AF, 'mov', '[eax + 8]')
    anchor(0x6B89B8, 'shl', 'eax, 2')
    anchor(0x6B89CD, 'mov', '[ecx + 0xc]')
    anchor(0x6B89DD, 'ret', '8')
    anchor(0x6B8A1A, 'cmp', '[eax + 0xc]', ', 0')
    anchor(0x6B8A38, 'mov', '[ecx + 0xc], 0')
    anchor(0x6A0B88, 'mov', '[ecx + 0x5c], 0')
    anchor(0x6A0B92, 'mov', '[edx + 0x60], 0')
    for va, offset in ((0x6A0B9C, 0x198), (0x6A0BAA, 0x1A8), (0x6A0BB8, 0x1B8), (0x6A0BC6, 0x1C8)):
        anchor(va, 'add', 'ecx, ' + hex(offset))
    for va in (0x69FE91, 0x6A0871):
        anchor(va, 'mov', ', 0')
    for va, table in ((0x69FF11, 0x6A0083), (0x6A08F1, 0x6A0A63)):
        anchor(va, 'jmp', hex(table))
    for va in (0x69FF09, 0x6A08E9):
        anchor(va, 'ja')
    for va in (0x69FF18, 0x69FF2F, 0x69FF46, 0x69FF5D,
               0x6A08F8, 0x6A090F, 0x6A0926, 0x6A093D):
        anchor(va, 'mov', '[ebp - 0x1c8]')
    for va in (0x69FE78, 0x6A0858):
        anchor(va, 'mov', '0x130')
    for va in (0x69FAA6, 0x6A0486):
        anchor(va, 'mov', '[ebp - 0x1c8], 0')
    for va in (0x69FF78, 0x6A0958):
        anchor(va, 'add', 'edx, 1')
    # 清理只清base不清三个计数字段；通过整个已解码函数逐store集合检查，不依赖伪码。
    cleared = next(x for x in functions if x['va'] == '0x6b8a00')['assembly']
    assert sum('mov dword ptr [ecx + 0xc], 0' == x['text'] for x in cleared) == 1
    # 旧追加序列有符号容量比较，不把JL擅自改成unsigned门。
    add = next(x for x in functions if x['va'] == '0x6b8a60')['assembly']
    assert add[12]['text'] == 'cmp edx, dword ptr [ecx + 4]' and add[13]['text'].startswith('jl ')
    anchors.extend(dict(site_va=x['va'], text=x['text'], expected_fragments=['人工序列核验'])
                   for x in (add[12], add[13], add[20], add[21], add[31], add[60], add[68], add[74]))

    # 派生边界例仅解释已证指令；不是运行游戏或额外正确性证明。
    def classify(value):
        return next((i for i, item in enumerate(types) if value == item[:-1]), 0)
    examples = [(b'CHU', 0), (b'ZHONG', 1), (b'GAO', 2), (b'XIN', 3),
                (b'chu', 0), (b'gao', 0), (b'', 0), (b'GAO ', 0), (b'OTHER', 0)]
    assert all(classify(value) == result for value, result in examples)
    lists = [[], [], [], []]
    for index, (value, channel_id) in enumerate([(b'GAO', 900), (b'XIN', 3), (b'GAO', 777)]):
        lists[classify(value)].append(index)
    assert lists == [[], [], [0, 2], [1]]
    boundary_examples = dict(classification=[dict(input=x.decode('ascii'), result=y) for x, y in examples],
                             index_example=lists, note='由指令契约推导，不是动态验收')
    formal = dict(schema='richonline-lobby-list-formal-1', disk_sha256=EXPECTED,
                  raw_sha256=sha(raw_path.read_bytes()), functions=functions)
    dump('formal_functions.json', formal)
    dump('semantic_anchors.json', dict(anchors=anchors, derived_examples=boundary_examples))
    stats = dict(result='PASS', disk_sha256=EXPECTED, new_functions=4, reused_functions=3,
                 instructions=sum(len(x['assembly']) for x in functions),
                 chunk_bytes=sum(x['size'] for f in functions for x in f['chunk_byte_ranges']),
                 verified_unique_ranges=len(verified), data_window_count=len(windows),
                 direct_bridges=len(raw['verified_direct_bridges']), semantic_anchors=len(anchors),
                 source_hashes=source_hashes,
                 limitations='静态字节和有限语义；未联网、未运行游戏、未动态分配失败测试')
    dump('author_validation.json', stats)
    # 绑定作者交付集，不包含独审文件和本绑定本身，便于独审发现终稿后的变化。
    bound_paths = [TOPIC / '函数审阅清单.json', *sorted(TOPIC.glob('0[0-4]_*.txt')),
                   HERE / 'export_bounded.py', Path(__file__), raw_path,
                   HERE / 'formal_functions.json', HERE / 'semantic_anchors.json',
                   HERE / 'author_validation.json', table_path]
    dump('author_bindings.json', dict(files=[dict(path=str(p.relative_to(TOPIC)).replace('\\', '/'),
                                                  sha256=sha(p.read_bytes())) for p in bound_paths]))
    print(json.dumps({k: v for k, v in stats.items() if k != 'source_hashes'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
