"""离线核验 IDA 原证并生成三 WORD 回调索引。"""
import collections
import hashlib
import json
import re
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
IMAGE = ROOT / 'RnClient.exe'
RAW = HERE / 'global_refs_raw.json'
EXPECTED_SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    image = IMAGE.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    assert digest == EXPECTED_SHA256
    raw = json.loads(RAW.read_text(encoding='utf-8'))
    assert raw['schema'] == 4 and raw['disk_sha256'] == digest
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, pe + 24)[0] == 0x10B
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + n * 40 + 8)
                for n in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def disk_bytes(ea, size):
        matches = [(rva, off) for _, rva, raw_size, off in sections
                   if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(matches) == 1, hex(ea)
        rva, off = matches[0]
        return image[off + ea - base - rva:off + ea - base - rva + size]

    def check_block(row):
        ea = int(row['va'], 16)
        size = row['size']
        assert int(row['end'], 16) - ea == size
        data = disk_bytes(ea, size)
        assert data.hex() == row['ida_hex'] == row['disk_hex']
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        assert row['equal'] is True

    for row in raw['globals'][:3]:
        check_block(row['bytes'])
    for row in raw['refs']:
        assert row['site_is_instruction'] is True
        check_block(row['bytes'])
        ins = row['instruction']
        assert ins['va'] == row['site'] and ins['size'] == row['bytes']['size']
        assert ins['hex'] == row['bytes']['ida_hex']
    for row in raw['windows']:
        check_block(row['block'])
        start, end = int(row['block']['va'], 16), int(row['block']['end'], 16)
        assert start <= int(row['site'], 16) < end
        for ins in row['instructions']:
            ea = int(ins['va'], 16)
            assert start <= ea < end and ea + ins['size'] <= end
            assert disk_bytes(ea, ins['size']).hex() == ins['hex']

    # 两个写入点在磁盘中分别为 E9 跳板；只确认静态目标。
    aliases = {}
    for ea, expected in ((0x60C5E3, 0x6BE2E0), (0x61029C, 0x6BE8D0)):
        code = disk_bytes(ea, 5)
        assert code[0] == 0xE9
        target = ea + 5 + struct.unpack_from('<i', code, 1)[0]
        assert target == expected
        aliases[hex(ea)] = dict(hex=code.hex(), target=hex(target))

    refs = raw['refs']
    counts = collections.Counter((row['target'], row['xref_type']) for row in refs)
    assert counts == {
        ('0xa6779c', 2): 130, ('0xa6779c', 3): 130,
        ('0xa6779e', 2): 130,
        ('0xa677a0', 2): 130, ('0xa677a0', 3): 130,
        ('0xacb864', 2): 2, ('0xacb864', 3): 93,
        ('0xacb868', 2): 2, ('0xacb868', 3): 38,
    }
    by_site = {row['site']: row for row in raw['windows']}
    calls = [row for row in refs if row['target'] in ('0xacb864', '0xacb868')
             and row['instruction']['text'].startswith('call')]
    reads = [row for row in refs if row['target'] == '0xa677a0' and row['xref_type'] == 3]
    writes = [row for row in refs if row['target'] in ('0xa6779c', '0xa6779e', '0xa677a0')
              and row['xref_type'] == 2]
    events = []
    for call in sorted(calls, key=lambda row: int(row['site'], 16)):
        window = by_site[call['site']]
        positions = [i for i, ins in enumerate(window['instructions']) if ins['va'] == call['site']]
        assert len(positions) == 1 and positions[0] > 0
        push = window['instructions'][positions[0] - 1]
        assert push['text'].startswith('push    ')
        immediate = re.match(r'push\s+((?:[0-9A-F]+h)|(?:[0-9]+))(?:\s*;.*)?$', push['text'])
        assert immediate, (call['site'], push['text'])
        value = immediate.group(1)
        category = int(value[:-1], 16) if value.endswith('h') else int(value)
        site = int(call['site'], 16)
        near_reads = [row for row in reads if row['owner'] == call['owner']
                      and 0 < site - int(row['site'], 16) < 80]
        near_reads.sort(key=lambda row: int(row['site'], 16), reverse=True)
        matched = bool(near_reads)
        fields = {}
        if matched:
            for target in ('0xa6779c', '0xa6779e', '0xa677a0'):
                candidates = [row for row in writes if row['target'] == target
                              and row['owner'] == call['owner']
                              and 0 < site - int(row['site'], 16) < 500]
                assert candidates, (call['site'], target)
                field = max(candidates, key=lambda row: int(row['site'], 16))
                fields[target] = dict(site=field['site'], text=field['instruction']['text'])
        events.append(dict(site=call['site'], owner=call['owner'], callback=call['target'],
                           category=category, category_push=push['va'],
                           payload_read=near_reads[0]['site'] if matched else None,
                           fields=fields,
                           scope='已声明函数局部路径' if call['owner'] else 'IDA无owner代码窗口'))
    assert len(events) == 131
    assert sum(bool(row['payload_read']) for row in events) == 130
    assert [row['site'] for row in events if not row['payload_read']] == ['0x829faa']
    assert sum(row['owner'] is None for row in events) == 8

    index = dict(schema=1, source='global_refs_raw.json schema 4',
                 definition='回调前直接 push 的类别；通过 A677A0 最近读取关联三 WORD 组',
                 events=events)
    (HERE / 'event_index.json').write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding='utf-8')
    report = dict(status='PASS', disk_sha256=digest, idb_input_sha256=raw['idb_input_sha256'],
                  ref_count=len(refs), callback_calls=len(calls), callback_windows=len(raw['windows']),
                  declared_owner_count=len({row['owner'] for row in refs if row['owner']}),
                  matched_payload_calls=130, without_payload=['0x829faa'],
                  undeclared_callback_calls=8, thunk_targets=aliases,
                  note='仅逐字节静态核验；未运行客户端、未修改EXE或IDB')
    (HERE / 'validation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    grouped = collections.defaultdict(list)
    for row in events:
        grouped[row['owner']].append(row)
    lines = [
        '// ============================================================================',
        '// 逐函数分级清单：A6779C 三 WORD 与本地回调',
        '// ============================================================================',
        '// 这里的“局部已审”仅覆盖字段赋值、构包、直接回调类别；不等于整函数业务恢复。',
        '// 所有条目都见 global_refs_raw.json 与 event_index.json；代码字节由 validation.json 核。',
        '//',
        '// 6BE090 / 指针生命周期局部已审：ACB864=60C5E3，ACB868=61029C。',
        '// 6BE1C0 / 指针生命周期局部已审：ACB864、ACB868 清零。',
        '// 两函数完整语义已有“启动线程与退出”等专题；这里不重复宣称全函完成。',
        '// 60C5E3 -> 6BE2E0、61029C -> 6BE8D0 / E9 跳板字节已核；消费端复用“登录与大厅状态”。',
        '//',
        '// 已声明 owner：每行给出 owner / 局部等级 / 回调站点与十进制类别。',
    ]
    for owner in sorted((key for key in grouped if key), key=lambda value: int(value, 16)):
        produced = grouped[owner]
        detail = ', '.join(f"{row['site'][2:].upper()}={row['category']}({row['callback'][2:].upper()})"
                           for row in produced)
        grade = '回调局部已审；无三WORD组' if owner == '0x828f60' else '三WORD构包及回调局部已审'
        lines.append(f'// {owner[2:].upper()} / {grade} / {detail}')
    lines += [
        '//',
        '// 无 IDA 函数 owner：仅站点前后局部窗口已核，不纳入上方已声明函数数。',
    ]
    for row in grouped[None]:
        lines.append(f"// {row['site'][2:].upper()} / 未声明代码局部窗口 / "
                     f"类别 {row['category']} 经 {row['callback'][2:].upper()}；边界、入口、可达性未审。")
    lines.append('//')
    (HERE.parent / '03_逐函数分级清单.txt').write_text('\n'.join(lines), encoding='utf-8')

    window_index = {row['site']: index for index, row in enumerate(raw['windows'])}
    event_index = {row['site']: index for index, row in enumerate(events)}
    function_reviews = []
    for owner, sites, conclusion in (
        ('0x6be090', ('0x6be0e8', '0x6be0f2'),
         '局部路径将 ACB864/ACB868 分别设为 60C5E3/61029C 两个跳板。'),
        ('0x6be1c0', ('0x6be210', '0x6be21a'),
         '局部路径将 ACB864/ACB868 两个指针都清零。'),
    ):
        function_reviews.append(dict(
            va=owner, status='回调指针生命周期局部已审阅',
            scope='只审两处全局指针赋值，不覆盖整函数线程与对象生命周期',
            conclusion=conclusion,
            evidence=[f'证据/global_refs_raw.json/windows/{window_index[site]}' for site in sites]
                     + ['证据/validation.json'],
            boundary='整体线程初始化/退出行为复用启动线程与退出专题；运行时调用顺序未在本专题验证。',
            reuse_reference='专题/启动线程与退出'))
    for owner in sorted((key for key in grouped if key), key=lambda value: int(value, 16)):
        rows = grouped[owner]
        description = '；'.join(
            f"{row['site'][2:].upper()} 经 {row['callback'][2:].upper()} 触发本地类别 {row['category']}"
            for row in rows)
        exception = owner == '0x828f60'
        function_reviews.append(dict(
            va=owner,
            status='局部变量构包回调已审阅' if exception else '三WORD构包回调局部已审阅',
            scope='仅回调附近字段写入、栈参数构造及直接类别；非整函数语义审阅',
            conclusion=(('局部变量而非 A6779C 全局组三WORD；' if exception
                         else 'A6779C/A6779E/A677A0 三WORD 写入后读回构包；') + description),
            evidence=[f'证据/global_refs_raw.json/windows/{window_index[row["site"]]}'
                      for row in rows]
                     + [f'证据/event_index.json/events/{event_index[row["site"]]}'
                        for row in rows]
                     + ['证据/validation.json'],
            boundary='其它分支、回调消费端及运行时可达性未在本专题完整审阅；类别不等于网络 wire_type。'))
    known = {int(row['va'], 16) for row in json.loads(
        (ROOT / 'docs/逆向资料/全量分析/functions.json').read_text(encoding='utf-8'))}
    assert len(function_reviews) == 122
    assert all(int(row['va'], 16) in known for row in function_reviews)
    review = dict(scope='仅 A6779C 三WORD 构包及 ACB864/868 指针生命周期局部路径',
                  pe_sha256=digest, declared_functions=len(function_reviews),
                  functions=function_reviews,
                  undeclared_call_sites=[dict(site=row['site'], callback=row['callback'],
                                              category=row['category'],
                                              evidence=f'证据/global_refs_raw.json/windows/{window_index[row["site"]]}',
                                              boundary='IDA 无函数 owner；只作为代码站点导航，不计函数审阅')
                                         for row in grouped[None]])
    (HERE.parent / '函数审阅清单.json').write_text(
        json.dumps(review, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
