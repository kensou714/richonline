"""离线复核文本节点原证；机器字节一致不自动提升语义审阅状态。"""
import hashlib
import json
import struct
from pathlib import Path
from verify_reused_owners import DOCS, EXPECTED_SHA, HERE, Image, audit_binding, audit_reuse

SEEDS = {0x6e52d0, 0x6fabe0, 0x6facf0, 0x6fad40, 0x8e02f0, 0x8eaa30, 0x8eaaf0}
ANCHORS = {
    0x6e5336: '81fa80000000', 0x6e5370: '83fa06',
    0x6e5380: '83f914', 0x6e5390: '83f846',
    0x6e53db: 'c6410800', 0x6e5470: 'c6400801', 0x6e558c: 'c6400800',
    0x6fac2f: '8915c4c3ac00', 0x6fac5e: '6a10', 0x6fad01: 'c6400800',
    0x6fad4e: '833dc4c3ac0000', 0x8e02f3: '8b8618510000',
    0x8e0310: '8b8620510000', 0x8e033e: 'e82f75d2ff',
    0x8eaa63: 'ff5340', 0x8eaa66: '83c410', 0x8eaa6f: '8b7104',
    0x8eaa99: '8935c4c3ac00', 0x8eaaa7: 'c21000',
    0x8eab37: 'ff5240', 0x8eab3a: '83c410', 0x8eab9a: 'c1e902',
    0x8eac53: '8915c4c3ac00', 0x8eac64: 'c21000',
}
REVIEWS = {
    0x6e52d0: ('局部路径已核', '六处分配建链、两种节点、WCHAR控制对条件及测宽累加已核；字体算法依赖未闭合。'),
    0x6fabe0: ('静态契约已审阅', '包括附属EH块：非空池弹头清字段，空池分配16B并条件构造；不扩展为CRT异常保证。'),
    0x6facf0: ('静态契约已审阅', 'ECX节点的+0/+4/+12以DWORD清零，+8以BYTE清零，返回节点；+9..11不写。'),
    0x6fad40: ('静态契约已审阅', '仅返回全局ACC3C4为空的布尔值，传入ECX不参与谓词。'),
    0x8e02f0: ('静态契约已审阅', '释放并清上下文+5118/+5120；全局池非空时取得节点后delete，最终清池头。'),
    0x8eaa30: ('局部路径已核', '对链DWORD+4求和；已有链保留，+40回调临时链反向接入空闲池；动态回调写者未闭合。'),
    0x8eaaf0: ('局部路径已核', '已核4参ABI、+40回调和临时链回收；固定522B暂存与按wcslen字节清源，不宣称安全过滤。'),
}


def adapt_formal(raw, raw_sha):
    functions = []
    for index, function in enumerate(raw['functions']):
        ranges = [dict(row, va=row['start_va']) for row in function['chunk_byte_ranges']]
        chunks = [dict(start_va=row['start_va'],
                       end_va=hex(int(row['start_va'], 16) + row['size']),
                       is_main=row['start_va'] == function['seed_va']) for row in ranges]
        functions.append(dict(va=function['seed_va'], end_va=function['end_va'],
                              name=function['name'], status='仅导出；审阅见分级清单',
                              assembly=[dict(row, va=row['site_va']) for row in function['assembly']],
                              pseudocode=function['pseudocode'], decompile_error=function['decompile_error'],
                              declared_chunks=chunks, byte_ranges=ranges, bytes_match_disk=True,
                              source='证据/bounded_raw.json', source_sha256=raw_sha,
                              json_pointer=f'/functions/{index}'))
    return dict(schema='richonline-formal-functions-1', disk_sha256=EXPECTED_SHA,
                source='bounded_raw.json', source_sha256=raw_sha,
                scope='仅机械适配；字段值与原证等价；语义级别另见函数审阅清单', functions=functions,
                thunks=[dict(row, va=row['start_va'], target=row['target_va'])
                        for row in raw['verified_direct_bridges']])


def semantic_review(image, raw):
    sites = {int(row['site_va'], 16) for function in raw['functions'] for row in function['assembly']}
    for site, code in ANCHORS.items():
        assert site in sites and image.read(site, len(code) // 2).hex() == code, hex(site)
    expected_acquires = {0x6e53af, 0x6e53e7, 0x6e5444, 0x6e547c, 0x6e5522, 0x6e555a}
    assert {int(row['site_va'], 16) for row in raw['calls']
            if row['seed_va'] == '0x6e52d0' and row['implementation_va'] == '0x6fabe0'} == expected_acquires
    assert {int(row['start_va'], 16) for row in next(function for function in raw['functions']
            if function['seed_va'] == '0x6fabe0')['chunk_byte_ranges']} == {0x6fabe0, 0xa13d00}
    return dict(semantic_anchor_sites=[hex(site) for site in ANCHORS],
                producer_acquire_sites=[hex(site) for site in sorted(expected_acquires)],
                binding_reuse=audit_binding(image))


def audit_bounded(image):
    raw = json.loads((HERE / 'bounded_raw.json').read_text(encoding='utf-8'))
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['topic'] == '文本控制节点池与操作'
    assert raw['disk_sha256'] == EXPECTED_SHA
    core = DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py'
    assert hashlib.sha256(core.read_bytes()).hexdigest() == raw['exporter_sha256']
    assert {int(row['seed_va'], 16) for row in raw['seeds']} == SEEDS
    audited = {}
    for row in raw['current_chunk_audits']:
        va = int(row['seed_va'], 16)
        assert va in SEEDS and va not in audited
        ranges = [image.check_range(chunk) for chunk in row['chunk_byte_ranges']]
        assert ranges
        assert any(int(chunk['start_va'], 16) == va for chunk in ranges)
        audited[va] = ranges
    assert set(audited) == SEEDS
    exported = {}
    for function in raw['functions']:
        va = int(function['seed_va'], 16)
        assert va in SEEDS and va not in exported
        ranges = [image.check_range(chunk) for chunk in function['chunk_byte_ranges']]
        assert ranges == audited[va]
        sites = [int(row['site_va'], 16) for row in function['assembly']]
        assert len(sites) == len(set(sites))
        for site in sites:
            assert any(int(chunk['start_va'], 16) <= site < int(chunk['end_va'], 16)
                       for chunk in ranges)
        exported[va] = function
    reused = {int(row['seed_va'], 16) for row in raw['reused_seeds']}
    assert set(exported).isdisjoint(reused)
    assert set(exported) | reused == SEEDS
    # E9 必须由导出器确认是独立声明的五字节桥，离线再核目标与链。
    bridges = {}
    for bridge in raw['verified_direct_bridges']:
        image.check_range(bridge)
        va = int(bridge['start_va'], 16)
        code = bytes.fromhex(bridge['idb_hex'])
        assert len(code) == 5 and code[0] == 0xe9
        target = va + 5 + struct.unpack_from('<i', code, 1)[0]
        assert target == int(bridge['target_va'], 16)
        assert va not in bridges
        bridges[va] = target
    for call in raw['calls']:
        va = int(call['target_va'], 16)
        for bridge in call['bridges']:
            assert va == int(bridge, 16) and va in bridges
            va = bridges[va]
        assert va == int(call['implementation_va'], 16)
        site = int(call['site_va'], 16)
        if image.read(site, 1) == b'\xe8':
            target = site + 5 + struct.unpack('<i', image.read(site + 1, 4))[0]
            assert target == int(call['target_va'], 16)
    windows = []
    candidates = list(raw['explicit_owner_windows'])
    for edges in raw['incoming'].values():
        candidates.extend(edge['owner_window'] for edge in edges if 'owner_window' in edge)
    for window in candidates:
        if window['owner_va'] is None:
            assert not window['assembly']
            continue
        rows = window['assembly']
        assert rows
        ranges = [image.check_range(row['bytes']) for row in rows]
        for index, row in enumerate(rows):
            assert row['site_va'] == ranges[index]['start_va']
            if index:
                assert ranges[index - 1]['end_va'] == ranges[index]['start_va']
        assert window['site_va'] in {row['site_va'] for row in rows}
        windows.append(dict(owner=window['owner_va'], start=ranges[0]['start_va'],
                            end=ranges[-1]['end_va'], site=window['site_va'],
                            scope='有限调用窗口；不计 owner 整函数语义覆盖'))
    sources = []
    for source in raw['reuse_sources']:
        path = DOCS / source['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['source_sha256']
        sources.append(dict(path=source['path'], sha256=source['source_sha256']))
    for string in raw['strings']:
        image.check_range(string['byte_audit'])
        width = string['unit_width']
        assert width in (1, 2)
        payload = bytes.fromhex(string['payload_hex'])
        nul = bytes(width)
        assert len(payload) % width == 0
        assert string['nul_hex'] == nul.hex()
        assert string['byte_audit']['idb_hex'] == (payload + nul).hex()
        assert all(payload[index:index + width] != nul for index in range(0, len(payload), width))
    virtual = []
    for row in raw['data_windows']:
        if row['matching'] is True:
            image.check_range(row)
            continue
        assert row['matching'] is None and row['disk_hex'] is None
        va, size = int(row['start_va'], 16), row['size']
        assert not any(0 <= va - image.base - rva and va - image.base - rva + size <= raw_size
                       for _, rva, raw_size, _ in image.sections)
        assert sum(0 <= va - image.base - rva and va - image.base - rva + size <= virtual_size
                   for virtual_size, rva, _, _ in image.sections) == 1
        if row['idb_hex'] is not None:
            data = bytes.fromhex(row['idb_hex'])
            assert len(data) == size
            assert hashlib.sha256(data).hexdigest() == row['sha256']
        virtual.append(dict(start=row['start_va'], size=size,
                            scope='静态虚拟区快照；不是磁盘字节或运行中池头'))
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//')
                   for line in path.read_text(encoding='utf-8').splitlines()), str(path)
    return dict(disk_sha256=EXPECTED_SHA, fresh_functions=len(exported), reused_seeds=len(reused),
                current_chunks=sum(len(chunks) for chunks in audited.values()),
                verified_e9_bridges=len(bridges), finite_windows=windows,
                reuse_sources=sources, static_virtual_windows=virtual,
                owner_reuse=audit_reuse(image),
                **semantic_review(image, raw),
                boundary='原证结构与字节验证；不自动登记业务语义完成')


def main():
    result = audit_bounded(Image())
    raw_bytes = (HERE / 'bounded_raw.json').read_bytes()
    raw = json.loads(raw_bytes)
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    formal = adapt_formal(raw, raw_sha)
    formal_path = HERE / 'formal_functions.json'
    formal_path.write_text(json.dumps(formal, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    assert json.loads(formal_path.read_text(encoding='utf-8')) == adapt_formal(raw, raw_sha)
    functions = [dict(va=hex(va), status=status, conclusion=conclusion,
                      evidence='证据/formal_functions.json', scope='本入口完整声明块的限定静态契约或局部路径',
                      unknown='没有实机；动态回调、字体算法、异常失败及线程重入图未闭合')
                 for va, (status, conclusion) in REVIEWS.items()]
    functions += [dict(va=hex(va), status='复用局部路径', conclusion=conclusion,
                       evidence='证据/reused_owner_audit.json', scope='旧原证全部声明块当前字节一致；只复核指定语义路径')
                  for va, conclusion in ((0x8e1620, '节点消费循环及活动链保留，不扩展为完整布局算法。'),
                                         (0x8ea2b0, '空闲池释放与上下文退出顺序，不扩展为所有控件析构。'))]
    windows = [dict(owner_va=row['owner'], start=row['start'], end=row['end'],
                    window_status='仅有限窗口核验', window_conclusion='调用点参数与后续局部操作已核；不能覆盖owner整函数',
                    evidence='证据/bounded_raw.json', site=row['site'])
               for row in result['finite_windows']]
    assert all({'va', 'status', 'conclusion'}.isdisjoint(row) for row in windows)
    review = dict(disk_sha256=EXPECTED_SHA, raw_source_sha256=raw_sha, functions=functions, windows=windows,
                  boundary='只按functions中的级别汇总；windows不得增加函数覆盖')
    (HERE.parent / '函数审阅清单.json').write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (HERE / 'bounded_audit.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    summary = dict(status='PASS', disk_sha256=EXPECTED_SHA, raw_source_sha256=raw_sha,
                   fresh_functions=7, current_chunks=result['current_chunks'],
                   review_levels={'静态契约已审阅': 4, '局部路径已核': 3, '复用局部路径': 2},
                   finite_windows=len(windows), verified_e9_bridges=result['verified_e9_bridges'],
                   semantic_anchors=len(ANCHORS), reused_owner_anchors=15,
                   formal_adapter_equivalent=True, doc_format_passed=True,
                   boundary='限定静态审阅；未执行客户端或回调，不证明线程、容量或失败安全')
    (HERE.parent / '验证结果.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status='PASS', fresh_functions=result['fresh_functions'],
                         current_chunks=result['current_chunks'],
                         finite_windows=len(result['finite_windows']),
                         verified_e9_bridges=result['verified_e9_bridges']), ensure_ascii=False))


if __name__ == '__main__':
    main()
