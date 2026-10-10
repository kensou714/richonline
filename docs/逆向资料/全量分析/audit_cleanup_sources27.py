"""只读预审两份历史清理函数原证；不写中央台账、历史文件或测试输出。"""
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCES = {
    'cleanup_targets_full.json': 'a496de5fc366a794677e2b7274c36de7389de4da99614d79be99cf881681f4c2',
    'unwind_runtime.json': 'b48146affced509befb371f5551880fea9f866018ba739b7c94eb0f65c73b384',
}
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
EXPECTED_MISSING = set('''7ecd80 7ecf70 841fb0 8437f0 8690d0 869120 869300
86bff0 86d270 86d670 870ec0 870f10 871190 8711e0 871bc0 871c10
87a410 87a460 87a960 87aa20 87ab80 87dcf0 87e5a0 87e5f0 87e970
87f5b0 87f600 87f7e0 87f8d0 8848b0 884900 88bfd0 88c0e0 88c2d0
88e990 88eab0 8a00a0 8a0390 8a0670 8a0960 8a0d00 8d95f0 8da200
91fe50 92cbf0 931190'''.split())
EXPECTED_MISSING = {'0x' + va for va in EXPECTED_MISSING}
CHINESE_SOURCES = (
    '专题/移动与动画协议/证据/movement_protocol_core.json',
    '专题/地图与路径/证据/map_runtime_core.json',
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def audit():
    snapshot = read(HERE / '第二十六批推进快照.json')
    frozen = {item['path']: item['sha256'] for item in snapshot['source_fingerprints']}
    # 仅保存两个中央文件与本次四份来源有关的集合投影，后续归并不改变本次差分口径。
    projection_path = HERE / '第二十六批尾块来源预审基线.json'
    assert sha(projection_path) == 'f46f4d507d1868bf33fa1d47a8bf617396b680fcf6c64fc760a246fc08cab179'
    projection = read(projection_path)
    assert projection['冻结快照SHA256'] == sha(HERE / '第二十六批推进快照.json')
    assert projection['中央来源SHA256'] == {name: frozen[name] for name in
        ('evidence_coverage.json', 'review_coverage.json')}
    assert projection['原证总入口数'] == snapshot['unique_exported_functions'] == 6052
    assert not projection['已有白名单来源关系']
    previous = {va: {'evidence': []} for va in projection['已有原证入口集合']}
    reviews = {va: {} for va in projection['已有显式审阅入口集合']}
    required = set(projection['所需入口集合'])
    # 若当前中央仍为第二十六批，额外重算投影；后续中央改变后仍使用已冻结投影。
    for name, expected_set in [('evidence_coverage.json', set(previous)),
                               ('review_coverage.json', set(reviews))]:
        path = HERE / name
        if sha(path) == frozen[name]:
            actual = {r['va'] for r in read(path)['functions']} & required
            assert actual == expected_set
    for relative, digest in projection['专题来源SHA256'].items():
        assert sha(HERE.parent / relative) == digest
    inventory = {r['va']: r for r in read(HERE / 'functions.json')}
    image_path = ROOT / 'RnClient.exe'
    image = image_path.read_bytes()
    assert hashlib.sha256(image).hexdigest() == PE_SHA
    nt = struct.unpack_from('<I', image, 0x3c)[0]
    assert image[:2] == b'MZ' and image[nt:nt + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt + 24)[0] == 0x10b
    base = struct.unpack_from('<I', image, nt + 52)[0]
    section_count = struct.unpack_from('<H', image, nt + 6)[0]
    optional_size = struct.unpack_from('<H', image, nt + 20)[0]
    sections = []
    for i in range(section_count):
        at = nt + 24 + optional_size + 40 * i
        _, rva, raw_size, offset = struct.unpack_from('<4I', image, at + 8)
        flags = struct.unpack_from('<I', image, at + 36)[0]
        sections.append((base + rva, raw_size, offset, flags))

    def check_span(span):
        address, size = int(span['va'], 16), span['size']
        assert type(size) is int and size > 0
        raw = bytes.fromhex(span['idb_hex'])
        assert len(raw) == size and span['matching'] is True
        assert raw == bytes.fromhex(span['disk_hex'])
        matches = [(start, offset) for start, length, offset, flags in sections
                   if flags & 0x20000000 and start <= address < address + size <= start + length]
        assert len(matches) == 1, hex(address)
        start, offset = matches[0]
        assert image[offset + address - start:offset + address - start + size] == raw, hex(address)
        return set(range(address, address + size))

    watched = [projection_path, image_path, HERE / '第二十六批推进快照.json']
    watched += [HERE / '异常尾块与清理契约' / name for name in SOURCES]
    before = {str(path): sha(path) for path in watched}
    groups, all_addresses, all_thunks = [], set(), set()
    source_pairs, new_pairs = set(), set()
    for name, digest in SOURCES.items():
        path = HERE / '异常尾块与清理契约' / name
        assert sha(path) == digest
        data = read(path)
        assert data['disk_sha256'] == PE_SHA
        assert isinstance(data['functions'], list) and isinstance(data['thunks'], list)
        group = dict(source='全量分析/异常尾块与清理契约/' + name,
                     functions=0, instructions=0, byte_ranges=0, bytes=0,
                     declared_chunks=0, tail_chunks=0, thunks=0, entries=[])
        seen = set()
        for index, function in enumerate(data['functions']):
            va = function['va']
            assert va in inventory and va not in seen
            assert function['end_va'] == inventory[va]['end_va']
            assert function['bytes_match_disk'] is True
            assert isinstance(function['assembly'], list) and function['assembly']
            assert function['assembly'][0]['va'] == va
            assert isinstance(function['pseudocode'], list)
            chunks = function['declared_chunks']
            main = [c for c in chunks if c['is_main'] is True]
            assert len(main) == 1
            assert main[0]['start_va'] == va and main[0]['end_va'] == function['end_va']
            covered = set()
            for span in function['byte_ranges']:
                block = check_span(span)
                assert not (covered & block), (name, va, '重叠字节')
                covered |= block
                group['byte_ranges'] += 1
                group['bytes'] += span['size']
            declared = set()
            for chunk in chunks:
                lo, hi = int(chunk['start_va'], 16), int(chunk['end_va'], 16)
                assert lo < hi
                assert not (declared & set(range(lo, hi)))
                declared.update(range(lo, hi))
            assert covered == declared, (name, va, '声明块与保存字节边界不同')
            instruction_sites = [int(i['va'], 16) for i in function['assembly']]
            assert len(instruction_sites) == len(set(instruction_sites))
            assert set(instruction_sites) <= covered
            source_pair = (va, group['source'])
            source_pairs.add(source_pair)
            if group['source'] not in previous.get(va, {}).get('evidence', []):
                new_pairs.add(source_pair)
            group['entries'].append(dict(va=va, pointer='/functions/' + str(index),
                                         absent_in_batch26=va not in previous,
                                         explicit_review_in_batch26=va in reviews))
            seen.add(va)
            group['functions'] += 1
            group['instructions'] += len(function['assembly'])
            group['declared_chunks'] += len(chunks)
            group['tail_chunks'] += sum(c['is_main'] is False for c in chunks)
        for thunk in data['thunks']:
            check_span(thunk)
            raw = bytes.fromhex(thunk['idb_hex'])
            assert len(raw) == 5 and raw[0] == 0xe9
            assert int(thunk['va'], 16) + 5 + struct.unpack('<i', raw[1:])[0] == int(thunk['target'], 16)
            assert thunk['va'] in inventory
            all_thunks.add(thunk['va'])
            group['thunks'] += 1
        all_addresses |= seen
        groups.append(group)
    missing = all_addresses - previous.keys()
    assert len(all_addresses) == 78 and len(source_pairs) == len(new_pairs) == 78
    assert missing == EXPECTED_MISSING and len(missing) == 46
    assert not missing & reviews.keys()
    assert len(all_addresses & reviews.keys()) == 31
    assert (all_addresses & previous.keys()) - reviews.keys() == {'0x80e100'}
    chinese = set()
    for relative in CHINESE_SOURCES:
        data = read(HERE.parent / relative)
        chinese.update(hex(int(row['地址'], 16)) for row in data['函数'])
    chinese_missing = chinese - previous.keys()
    assert len(chinese) == 159 and len(chinese_missing) == 39
    assert not missing & chinese_missing
    assert all_addresses | chinese == set(projection['所需入口集合'])
    # 裸桥只逐字节核验，不使用主体投影去推算它们的历史存在性。
    assert len(all_thunks) == 93
    assert before == {str(path): sha(Path(path)) for path in before}, '检查期间原件发生变化'
    return dict(status='PASS', pe_sha256=PE_SHA,
                baseline_evidence_sha256=frozen['evidence_coverage.json'],
                baseline_review_sha256=frozen['review_coverage.json'], groups=groups,
                unique_bodies=len(all_addresses), historical_missing_bodies=len(missing),
                missing_body_vas=sorted(missing, key=lambda va: int(va, 16)),
                added_source_pairs=len(new_pairs),
                existing_reviewed_bodies=len(all_addresses & reviews.keys()),
                missing_bodies_already_reviewed=len(missing & reviews.keys()),
                chinese_historical_missing=len(chinese_missing), intersection_with_chinese=[],
                combined_historical_missing=len(missing | chinese_missing),
                excluded_thunks=len(all_thunks),
                writes=0)


if __name__ == '__main__':
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
