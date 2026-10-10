"""第二十五批中央独审；准备完成前禁止正式检查，不运行作者生成程序。"""
import argparse
import hashlib
import importlib.util
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent
BASE_PATH = HERE / 'independent_snapshot_audit24.py'
BASE_SHA = 'b9817f7d3dc1d26ddc499a90a70aaab02fb23f0d1b104fe15780fb46f40538a0'
assert hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() == BASE_SHA
SPEC = importlib.util.spec_from_file_location('frozen_independent_audit24', BASE_PATH)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
load, digest, pointer, walk, va = BASE.load, BASE.digest, BASE.pointer, BASE.walk, BASE.va
Image, PE_SHA = BASE.Image, BASE.PE_SHA
READY = True
TOPICS = {
    '124字节共享数组生命周期': {'fresh': 3, 'reused': 2},
    '股票数值辅助与组合消费': {'fresh': 7, 'reused': 0},
    '名称查找与等待消费者': {'fresh': 4, 'reused': 1},
    '基础边框与派生绘制消费': {'fresh': 4, 'reused': 1},
}
BASE.TOPICS = TOPICS
FRESH = {
    '124字节共享数组生命周期': ['0x6a4a80', '0x6a4860', '0x6b7cb0'],
    '股票数值辅助与组合消费': ['0x6c1c80', '0x6c1d00', '0x6c1d80', '0x6c08b0', '0x6c0960', '0x6c0bf0', '0x6c0ce0'],
    '名称查找与等待消费者': ['0x6b20a0', '0x6b81d0', '0x6ad9f0', '0x73d560'],
    '基础边框与派生绘制消费': ['0x8e41d0', '0x90c070', '0x902180', '0x90a430'],
}
SUPPLEMENTS = {
    '124字节共享数组生命周期': ['0x6b7c60', '0x6a76e0', '0x6b9af0', '0x6a1190'],
    '名称查找与等待消费者': ['0x858e50', '0x858ea0', '0x922830', '0x9228e0'],
    '基础边框与派生绘制消费': ['0x8ea8d0'],
}
REVIEWED_VAS = {
    '124字节共享数组生命周期': FRESH['124字节共享数组生命周期'] + [
        '0x69e600', '0x6ab5f0', '0x622d50', '0x6a2350', '0x91bd80', '0x91bd30', '0x91f7e0'] + SUPPLEMENTS['124字节共享数组生命周期'],
    '股票数值辅助与组合消费': FRESH['股票数值辅助与组合消费'],
    '名称查找与等待消费者': FRESH['名称查找与等待消费者'] + ['0x6aebe0'] + SUPPLEMENTS['名称查找与等待消费者'] + ['0x85b800', '0x85b870'],
    '基础边框与派生绘制消费': FRESH['基础边框与派生绘制消费'] + ['0x8e46e0', '0x8ea8d0'],
}
FINAL_FILES = {
    name: ('函数审阅清单.json', 'independent_review_validation.json') if name == '股票数值辅助与组合消费'
          else ('function_review.json', 'independent_validation.json') for name in TOPICS
}


def normalized_record(old, name, ref, sha, scope):
    address = old.get('seed_va', old.get('va', old.get('address')))
    chunks = old.get('chunk_byte_ranges', old.get('chunks', old.get('byte_ranges')))
    assembly = old.get('assembly', old.get('instructions'))
    normalized = [dict(start_va=c.get('start_va', c.get('va', c.get('address'))),
        **{k: v for k, v in c.items() if k not in ('start_va', 'va', 'address')}) for c in chunks]
    wanted = dict(old, va=address, source_path=name, source_pointer=ref, source_sha256=sha,
        source_field_pointers={k: ref + '/' + k for k in old}, adaptation_scope=scope,
        normalized_chunks=normalized, normalized_assembly=[dict(
            site_va=x.get('site_va', x.get('va', x.get('address'))), text=x['text'],
            is_code=x.get('is_code', True), original=x) for x in assembly])
    wanted.setdefault('declared_chunks', [dict(start_va=c['start_va'],
        end_va=hex(va(c['start_va']) + c['size']), is_main=c['start_va'] == address) for c in normalized])
    wanted.setdefault('byte_ranges', chunks)
    return wanted


def fresh_adaptations(directory, image):
    path = directory / '证据/bounded_raw.json'
    raw, formal, sha = load(path), load(directory / '证据/formal_functions.json'), digest(path)[1]
    assert [r['seed_va'] for r in raw['functions']] == FRESH[directory.name]
    assert formal['disk_sha256'] == raw['disk_sha256'] == PE_SHA
    assert len(formal['functions']) == len(raw['functions'])
    for i, (old, new) in enumerate(zip(raw['functions'], formal['functions'])):
        if directory.name == '股票数值辅助与组合消费':
            wanted = normalized_record(old, path.relative_to(ROOT).as_posix(), f'/functions/{i}', sha, '本批新原证无损适配')
        else:
            chunks = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'})
                      for c in old['chunk_byte_ranges']]
            wanted = dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'],
                status='机械适配；语义见function_review.json',
                assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in old['assembly']],
                pseudocode=old['pseudocode'], decompile_error=old['decompile_error'],
                declared_chunks=[dict(start_va=c['va'], end_va=hex(va(c['va']) + c['size']),
                    is_main=c['va'] == old['seed_va']) for c in chunks], chunk_byte_ranges=chunks,
                bytes_match_disk=all(c['matching'] is True for c in chunks),
                source=dict(path='证据/bounded_raw.json', sha256=sha, json_pointer=f'/functions/{i}'))
        assert new == wanted, (directory.name, i)
        for chunk in old['chunk_byte_ranges']:
            assert image.check(chunk) == 'disk'
    if directory.name == '股票数值辅助与组合消费':
        helper = ROOT / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
        assert formal['adapter_helper_sha256'] == digest(helper)[1]
        specs = [('专题/股票与交易流程/证据/stock_core.json', '/functions/2', '0x6283e0', '旧根局部契约复用'),
                 ('专题/高扇入界面操作辅助/证据/dependency_raw.json', '/functions/2', '0x922798', '既有运行库窄转换契约复用')]
        reused = load(directory / '证据/reused_functions.json')
        assert len(reused['functions']) == 2 and reused['disk_sha256'] == PE_SHA
        for row, (name, ref, address, scope) in zip(reused['functions'], specs):
            source = ROOT / name
            old = pointer(load(source), ref)
            assert old['va'] == address
            assert row == normalized_record(old, name, ref, digest(source)[1], scope)
            for chunk in row['normalized_chunks']:
                BASE.byte_record_check(chunk, image)
    else:
        assert formal['source_sha256'] == sha
    return len(raw['functions'])


def exact_reuse(directory):
    path = directory / '证据/reused_raw.json'
    if not path.exists():
        return []
    records = load(path)['records']
    expected_counts = {'124字节共享数组生命周期': 14, '名称查找与等待消费者': 8, '基础边框与派生绘制消费': 3}
    assert len(records) == expected_counts[directory.name]
    copied_reviews = []
    for index, row in enumerate(records):
        source = (path.parent / row['source']['path']).resolve()
        assert source.is_relative_to(ROOT)
        assert digest(source)[1] == row['source']['sha256']
        original = pointer(load(source), row['source']['pointer'])
        assert row['original_record'] == original
        assert original.get('va', original.get('address')) == row['va']
        for node, ref in walk(original):
            if is_review(node):
                copied_reviews.append(dict(va=address_of(node), source=path.relative_to(ROOT).as_posix(),
                    json_pointer=f'/records/{index}/original_record' + ('' if ref == '/' else ref),
                    original_source=source.relative_to(ROOT).as_posix(),
                    original_pointer=row['source']['pointer'] + ('' if ref == '/' else ref), original=node))
    return copied_reviews


def is_review(row):
    return isinstance(row.get('status'), str) and isinstance(row.get('conclusion'), str) and any(
        key in row for key in ('va', 'address', 'ea', '地址'))


def address_of(row):
    return hex(va(row.get('va', row.get('address', row.get('ea', row.get('地址'))))))


def supplement_bytes(directory, image):
    if directory.name not in SUPPLEMENTS:
        return {}
    source = load(directory / '证据/supplement_raw.json')
    assert source['disk_sha256'] == PE_SHA
    assert source['seeds'] == [row['seed_va'] for row in source['functions']] == SUPPLEMENTS[directory.name]
    sizes = {}
    for row in source['functions']:
        for chunk in row['chunk_byte_ranges']:
            assert image.check(chunk) == 'disk'
        assert va(row['end_va']) == max(va(c['start_va']) + c['size'] for c in row['chunk_byte_ranges'])
        assert all(any(va(c['start_va']) <= va(item['site_va']) < va(c['start_va']) + c['size']
                       for c in row['chunk_byte_ranges']) for item in row['assembly'])
        sizes[row['seed_va']] = sum(c['size'] for c in row['chunk_byte_ranges'])
    for row in source['verified_direct_bridges']:
        assert image.check(row) == 'disk'
        raw = bytes.fromhex(row['idb_hex'])
        assert row['size'] == 5 and raw[0] == 0xe9
        assert va(row['target_va']) == va(row['start_va']) + 5 + struct.unpack_from('<i', raw, 1)[0]
    for row in source['data_windows']:
        image.check(row)
    return sizes


def simple_adaptation(old, name, sha, index, status):
    chunks = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'})
              for c in old['chunk_byte_ranges']]
    return dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'], status=status,
        assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in old['assembly']],
        pseudocode=old['pseudocode'], decompile_error=old['decompile_error'],
        declared_chunks=[dict(start_va=c['va'], end_va=hex(va(c['va']) + c['size']),
            is_main=c['va'] == old['seed_va']) for c in chunks], chunk_byte_ranges=chunks,
        bytes_match_disk=all(c['matching'] is True for c in chunks),
        source=dict(path=name, sha256=sha, json_pointer=f'/functions/{index}'))


def supplement_adaptations(directory):
    if directory.name == '股票数值辅助与组合消费':
        return 0
    path = directory / '证据/supplement_raw.json'
    raw, sha = load(path), digest(path)[1]
    if directory.name == '124字节共享数组生命周期':
        formal = load(directory / '证据/supplement_formal.json')
        rows = formal['functions']
        assert formal['disk_sha256'] == PE_SHA and formal['source_sha256'] == sha
        status = '机械适配；补证语义见function_review.json'
    elif directory.name == '基础边框与派生绘制消费':
        formal = load(directory / '证据/formal_functions.json')
        rows = formal['dependency_functions']
        assert formal['supplement_sha256'] == sha
        assert formal['data_windows'] == raw['data_windows']
        status = '必要依赖机械适配；不增加固定四主体'
    else:
        formal = load(directory / '证据/supplement_formal.json')
        rows = formal['functions']
        assert formal['disk_sha256'] == PE_SHA and formal['source_sha256'] == sha
        status = '必要依赖无损机械适配；语义见function_review.json'
    assert len(rows) == len(raw['functions'])
    for i, (old, new) in enumerate(zip(raw['functions'], rows)):
        assert new == simple_adaptation(old, '证据/supplement_raw.json', sha, i, status)
    if directory.name == '名称查找与等待消费者':
        name = '证据/container_dependency/bounded_raw.json'
        path = directory / name
        raw, sha = load(path), digest(path)[1]
        formal = load(directory / '证据/container_formal.json')
        assert formal['disk_sha256'] == PE_SHA and formal['source_sha256'] == sha
        assert len(formal['functions']) == len(raw['functions']) == 2
        for i, (old, new) in enumerate(zip(raw['functions'], formal['functions'])):
            assert new == simple_adaptation(old, name, sha, i, '必要容器依赖无损适配；下层模板语义限定')
        return len(rows) + 2
    return len(rows)


def container_bytes(image):
    path = ROOT / '专题/名称查找与等待消费者/证据/container_dependency/bounded_raw.json'
    assert digest(path)[1] == '50b81df4ceb2447338eee2df17334ebc7cc75944b9cc725dc30db056d05071cc'
    raw = load(path)
    assert raw['disk_sha256'] == PE_SHA
    assert [r['seed_va'] for r in raw['functions']] == ['0x85b800', '0x85b870']
    assert not raw['reused_seeds']
    sizes = {}
    for row in raw['functions']:
        for chunk in row['chunk_byte_ranges']:
            assert image.check(chunk) == 'disk'
        sizes[row['seed_va']] = sum(c['size'] for c in row['chunk_byte_ranges'])
    assert sizes == {'0x85b800': 90, '0x85b870': 97}
    for row in raw['verified_direct_bridges']:
        assert image.check(row) == 'disk'
        bytecode = bytes.fromhex(row['idb_hex'])
        assert row['size'] == 5 and bytecode[0] == 0xe9
        assert va(row['target_va']) == va(row['start_va']) + 5 + struct.unpack_from('<i', bytecode, 1)[0]
    for row in raw['data_windows']:
        image.check(row)
    return sizes


def navigation_reuse(directory):
    if directory.name != '名称查找与等待消费者':
        return
    path = directory / '证据/source_navigation.json'
    navigation = load(path)
    assert len(navigation['owners']) == 2
    for row in navigation['owners']:
        source = (path.parent / row['source']['path']).resolve()
        assert digest(source)[1] == row['source']['sha256']
        assert row['original_record'] == pointer(load(source), row['source']['pointer'])
    path = directory / '证据/network_production_navigation.json'
    network = load(path)
    source = (path.parent / network['source']['path']).resolve()
    assert digest(source)[1] == network['source']['sha256']
    assert network['original_document'] == load(source)
    assert not any(is_review(row) for row, _ in walk(network))
    path = directory / '证据/container_template_navigation.json'
    template = load(path)
    source = (path.parent / template['source']['path']).resolve()
    assert source == (ROOT / '专题/高扇入函数群筛选/证据/highfanout_raw.json').resolve()
    assert digest(source)[1] == template['source']['sha256'] and template['source']['pointer'] == '/targets/3'
    assert template['original_record'] == pointer(load(source), '/targets/3')
    assert template['original_record']['va'] == '0x85bb10'
    assert not any(is_review(row) for row, _ in walk(template))


def auxiliary_bytes(image):
    path = ROOT / '专题/124字节共享数组生命周期/证据/callback_bridge.json'
    raw = load(path)
    assert raw['disk_sha256'] == PE_SHA and raw['seed_va'] == '0x60d34e'
    assert raw['endpoint_seed_va'] == '0x6b7c60' and len(raw['bridges']) == 1
    bridge = raw['bridges'][0]
    assert image.check(bridge) == 'disk' and bridge['start_va'] == '0x60d34e'
    assert bridge['target_va'] == '0x6b7c60' and bridge['size'] == 5
    code = bytes.fromhex(bridge['idb_hex'])
    assert code[0] == 0xe9 and 0x60d34e + 5 + struct.unpack_from('<i', code, 1)[0] == 0x6b7c60
    path = ROOT / '专题/名称查找与等待消费者/证据/container_template_navigation.json'
    for row, _ in walk(load(path)['original_record']):
        if 'ida_hex' in row and 'disk_hex' in row:
            BASE.byte_record_check(row, image)
        if all(key in row for key in ('va', 'hex', 'size')):
            assert image.read(row['va'], row['size']).hex() == row['hex']


def precheck():
    image = Image()
    supplement_session_check()
    auxiliary_bytes(image)
    result = {}
    for topic in TOPICS:
        directory = ROOT / '专题' / topic
        count = fresh_adaptations(directory, image)
        copies = exact_reuse(directory)
        navigation_reuse(directory)
        ranges, owners, instructions = BASE.bounded_check(directory / '证据/bounded_raw.json', image)
        result[topic] = dict(fresh_adaptations=count, exact_copied_reviews=len(copies),
            data_ranges=dict(ranges), finite_owner_windows=owners, finite_owner_instructions=instructions,
            supplement_bytes=supplement_bytes(directory, image), supplement_adaptations=supplement_adaptations(directory))
    result['名称查找与等待消费者']['container_bytes'] = container_bytes(image)
    return result


def supplement_session_check():
    session = load(HERE / '第二十五批补证会话.json')
    assert session['schema'] == 'richonline-readonly-supplement-session-25-1'
    assert session['instance_id'] == 'c7bb50fa35c1' and session['backend'] == 'gui'
    assert Path(session['input_path']).resolve() == (PROJECT / 'RnClient.exe').resolve()
    assert session['current_pe_sha256'] == PE_SHA
    assert session['idb_input_sha256'] == 'cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77'
    assert session['idb_input_sha256'] != PE_SHA and session['idb_input_filesize'] == 4714496
    exporter = ROOT / session['exporter']
    assert len(session['captures']) == 3
    expected = {'专题/' + topic + '/证据/supplement_raw.json' for topic in SUPPLEMENTS}
    assert {row['path'] for row in session['captures']} == expected
    for row in session['captures']:
        path = ROOT / row['path']
        assert digest(path)[1] == row['sha256'] and row['stdout'] == row['stderr'] == ''
        raw = load(path)
        assert raw['exporter_sha256'] == digest(exporter)[1]
        assert len(raw['functions']) == row['complete_function_declarations']
        assert len(raw['verified_direct_bridges']) == row['direct_bridges']
        assert len(raw['data_windows']) == row['data_windows']


def final_bindings(directory):
    manifest_name, validation_name = FINAL_FILES[directory.name]
    report = load(directory / '证据' / validation_name)
    assert report.get('status', report.get('result')) == 'PASS', directory.name
    assert report.get('disk_sha256', report.get('pe_sha256')) == PE_SHA
    checked = set()

    def verify(name, sha):
        name = name.replace('\\', '/')
        base = PROJECT if name.startswith('docs/') else ROOT if name.startswith('专题/') else directory
        path = base / name
        if not path.is_file():
            path = directory / '证据' / name
        assert path.is_file() and path.resolve().is_relative_to(PROJECT), name
        assert digest(path)[1] == sha.lower(), path
        checked.add(path.resolve())

    def bindings(value):
        if isinstance(value, dict):
            if isinstance(value.get('path'), str) and isinstance(value.get('sha256'), str):
                verify(value['path'], value['sha256'])
            for name, item in value.items():
                if isinstance(item, str) and len(item) == 64 and all(c in '0123456789abcdefABCDEF' for c in item):
                    if Path(name).suffix in ('.json', '.txt', '.py'):
                        verify(name, item)
                elif isinstance(item, (dict, list)):
                    bindings(item)
        elif isinstance(value, list):
            for item in value:
                bindings(item)

    # 仅终稿及固定来源字段有效；preview哈希不充当最终绑定。
    for key in ('sources', 'source_sha256', 'reviewed_final_sha256', 'final_documents',
                'final_artifacts', 'final_binding_sha256', 'authored_bundle', 'documents',
                'source_files', 'bound_files', 'final_supplements', 'final_text_sha256'):
        if key in report:
            bindings(report[key])
    direct = {'review_sha256': manifest_name, 'manifest_sha256': manifest_name,
              'raw_sha256': '证据/bounded_raw.json', 'formal_sha256': '证据/formal_functions.json',
              'supplement_sha256': '证据/supplement_raw.json'}
    if directory.name == '124字节共享数组生命周期':
        direct.update(independent_report_sha256='证据/独立审阅.txt', verifier_sha256='证据/verify_independent.py')
    for key, name in direct.items():
        if isinstance(report.get(key), str):
            verify(name, report[key])
    required = {directory / manifest_name, directory / '证据/bounded_raw.json', directory / '证据/formal_functions.json'}
    required.update(directory.glob('*.txt'))
    if directory.name in SUPPLEMENTS:
        required.add(directory / '证据/supplement_raw.json')
    if directory.name == '124字节共享数组生命周期':
        required.add(directory / '证据/supplement_formal.json')
    if directory.name == '名称查找与等待消费者':
        required.update(directory / name for name in ('证据/container_dependency/bounded_raw.json',
                         '证据/supplement_formal.json', '证据/container_formal.json'))
    assert {p.resolve() for p in required} <= checked, (directory.name, sorted(str(p) for p in required if p.resolve() not in checked))
    return len(checked)


def central_topic(directory, central, records, evidence):
    manifest_name, _ = FINAL_FILES[directory.name]
    path = directory / manifest_name
    manifest = load(path)
    source = path.relative_to(ROOT).as_posix()
    expected = [(row, ref) for row, ref in walk(manifest) if is_review(row)]
    addresses = [address_of(row) for row, _ in expected]
    assert len(addresses) == len(set(addresses)) and set(addresses) == set(REVIEWED_VAS[directory.name])
    for row, ref in expected:
        found = [item for item in central[address_of(row)] if item['source'] == source and item['json_pointer'] == ref]
        assert len(found) == 1 and all(found[0][key] == row[key] for key in ('status', 'conclusion'))
    allowed = {(source, ref) for _, ref in expected}
    assert not exact_reuse(directory), '历史复制携带审阅项，须单独明确来源边界'
    prefix = directory.relative_to(ROOT).as_posix() + '/'
    assert {(row['source'], row['json_pointer']) for row in records if row['source'].startswith(prefix)} == allowed
    for name in ('bounded_raw.json', 'supplement_raw.json', 'container_dependency/bounded_raw.json'):
        forbidden = prefix + '证据/' + name
        assert not any(row['source'] == forbidden for row in records)
        assert not any(forbidden in row['evidence'] for row in evidence['functions'] + evidence['unrecognized_code_ranges'])
    return dict(manifest_reviews=len(expected), bound_files=final_bindings(directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十五批推进快照.json')
    args = parser.parse_args()
    assert READY, '第二十五批仍处准备阶段，禁止正式中央检查'
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十四批复核快照.json')
    sources = {}
    for row in snapshot['source_fingerprints']:
        path = HERE / row['path']
        assert digest(path) == (row['bytes'], row['sha256'])
        assert path.name not in sources
        sources[path.name] = load(path)
    assert set(sources) == {'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json',
                            '结构覆盖口径.json', 'archive_validation.json'}
    evidence, review, archive = (sources[name] for name in ('evidence_coverage.json', 'review_coverage.json', 'archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts']
    assert snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions'] == evidence['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions'] == review['unique_functions_with_explicit_reviews']
    assert len({r['va'] for r in evidence['functions']}) == len(evidence['functions'])
    assert len({r['va'] for r in review['functions']}) == len(review['functions'])
    central = {r['va']: r['reviews'] for r in review['functions']}
    records = [dict(item, function_va=r['va']) for r in review['functions'] for item in r['reviews']]
    states = Counter(item['status'] for item in records)
    assert sum(states.values()) == review['review_record_count'] == snapshot['review_record_count']
    assert dict(states) == review['raw_status_counts'] == snapshot['raw_status_counts']
    assert snapshot['structural_groups'] == sources['结构覆盖口径.json']['groups']
    assert snapshot['instruction_observation_count'] == evidence['instruction_observation_count'] == prior['instruction_observation_count']
    assert snapshot['unrecognized_code_ranges'] == evidence['unrecognized_code_ranges'] == prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows'] == evidence['navigation_windows']
    navigation = {(va(r['start_va']), va(r['end_va'])) for r in snapshot['navigation_windows']}
    assert len(navigation) == len(snapshot['navigation_windows']) == evidence['navigation_window_count']
    assert {(va(r['start_va']), va(r['end_va'])) for r in prior['navigation_windows']} <= navigation
    results = precheck()
    for topic in TOPICS:
        results[topic].update(central_topic(ROOT / '专题' / topic, central, records, evidence))
    captured = set()
    for row in archive['files']:
        assert not row['errors'] and digest(ROOT / row['path']) == (row['bytes'], row['sha256'])
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(name).suffix for name in captured)) == archive['counts']
    assert {'全量分析/independent_snapshot_audit25.py', '全量分析/independent_snapshot_audit24.py',
            '全量分析/independent_snapshot_audit24_v2.py', '全量分析/第二十五批补证会话.json'} <= captured
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exports = [r for r in evidence['functions'] if all(s.startswith(prefixes) for s in r['evidence'])]
    reviews = [r for r in review['functions'] if all(i['source'].startswith(prefixes) for i in r['reviews'])]
    new_records = [r for r in records if r['source'].startswith(prefixes)]
    derived = dict(zip(keys, (len(exports), len(reviews), len(new_records))))
    assert changes == derived, (changes, derived)
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot, counts={k: snapshot[k] for k in keys},
        changes=changes, source_fingerprints=len(sources), captured_archive_files=len(captured),
        topics=results, navigation_windows=len(navigation),
        scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
