"""第二十八批中央独审准备脚本：四专题原证与分层补证。"""
import hashlib
import importlib.util
import json
import struct
import argparse
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PREV_PATH = HERE / 'independent_snapshot_audit27.py'
PREV_SHA = '7b39e79a51c93d41f013a89371be83d45e4b126edb9ddf0d0593fbbf7d165935'
assert hashlib.sha256(PREV_PATH.read_bytes()).hexdigest() == PREV_SHA
spec = importlib.util.spec_from_file_location('audit27_frozen', PREV_PATH)
PREV = importlib.util.module_from_spec(spec); spec.loader.exec_module(PREV)
PE_SHA = PREV.PE_SHA
READY = False
TOPICS = {
    '资源槽池生产与归还': {'fresh': 6, 'reused': 3, 'raw': '32bb1c22c33bd0ca58ba757e74943af2d1da4eb0514d7114c61c2f834ee0ca80'},
    '大厅分类与索引列表生命周期': {'fresh': 4, 'reused': 3, 'raw': '80caf7a717f3f67d960f14bd0749df7ef1a74e9c5150593fd34dfb7f307a881d'},
    '共享记录地图候选回调': {'fresh': 2, 'reused': 0, 'raw': '73c4b8febe7b40beed41ab6602dde5dbd8a27fc66dbc79a807686dc8ec23d490'},
    '角色外观描述与界面实例': {'fresh': 2, 'reused': 3, 'raw': '6dafad4aa131c1c24e4b78beb454ade0860e5e97692b553d028c0d26a2c26681'},
}
SEEDS = {
    '资源槽池生产与归还': ['0x6d75a0','0x62eae0','0x6dfc30','0x6dfd50','0x6d7690','0x6dbdf0'],
    '大厅分类与索引列表生命周期': ['0x69f6d0','0x6a0b50','0x6b8980','0x6b8a00'],
    '共享记录地图候选回调': ['0x6ba170','0x6aaa40'],
    '角色外观描述与界面实例': ['0x6423c0','0x6fc210'],
}
REPORTS = {'资源槽池生产与归还':'independent_validation.json',
    '大厅分类与索引列表生命周期':'independent_final_audit.json',
    '共享记录地图候选回调':'independent_validation28.json',
    '角色外观描述与界面实例':'independent_validation.json'}
REVIEW_COUNTS = {'资源槽池生产与归还':12,'大厅分类与索引列表生命周期':7,
    '共享记录地图候选回调':6,'角色外观描述与界面实例':2}
FINAL_HASHES = {
    '资源槽池生产与归还':'d6e8fadd9fa294d2c0251f0c952ed6d1fbda60500c25b643a0194f305c438ed2',
    '大厅分类与索引列表生命周期':'b739ab95f3a860071b373dd004227e21c4c95a30a734e6a8303068d7120e7660',
    '共享记录地图候选回调':'cee85d7fdf9278d91bebf85ea8c57a56f89de41358f19e9c5d443be6ccf7d545',
    '角色外观描述与界面实例':'f473ea69adc2e74fae36db89d985d05bcf696c1351f4f39ebffe4347eb624e92',
}
INDEX_SHA = 'a95d5cf902dfe6a9cb53c98781f02307747b820b9d1c1ce1bf07efa47d602bb6'
PE_PATH = PREV.PROJECT / 'RnClient.exe'

def read(path): return json.loads(path.read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def ptr(obj, path):
    for key in path.strip('/').split('/'):
        obj = obj[int(key)] if isinstance(obj, list) else obj[key]
    return obj

def check_pe():
    assert sha(PE_PATH) == PE_SHA
    data = PE_PATH.read_bytes(); nt = struct.unpack_from('<I', data, 60)[0]
    assert data[:2] == b'MZ' and data[nt:nt+4] == b'PE\0\0'
    return data

def raw_check(topic, image):
    directory = ROOT / '专题' / topic
    path = directory / '证据/bounded_raw.json'; raw = read(path)
    assert sha(path) == TOPICS[topic]['raw'] and raw['disk_sha256'] == PE_SHA
    assert [r['seed_va'] for r in raw['functions']] == SEEDS[topic]
    assert len(raw['reused_seeds']) == TOPICS[topic]['reused']
    for row in raw['functions']:
        assert row['seed_va'] in SEEDS[topic] and row['chunk_byte_ranges']
        assert all(c.get('matching') is True for c in row['chunk_byte_ranges'])
    assert len(raw['explicit_owner_windows']) == {'资源槽池生产与归还': 6, '大厅分类与索引列表生命周期': 20,
        '共享记录地图候选回调': 12, '角色外观描述与界面实例': 5}[topic]
    PREV.BASE.TOPICS = TOPICS
    PREV.BASE.bounded_check(path, image)
    PREV.all_bytes(raw, image)
    return raw

def supplement_check(topic, image):
    directory = ROOT / '专题' / topic / '证据'
    if topic == '大厅分类与索引列表生命周期':
        raw = read(directory / 'type_tables/bounded_raw.json')
        assert raw['disk_sha256'] == PE_SHA and [(r['start_va'], r['size']) for r in raw['data_windows']] == [
            ('0xa673a4',16),('0xa237bc',4),('0xa237b4',6),('0xa237b0',4),('0xa237ac',4),('0x6a0083',16),('0x6a0a63',16)]
        PREV.all_bytes(raw, image)
        assert not raw['functions'] and not raw['seeds']
        assert struct.unpack('<4I', image.read(0xa673a4,16)) == (0xa237bc,0xa237b4,0xa237b0,0xa237ac)
        return 66
    if topic == '共享记录地图候选回调':
        raw = read(directory / 'boundary_data/bounded_raw.json'); assert raw['disk_sha256'] == PE_SHA
        assert len(raw['data_windows']) == 6 and sum(r['size'] for r in raw['data_windows']) == 60
        PREV.all_bytes(raw, image); assert not raw['functions'] and not raw['seeds']; return 60
    if topic == '角色外观描述与界面实例':
        raw = read(directory / 'unwind_data/bounded_raw.json'); assert raw['disk_sha256'] == PE_SHA
        assert len(raw['data_windows']) == 7 and sum(r['size'] for r in raw['data_windows']) == 103
        PREV.all_bytes(raw, image); assert not raw['functions'] and not raw['seeds']; return 103
    return 0

def slot_adapter_check(raw, image):
    directory = ROOT / '专题/资源槽池生产与归还/证据'
    count = 0
    for filename, wanted_count in [('formal_functions.json', 6), ('reused_functions.json', 6)]:
        document = read(directory / filename)
        assert document['disk_sha256'] == PE_SHA and len(document['functions']) == wanted_count
        for row in document['functions']:
            source = ROOT / row['source_path']
            assert sha(source) == row['source_sha256']
            original = ptr(read(source), row['source_pointer'])
            assert json.loads(row['source_record_json']) == original
            assert row['source_field_pointers'] == {k: row['source_pointer'] + '/' + k for k in original}
            address = original.get('seed_va', original.get('va', original.get('address')))
            assert row['va'] == address
            chunks = original.get('chunk_byte_ranges', original.get('chunks', original.get('byte_ranges')))
            current = None
            if not chunks:
                matches = [(i, a) for i, a in enumerate(raw['current_chunk_audits']) if a['seed_va'] == address]
                assert len(matches) == 1
                index, audit = matches[0]
                chunks = audit['chunk_byte_ranges']
                current = dict(source_path='专题/资源槽池生产与归还/证据/bounded_raw.json',
                    source_pointer=f'/current_chunk_audits/{index}', source_sha256=TOPICS['资源槽池生产与归还']['raw'])
            normalized = []
            for c in chunks:
                start = c.get('start_va', c.get('va', c.get('start')))
                size = c.get('size', int(c['end'], 16) - int(start, 16) if 'end' in c else None)
                normalized.append(dict(start_va=start, size=size, original=c))
            assert row['normalized_chunks'] == normalized
            assembly = original.get('assembly', original.get('instructions'))
            assert row['normalized_assembly'] == [dict(site_va=x.get('site_va', x.get('va', x.get('address', x.get('ea')))),
                text=x['text'], is_code=x.get('is_code', True), original=x) for x in assembly]
            assert row['declared_chunks'] == original.get('declared_chunks', [dict(start_va=c['start_va'],
                end_va=hex(int(c['start_va'], 16)+c['size']), is_main=c['start_va'] == address) for c in normalized])
            if current is None:
                assert 'current_bytes_source' not in row
            else:
                assert row['current_bytes_source'] == current
            PREV.all_bytes(chunks, image)
            assert not PREV.OLD.is_review(row)
            count += 1
    shared = read(directory / 'shared_sites.json')
    assert shared['status'] == 'PASS' and shared['site_count'] == len(shared['sites']) == 15
    assert shared['file_categories'] == len({r['file'] for r in shared['sites']}) == 12
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    for site in shared['sites']:
        source = ROOT / site['source_path']
        assert sha(source) == site['source_sha256']
        origin = read(source)
        payload = bytes.fromhex(site['filename_hex'])
        assert payload == image.read(site['filename_target_va'], len(payload))
        assert payload == site['file'].encode('ascii') + b'\0'
        for instruction in site['instructions']:
            old = ptr(origin, instruction['source_pointer'])
            assert instruction['original'] == old
            data = image.read(old['va'], old['size'])
            assert data.hex() == instruction['disk_hex']
            decoded = list(decoder.disasm(data, int(old['va'], 16)))
            assert len(decoded) == 1 and decoded[0].size == len(data)
            assert instruction['decoded'] == decoded[0].mnemonic + ' ' + decoded[0].op_str
    return dict(adapted_records=count, historical_loader_sites=15, configuration_categories=12)

def lobby_adapter_check(raw, image):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    directory = ROOT / '专题/大厅分类与索引列表生命周期/证据'
    formal = read(directory / 'formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and formal['raw_sha256'] == TOPICS['大厅分类与索引列表生命周期']['raw']
    assert [r['va'] for r in formal['functions']] == SEEDS['大厅分类与索引列表生命周期'] + ['0x6b8a60', '0x69f750', '0x6a0130']
    for row in formal['functions']:
        source = row['source']; path = (ROOT if source['path'].startswith('专题/') else directory) / source['path']
        assert sha(path) == source['source_sha256']
        original = ptr(read(path), source['json_pointer'])
        assert json.loads(row['source_record_json']) == original
        current = [x for x in raw['current_chunk_audits'] if x['seed_va'] == row['va']]
        assert len(current) == 1 and row['chunk_byte_ranges'] == current[0]['chunk_byte_ranges']
        expected = []
        for chunk in row['chunk_byte_ranges']:
            data = image.read(chunk['start_va'], chunk['size'])
            decoded = list(decoder.disasm(data, int(chunk['start_va'], 16)))
            assert sum(x.size for x in decoded) == len(data)
            expected.extend(dict(va=hex(x.address), size=x.size, text=x.mnemonic + (' ' + x.op_str if x.op_str else ''), hex=x.bytes.hex()) for x in decoded)
        assert row['assembly'] == expected
        assert not PREV.OLD.is_review(row)
    return dict(adapted_records=7)

def map_adapter_check(raw, image):
    directory = ROOT / '专题/共享记录地图候选回调'
    formal = read(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and formal['raw_sha256'] == TOPICS[directory.name]['raw']
    assert len(formal['functions']) == 2 and len(formal['legacy_reused_functions']) == 4 and len(formal['helper_contracts']) == 7
    for original, row in zip(raw['functions'], formal['functions']):
        assert PREV.bound_original(directory, row['source']) == original == row['source_record']
        assert row['va'] == original['seed_va'] and row['end_va'] == original['end_va']
        assert row['name'] == original['name'] and row['pseudocode'] == original['pseudocode']
        assert row['chunk_byte_ranges'] == original['chunk_byte_ranges']
        assert row['assembly'] == [dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in original['assembly']]
    for row in formal['legacy_reused_functions'] + formal['helper_contracts']:
        original = PREV.bound_original(directory, row['source'])
        assert json.loads(row['source_record_json']) == original
        PREV.all_bytes(original, image)
        if 'source_audits' in row:
            expected = [a for a in raw['reused_source_byte_audits'] if a['seed_va'] == row['va']]
            assert len(expected) == 1 and row['source_audits'] == expected[0]['current_byte_audits']
            PREV.all_bytes(row['source_audits'], image)
        assert not PREV.OLD.is_review(row)
    assert formal['caller_windows'] == raw['explicit_owner_windows']
    assert formal['bridges'] == raw['verified_direct_bridges'] and formal['calls'] == raw['calls']
    assert formal['boundary_data_sha256'] == sha(directory / '证据/boundary_data/bounded_raw.json')
    return dict(adapted_records=13)

def appearance_adapter_check(raw, image):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    directory = ROOT / '专题/角色外观描述与界面实例/证据'
    formal = read(directory / 'formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and len(formal['functions']) == 2
    assert [r['va'] for r in formal['functions']] == SEEDS['角色外观描述与界面实例']
    for i, (old, row) in enumerate(zip(raw['functions'], formal['functions'])):
        assert all(row[k] == old[k] for k in old)
        assert row['source_path'] == '专题/角色外观描述与界面实例/证据/bounded_raw.json'
        assert row['source_pointer'] == f'/functions/{i}' and row['source_sha256'] == TOPICS['角色外观描述与界面实例']['raw']
        assert row['byte_ranges'] == old['chunk_byte_ranges']
        PREV.all_bytes(row, image)
        expected=[]
        for chunk in old['chunk_byte_ranges']:
            data=image.read(chunk['start_va'],chunk['size'])
            decoded=list(decoder.disasm(data,int(chunk['start_va'],16)))
            assert sum(x.size for x in decoded)==len(data)
            expected.extend(dict(site_va=hex(x.address),size=x.size,hex=x.bytes.hex(),text=x.mnemonic+' '+x.op_str) for x in decoded)
        assert row['decoded_instructions']==expected
    reused = read(directory / 'reused_sources.json')
    assert reused['disk_sha256'] == PE_SHA
    for row in reused['records']:
        source = ROOT / row['source_path']
        assert sha(source) == row['source_sha256']
        original = ptr(read(source), row['source_pointer'])
        assert json.loads(row['source_record_json']) == original
        PREV.all_bytes(original, image)
        assert not PREV.OLD.is_review(row)
    for row in reused['current_old_audits']:
        PREV.all_bytes(row, image)
    windows = read(directory / 'caller_fill_windows.json')
    assert windows['disk_sha256'] == PE_SHA
    for row in windows['records']:
        source = ROOT / row['source_path']
        assert sha(source) == row['source_sha256']
        old = ptr(read(source), row['source_pointer'])
        assert old.get('va', old.get('address')) == row['owner_va']
        lo,hi=int(row['start_va'],16),int(row['end_va'],16)
        assert row['instructions']==[x for x in old['assembly'] if lo<=int(x['va'],16)<hi]
        data = b''.join(image.read(x['va'], x['size']) for x in row['instructions'])
        assert len(data) == int(row['end_va'],16)-int(row['start_va'],16)
        assert data == image.read(row['start_va'],len(data))
        assert not PREV.OLD.is_review(row)
    return dict(adapted_new=2, historical_records=len(reused['records']), old_caller_windows=len(windows['records']))

def precheck():
    image = PREV.Image(); result = {}
    for topic, meta in TOPICS.items():
        raw = raw_check(topic, image)
        result[topic] = dict(fresh=len(raw['functions']), reused=len(raw['reused_seeds']),
            caller_windows=len(raw['explicit_owner_windows']), supplement_bytes=supplement_check(topic, image))
        if topic == '资源槽池生产与归还':
            result[topic].update(slot_adapter_check(raw, image))
        elif topic == '大厅分类与索引列表生命周期':
            result[topic].update(lobby_adapter_check(raw, image))
        elif topic == '共享记录地图候选回调':
            result[topic].update(map_adapter_check(raw, image))
        elif topic == '角色外观描述与界面实例':
            result[topic].update(appearance_adapter_check(raw, image))
    return result

def final_bindings(topic):
    directory = ROOT / '专题' / topic
    report_path = directory / '证据' / REPORTS[topic]
    report = read(report_path)
    assert report.get('status',report.get('result')) == 'PASS'
    assert sha(report_path) == FINAL_HASHES[topic]
    bound = set()
    for row, _ in PREV.walk(report):
        for name,value in row.items():
            if isinstance(value,str) and len(value) == 64 and Path(name).suffix in ('.json','.txt','.py'):
                base = PREV.PROJECT if name.startswith('docs/') else ROOT if name.startswith(('专题/','全量分析/')) else directory
                path = base/name
                assert path.is_file() and sha(path) == value, name
                bound.add(path.resolve())
        if all(k in row for k in ('path','sha256')) and isinstance(row['path'],str):
            name = row['path']; base = PREV.PROJECT if name.startswith('docs/') else ROOT if name.startswith(('专题/','全量分析/')) else directory
            path = base/name
            assert path.is_file() and sha(path) == row['sha256'],name
            bound.add(path.resolve())
    required = [directory/'函数审阅清单.json',directory/'证据/formal_functions.json',directory/'证据/bounded_raw.json']
    required += [p for p in directory.glob('*.txt') if '独立' not in p.name]
    assert all(p.resolve() in bound for p in required), [str(p) for p in required if p.resolve() not in bound]
    for name in ('formal_functions.json','reused_functions.json','reused_sources.json','caller_fill_windows.json'):
        path = directory/'证据'/name
        if path.exists():
            assert not any(PREV.OLD.is_review(r) for r,_ in PREV.walk(read(path))),name
    return len(bound)

def main():
    assert READY, '第二十八批四专题终稿尚未冻结；当前仅准备预核'
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot',nargs='?',default='第二十八批推进快照.json')
    args=parser.parse_args(); assert Path(args.snapshot).name == args.snapshot
    snapshot,prior=read(HERE/args.snapshot),read(HERE/'第二十七批推进快照.json')
    sources={}
    for row in snapshot['source_fingerprints']:
        path=HERE/row['path']; assert PREV.digest(path)==(row['bytes'],row['sha256'])
        assert path.name not in sources; sources[path.name]=read(path)
    assert set(sources)=={'evidence_coverage.json','review_coverage.json','followup_queue.json','结构覆盖口径.json','archive_validation.json'}
    evidence,review,archive=(sources[k] for k in ('evidence_coverage.json','review_coverage.json','archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records'] and not archive['error_files']
    assert not snapshot['format_check']['errors'] and snapshot['format_check']['counts']==archive['counts']
    assert snapshot['format_check']['checked_at']==archive['checked_at']
    assert len(evidence['functions'])==snapshot['unique_exported_functions']==evidence['unique_exported_functions']
    assert len(review['functions'])==snapshot['unique_explicit_review_functions']==review['unique_functions_with_explicit_reviews']
    central={r['va']:r['reviews'] for r in review['functions']}; assert len(central)==len(review['functions'])
    assert len({r['va'] for r in evidence['functions']})==len(evidence['functions'])
    records=[dict(item,function_va=r['va']) for r in review['functions'] for item in r['reviews']]
    states=Counter(item['status'] for item in records)
    assert sum(states.values())==review['review_record_count']==snapshot['review_record_count']
    assert dict(states)==review['raw_status_counts']==snapshot['raw_status_counts']
    assert snapshot['structural_groups']==sources['结构覆盖口径.json']['groups']
    assert snapshot['instruction_observation_count']==evidence['instruction_observation_count']==prior['instruction_observation_count']
    assert snapshot['unrecognized_code_ranges']==evidence['unrecognized_code_ranges']==prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows']==evidence['navigation_windows']
    nav={(PREV.va(r['start_va']),PREV.va(r['end_va'])) for r in snapshot['navigation_windows']}
    assert len(nav)==len(snapshot['navigation_windows'])==evidence['navigation_window_count']
    assert {(PREV.va(r['start_va']),PREV.va(r['end_va'])) for r in prior['navigation_windows']}<=nav
    indexes=list(ROOT.glob('19_*.txt')); assert len(indexes)==1 and sha(indexes[0])==INDEX_SHA
    results=precheck()
    for topic in TOPICS:
        directory=ROOT/'专题'/topic; path=directory/'函数审阅清单.json'; source=path.relative_to(ROOT).as_posix()
        expected=[(r,p) for r,p in PREV.walk(read(path)) if PREV.OLD.is_review(r)]
        assert len(expected)==REVIEW_COUNTS[topic]
        assert len({PREV.OLD.address_of(r) for r,_ in expected})==len(expected)
        for row,ref in expected:
            found=[r for r in central[PREV.OLD.address_of(row)] if r['source']==source and r['json_pointer']==ref]
            assert len(found)==1 and all(found[0][k]==row[k] for k in ('status','conclusion'))
        prefix=directory.relative_to(ROOT).as_posix()+'/'
        assert {(r['source'],r['json_pointer']) for r in records if r['source'].startswith(prefix)}=={(source,p) for _,p in expected}
        results[topic].update(manifest_records=len(expected),final_bound_files=final_bindings(topic))
    captured=set()
    for row in archive['files']:
        assert not row['errors'] and PREV.digest(ROOT/row['path'])==(row['bytes'],row['sha256'])
        assert row['path'] not in captured; captured.add(row['path'])
    assert dict(Counter(Path(p).suffix for p in captured))==archive['counts']
    assert {'全量分析/independent_snapshot_audit28.py','全量分析/independent_snapshot_audit27.py'}<=captured
    keys=('unique_exported_functions','unique_explicit_review_functions','review_record_count')
    changes={k:snapshot[k]-prior[k] for k in keys}; prefixes=tuple('专题/'+t+'/' for t in TOPICS)
    new_exported=[r for r in evidence['functions'] if all(s.startswith(prefixes) for s in r['evidence'])]
    assert {r['va'] for r in new_exported}==set(sum(SEEDS.values(),[]))
    new_reviewed=[r for r in review['functions'] if all(x['source'].startswith(prefixes) for x in r['reviews'])]
    derived=dict(zip(keys,(len(new_exported),len(new_reviewed),len([r for r in records if r['source'].startswith(prefixes)]))))
    assert changes==derived
    print(json.dumps(dict(status='PASS',snapshot=args.snapshot,counts={k:snapshot[k] for k in keys},changes=changes,
        source_fingerprints=len(sources),captured_archive_files=len(captured),topics=results,
        scope='冻结时点静态证据与计量，不表示全程序完成、运行时可达或IDB全文件与PE相同'),ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()
