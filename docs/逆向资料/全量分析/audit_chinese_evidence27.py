"""第二十七批中文原证计量预审；只读中央文件，在内存与临时目录验证两行别名修复。"""
import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCE_FILES = ['专题/移动与动画协议/证据/movement_protocol_core.json',
                '专题/地图与路径/证据/map_runtime_core.json']
FOCUS = {'0x7e1a40', '0x7e1b10', '0x7e1bd0', '0x7e1c60', '0x7e1f60'}


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def walk(node, ref=''):
    if isinstance(node, dict):
        yield node, ref
        for key, child in node.items():
            yield from walk(child, ref + '/' + str(key))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from walk(child, ref + '/' + str(index))


def strict_chinese_address(node, known, code_ranges, inventory):
    """建议的中文函数门；窗口与单条汇编字段不具备函数级原证资格。"""
    try:
        address = hex(int(node['地址'], 16))
        rows, size = node['完整汇编'], node['大小']
        if address not in known or type(size) is not int or size <= 0 or not isinstance(rows, list) or not rows:
            return None
        if any(key in node for key in ('start_va', 'owner_va', 'site_va', '范围起点')):
            return None
        if any(any(word in str(node.get(key, '')) for word in ('窗口', '导航', '片段'))
               for key in ('scope', 'kind', 'status', '状态')):
            return None
        if int(rows[0]['地址'], 16) != int(address, 16) or node.get('字节一致') is not True:
            return None
        previous_end, primary_end = None, None
        for row in rows:
            site = int(row['地址'], 16)
            audit = row['字节核验']
            raw = bytes.fromhex(audit['IDB字节'])
            if not raw or audit.get('匹配') is not True or raw != bytes.fromhex(audit['磁盘字节']):
                return None
            if not any(lo <= site < site + len(raw) <= hi for lo, hi in code_ranges):
                return None
            if previous_end is not None:
                if site < previous_end:
                    return None
                if site != previous_end and primary_end is None:
                    primary_end = previous_end
            previous_end = site + len(raw)
        primary_end = primary_end or previous_end
        if primary_end - int(address, 16) != size:
            return None
        declared = inventory[address]
        if 'span_bytes' in declared and size != declared['span_bytes']:
            return None
        if 'end_va' in declared and primary_end != int(declared['end_va'], 16):
            return None
        return address
    except (KeyError, TypeError, ValueError):
        return None


def merger(patched):
    path = HERE / 'merge_evidence.py'
    code = path.read_text(encoding='utf-8')
    if patched == 'strict':
        code = code.replace("known={r['va'] for r in functions}", "known={r['va'] for r in functions}\n    inventory_by_va={r['va']:r for r in functions}")
        old = 'va=node.get("va") or node.get("address") or node.get("ea") or address_key'
        new = 'chinese_va=strict_chinese_address(node,known,code_ranges,inventory_by_va)\n                ' + old + ' or chinese_va'
        assert code.count(old) == 1
        code = code.replace(old, new)
        old = "bodies=[node.get(key) for key in ('pseudocode','disassembly','assembly','instructions')]"
        assert code.count(old) == 1
        code = code.replace(old, old + '\n                if chinese_va is not None: bodies.append(node["完整汇编"])')
    elif patched:
        replacements = [
            ('node.get("va") or node.get("address") or node.get("ea") or address_key',
             'node.get("va") or node.get("address") or node.get("ea") or node.get("地址") or address_key'),
            ("('pseudocode','disassembly','assembly','instructions')",
             "('pseudocode','disassembly','assembly','instructions','伪代码','完整汇编')")]
        for old, new in replacements:
            assert code.count(old) == 1
            code = code.replace(old, new)
    module = types.ModuleType('readonly_merger_candidate')
    module.__file__ = str(path)
    module.strict_chinese_address = strict_chinese_address
    exec(compile(code, str(path), 'exec'), module.__dict__)
    return module


def run_without_writes(module):
    output = []
    expected = module.ROOT / 'evidence_coverage.json'

    def capture(path, content, *args, **kwargs):
        assert path == expected, '拒绝任何额外写入'
        output.append(json.loads(content))
        return len(content)

    original_rglob = Path.rglob

    def frozen_rglob(path, pattern):
        if path == module.TOPICS and hasattr(module, 'frozen_files'):
            assert pattern == '*.json'
            return iter(module.frozen_files)
        return original_rglob(path, pattern)

    with patch.object(Path, 'write_text', capture), patch.object(Path, 'rglob', frozen_rglob), contextlib.redirect_stdout(io.StringIO()):
        module.main()
    assert len(output) == 1
    return output[0]


def fixture_checks():
    # 候选修复只在内存中存在；临时夹具不接触中央结果。
    with tempfile.TemporaryDirectory(prefix='richonline_chinese_evidence27_') as temp:
        root = Path(temp) / '全量分析'
        topic = Path(temp) / '专题' / '中文夹具'
        root.mkdir()
        topic.mkdir(parents=True)
        (root / 'functions.json').write_text(json.dumps([{'va': hex(v)} for v in range(0x1000, 0x1007)]), encoding='utf-8')
        (root / 'segments.json').write_text(json.dumps([{'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1}]), encoding='utf-8')
        rows = [
            {'地址': '0x1000', '伪代码': 'return 1;'},
            {'地址': '0x1001', '完整汇编': [{'地址': '0x1001', '汇编': 'ret'}]},
            {'地址': '0x1002', '汇编': 'ret'},
            {'地址': '0x1003', '状态': '局部', '结论': '只有结论，没有原证'},
            {'va': '0x1004', 'assembly': [{'va': '0x1004', 'text': 'ret'}]},
            {'va': '0x1005', 'assembly': 'ret', 'function': '0x1005'},
            {'地址': '0x1000', '完整汇编': [{'地址': '0x1006', '汇编': 'ret'}]},
            {'start_va': '0x1006', 'end_va': '0x1007', 'assembly': [], 'idb_hex': 'c3',
             'disk_hex': 'c3', 'matching': True, 'scope': '有限导航窗口'}]
        (topic / 'raw.json').write_text(json.dumps(rows, ensure_ascii=False), encoding='utf-8')
        outputs = []
        for changed in (False, True):
            module = merger(changed)
            module.ROOT, module.TOPICS = root, topic.parent
            outputs.append(run_without_writes(module))
        old, new = outputs
        assert {r['va'] for r in old['functions']} == {'0x1004'}
        assert {r['va'] for r in new['functions']} == {'0x1000', '0x1001', '0x1004'}
        assert old['instruction_observations'] == new['instruction_observations']
        assert new['instruction_observations'][0]['va'] == '0x1005'
        assert old['navigation_windows'] == new['navigation_windows']
        assert new['navigation_window_count'] == 1 and not new['outside_inventory']
        assert len(next(r for r in new['functions'] if r['va'] == '0x1000')['evidence']) == 1
    known = {'0x1000', '0x1001'}
    code_ranges = [(0x1000, 0x2000)]
    inventory = {'0x1000': {'span_bytes': 1, 'end_va': '0x1001'}}
    valid = {'地址': '0x1000', '大小': 1, '字节一致': True,
             '完整汇编': [{'地址': '0x1000', '汇编': 'ret', '字节核验': {'匹配': True, 'IDB字节': 'c3', '磁盘字节': 'c3'}}]}
    assert strict_chinese_address(valid, known, code_ranges, inventory) == '0x1000'
    import copy
    cases = []
    for changes in ({'地址': '0x1100'}, {'大小': 0}, {'大小': True}, {'大小': '1'}, {'大小': 2},
                    {'完整汇编': []}, {'完整汇编': 'ret'}, {'字节一致': False}, {'scope': '中文导航窗口'}, {'owner_va': '0x1000'}):
        cases.append(dict(valid, **changes))
    for change in ({'地址': '0x1001'}, {'字节核验': {'匹配': False, 'IDB字节': 'c3', '磁盘字节': 'c3'}},
                   {'字节核验': {'匹配': True, 'IDB字节': 'c3', '磁盘字节': 'cc'}},
                   {'字节核验': {'匹配': True, 'IDB字节': 'xx', '磁盘字节': 'xx'}}):
        row = copy.deepcopy(valid)
        row['完整汇编'][0].update(change)
        cases.append(row)
    assert all(strict_chinese_address(row, known, code_ranges, inventory) is None for row in cases)
    assert strict_chinese_address(valid, known, code_ranges, {'0x1000': {'span_bytes': 2}}) is None
    assert strict_chinese_address(valid, known, code_ranges, {'0x1000': {'end_va': '0x1002'}}) is None
    tail = copy.deepcopy(valid)
    item = copy.deepcopy(valid['完整汇编'][0])
    item['地址'] = '0x1100'
    tail['完整汇编'].append(item)
    assert strict_chinese_address(tail, known, code_ranges, inventory) == '0x1000'
    tail['完整汇编'][-1]['地址'] = '0x2100'
    assert strict_chinese_address(tail, known, code_ranges, inventory) is None
    return 'PASS：宽别名归因夹具与严格函数门16项拒绝边例、尾块允许/越界拒绝；英文、窗口、单指令和去重保持'


def main():
    tracked = [HERE / name for name in ['merge_evidence.py', 'evidence_coverage.json', 'review_coverage.json',
               'followup_queue.json', '第二十六批推进快照.json', 'independent_snapshot_audit26.py']]
    tracked += [ROOT / name for name in SOURCE_FILES]
    before = {str(p): sha(p) for p in tracked}
    spec = importlib.util.spec_from_file_location('readonly_pe_audit24', HERE / 'independent_snapshot_audit24.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    image = module.Image()
    inventory = {r['va']: r for r in read(HERE / 'functions.json')}
    covered = {r['va']: r for r in read(HERE / 'evidence_coverage.json')['functions']}
    reviewed = {r['va']: r for r in read(HERE / 'review_coverage.json')['functions']}
    snapshot = read(HERE / '第二十六批推进快照.json')
    archive_ref = next(r for r in snapshot['source_fingerprints'] if r['path'] == 'archive_validation.json')
    assert sha(HERE / 'archive_validation.json') == archive_ref['sha256']
    archive = read(HERE / 'archive_validation.json')
    frozen_files = []
    for row in archive['files']:
        if row['path'].startswith('专题/') and row['path'].endswith('.json'):
            path = ROOT / row['path']
            assert sha(path) == row['sha256']
            frozen_files.append(path)
    discovered = []
    for path in sorted(frozen_files):
        nodes = [(row, ref) for row, ref in walk(read(path)) if '地址' in row and ('伪代码' in row or '完整汇编' in row)]
        if nodes:
            discovered.append(path.relative_to(ROOT).as_posix())
    assert set(discovered) == set(SOURCE_FILES), discovered
    results, addresses, instructions, tail_rows = [], set(), 0, []
    for name in SOURCE_FILES:
        source = read(ROOT / name)
        assert source['磁盘SHA256'].lower() == module.PE_SHA
        missing, focus = [], []
        for index, row in enumerate(source['函数']):
            address = row['地址'].lower()
            assert address in inventory and address not in addresses and row['字节一致'] is True
            addresses.add(address)
            chunks, last_end, byte_count = [], None, 0
            for item in row['完整汇编']:
                check = item['字节核验']
                data = bytes.fromhex(check['IDB字节'])
                assert check['匹配'] is True and data and data == bytes.fromhex(check['磁盘字节'])
                assert data == image.read(item['地址'], len(data))
                site = int(item['地址'], 16)
                if site != last_end:
                    chunks.append([site, site])
                chunks[-1][1] = last_end = site + len(data)
                byte_count += len(data)
                instructions += 1
            assert chunks[0][0] == int(address, 16)
            assert chunks[0][1] - chunks[0][0] == row['大小'] == inventory[address]['span_bytes']
            if len(chunks) > 1:
                tail_rows.append(dict(va=address, primary_bytes=row['大小'], captured_bytes=byte_count,
                                      contiguous_ranges=[[hex(a), hex(b)] for a, b in chunks]))
            if address not in covered:
                missing.append(address)
            if address in FOCUS:
                focus.append(dict(va=address, json_pointer=f'/函数/{index}', bytes=byte_count,
                                  instructions=len(row['完整汇编']), already_reviewed=address in reviewed))
        results.append(dict(source=name, sha256=sha(ROOT / name), functions=len(source['函数']),
                            missing_count=len(missing), missing=missing, focus=focus))
    modules = [merger(mode) for mode in (False, True, 'strict')]
    for current in modules:
        current.frozen_files = frozen_files
    baseline, candidate, strict_candidate = [run_without_writes(current) for current in modules]
    assert baseline == read(HERE / 'evidence_coverage.json'), '冻结来源复跑应与26原证统计完全相等'
    assert strict_candidate == candidate, '严格门必须与已逐字节复核的中文全集一致'
    old_map = {r['va']: r for r in baseline['functions']}
    new_map = {r['va']: r for r in candidate['functions']}
    missing = {v for result in results for v in result['missing']}
    assert set(new_map) - set(old_map) == missing and len(missing) == 39
    assert not set(old_map) - set(new_map)
    changed_sources = []
    for address, row in new_map.items():
        added = set(row['evidence']) - set(old_map.get(address, {'evidence': []})['evidence'])
        if added:
            assert address in addresses and added <= set(SOURCE_FILES)
            changed_sources.append(address)
    assert len(changed_sources) == len(addresses) == 159
    for key in ('total_identified_functions', 'outside_inventory', 'unrecognized_code_ranges',
                'instruction_observations', 'navigation_windows'):
        assert baseline[key] == candidate[key]
    assert all(sha(Path(path)) == value for path, value in before.items())
    print(json.dumps(dict(status='PASS', scope='只读计量预审；内存候选补丁，不是正式中央归并',
        baseline_functions=baseline['unique_exported_functions'], candidate_functions=candidate['unique_exported_functions'],
        correction_functions=len(missing), source_relation_additions=len(changed_sources),
        frozen_topic_json_files=len(frozen_files),
        source_files=results, verified_instruction_records=instructions, preserved_tail_ranges=tail_rows,
        regression=fixture_checks(), central_files_unchanged=True,
        strict_gate_same_result=True, semantic_review_change=0), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
