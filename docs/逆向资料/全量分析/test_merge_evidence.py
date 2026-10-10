"""未声明嵌套代码块应单列，不改变已声明函数分母。"""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import merge_evidence


class NestedUndeclaredEvidenceTest(unittest.TestCase):
    def test_nested_va_windows_cannot_bypass_rejection_or_count_function_heads(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / '全量分析'
            topics = base / '专题' / '窗口'
            root.mkdir()
            topics.mkdir(parents=True)
            (root / 'functions.json').write_text('[{"va":"0x1000"}]', encoding='utf-8')
            (root / 'segments.json').write_text(json.dumps([{
                'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1
            }]), encoding='utf-8')
            windows = []
            for start, changes in (
                    (0x1000, {}), (0x1100, {}),
                    (0x1200, {'disk_hex': '909090cc'}),
                    (0x1300, {'matching': False}),
                    (0x1400, {'size': 3}), (0x2100, {})):
                raw = dict(va=hex(start), size=4, idb_hex='90909090',
                           disk_hex='90909090', matching=True)
                raw.update(changes)
                windows.append(dict(va=hex(start), end_va=hex(start+4),
                                    kind='未定义代码导航窗口', assembly=[], byte_range=raw))
            (topics / 'raw.json').write_text(json.dumps(windows), encoding='utf-8')
            with patch.object(merge_evidence, 'ROOT', root), patch.object(
                    merge_evidence, 'TOPICS', base / '专题'), contextlib.redirect_stdout(io.StringIO()):
                merge_evidence.main()
            result = json.loads((root / 'evidence_coverage.json').read_text(encoding='utf-8'))
            self.assertEqual(result['unique_exported_functions'], 0)
            self.assertEqual(result['outside_inventory'], ['0x1100'])
            self.assertEqual(result['navigation_window_count'], 2)

    def test_flat_windows_separate_legacy_navigation_from_verified_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / '全量分析'
            topics = base / '专题' / '窗口'
            root.mkdir()
            topics.mkdir(parents=True)
            (root / 'functions.json').write_text('[]', encoding='utf-8')
            (root / 'segments.json').write_text(json.dumps([{
                'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1
            }]), encoding='utf-8')
            windows = []
            for start, changes in (
                    (0x1100, {}),
                    (0x1200, {'disk_hex': '909090cc'}),
                    (0x1300, {'matching': False}),
                    (0x1400, {'disk_hex': None, 'matching': None}),
                    (0x1500, {'size': 3})):
                raw = dict(start_va=hex(start), end_va=hex(start+4), size=4,
                           scope='未声明代码导航窗', assembly=[],
                           idb_hex='90909090', disk_hex='90909090', matching=True)
                raw.update(changes)
                windows.append({k: v for k, v in raw.items() if v is not None})
            (topics / 'raw.json').write_text(json.dumps(windows), encoding='utf-8')
            with patch.object(merge_evidence, 'ROOT', root), patch.object(
                    merge_evidence, 'TOPICS', base / '专题'), contextlib.redirect_stdout(io.StringIO()):
                merge_evidence.main()
            result = json.loads((root / 'evidence_coverage.json').read_text(encoding='utf-8'))
            self.assertEqual(result['outside_inventory'], ['0x1100'])
            self.assertEqual(result['navigation_window_count'], 3)
            self.assertEqual(result['unique_exported_functions'], 0)

    def test_item_windows_require_matching_complete_bytes_and_code_segment(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / '全量分析'
            topics = base / '专题' / '窗口'
            root.mkdir()
            topics.mkdir(parents=True)
            (root / 'functions.json').write_text(
                json.dumps([{'va': '0x1000'}]), encoding='utf-8')
            (root / 'segments.json').write_text(json.dumps([{
                'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1
            }]), encoding='utf-8')
            windows = []
            for start, changes in (
                    (0x1100, {}),
                    (0x1200, {'disk_hex': '909090cc'}),
                    (0x1300, {'size': 3}),
                    (0x1400, {'matching': False}),
                    (0x2100, {})):
                raw = dict(va=hex(start), size=4, idb_hex='90909090',
                           disk_hex='90909090', matching=True)
                raw.update(changes)
                windows.append(dict(start_va=hex(start), end_va=hex(start+4),
                                    status='未声明代码导航窗', raw_range=raw,
                                    items=[{'is_code': True}]))
            (topics / 'raw.json').write_text(json.dumps(windows), encoding='utf-8')
            with patch.object(merge_evidence, 'ROOT', root), patch.object(
                    merge_evidence, 'TOPICS', base / '专题'), contextlib.redirect_stdout(io.StringIO()):
                merge_evidence.main()
            result = json.loads((root / 'evidence_coverage.json').read_text(encoding='utf-8'))
            self.assertEqual(result['unique_exported_functions'], 0)
            self.assertEqual(result['outside_inventory'], ['0x1100'])
            self.assertEqual(result['navigation_window_count'], 1)
            self.assertEqual(result['navigation_windows'][0]['source_scopes'], ['未声明代码导航窗'])

    def test_nested_block_is_kept_only_when_bytes_match(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / '全量分析'
            topics = base / '专题' / '候选'
            root.mkdir()
            topics.mkdir(parents=True)
            (root / 'functions.json').write_text(
                json.dumps([{'va': '0x1000'}]), encoding='utf-8')
            (root / 'segments.json').write_text(json.dumps([{
                'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1
            }]), encoding='utf-8')
            candidates = [
                {'scope': '未声明函数形代码候选', 'block': {
                    'va': '0x1100', 'end': '0x1104', 'size': 4,
                    'ida_hex': '90909090', 'disk_hex': '90909090', 'equal': True}},
                {'scope': '未声明函数形代码候选', 'block': {
                    'va': '0x1200', 'end': '0x1204', 'size': 4,
                    'ida_hex': '90909090', 'disk_hex': '909090cc', 'equal': True}},
            ]
            (topics / 'raw.json').write_text(json.dumps(candidates), encoding='utf-8')
            with patch.object(merge_evidence, 'ROOT', root), patch.object(
                    merge_evidence, 'TOPICS', base / '专题'), contextlib.redirect_stdout(io.StringIO()):
                merge_evidence.main()
            result = json.loads((root / 'evidence_coverage.json').read_text(encoding='utf-8'))
            self.assertEqual(result['total_identified_functions'], 1)
            self.assertEqual(result['unique_exported_functions'], 0)
            self.assertEqual(result['outside_inventory'], ['0x1100'])
            self.assertEqual(result['unrecognized_code_ranges'][0]['evidence'],
                             ['专题/候选/raw.json'])


class ChineseCompleteFunctionEvidenceTest(unittest.TestCase):
    @staticmethod
    def row(va, raw):
        return {'地址': hex(va), '汇编': '测试指令', '字节核验': {
            '匹配': True, 'IDB字节': raw, '磁盘字节': raw}}

    def valid_record(self):
        return {'地址': '0x1000', '大小': 4, '字节一致': True,
                '完整汇编': [self.row(0x1000, '90'), self.row(0x1001, '909090'),
                          self.row(0x1100, 'c3')]}

    def test_strict_gate_checks_inventory_bytes_primary_span_and_tail(self):
        valid = self.valid_record()
        known = {'0x1000'}
        code_ranges = [(0x1000, 0x2000)]
        inventory = {'0x1000': {'span_bytes': 4, 'end_va': '0x1004'}}
        gate = merge_evidence.strict_chinese_function_address
        self.assertEqual(gate(valid, known, code_ranges, inventory), '0x1000')

        top_changes = [
            {'地址': '0x1200'}, {'大小': 0}, {'大小': -1}, {'大小': '4'},
            {'大小': True}, {'完整汇编': []}, {'完整汇编': 'ret'},
            {'字节一致': False}, {'scope': '有限导航窗口'},
            {'kind': '指令片段'}, {'status': '窗口'}, {'状态': '导航'},
            {'scope': 'Navigation window'}, {'kind': 'function fragment'},
            {'start_va': '0x1000'}, {'owner_va': '0x1000'},
            {'site_va': '0x1000'}, {'范围起点': '0x1000'},
            {'va': '0x1010'},
        ]
        for changes in top_changes:
            with self.subTest(top=changes):
                bad = copy.deepcopy(valid)
                bad.update(changes)
                self.assertIsNone(gate(bad, known, code_ranges, inventory))

        row_changes = [
            (0, {'地址': '0x1001'}),
            (0, {'字节核验': {'匹配': False, 'IDB字节': '90', '磁盘字节': '90'}}),
            (0, {'字节核验': {'匹配': True, 'IDB字节': '90', '磁盘字节': 'cc'}}),
            (0, {'字节核验': {'匹配': True, 'IDB字节': 'xx', '磁盘字节': 'xx'}}),
            (0, {'字节核验': {'匹配': True, 'IDB字节': '', '磁盘字节': ''}}),
            (0, {'字节核验': {'匹配': True, 'IDB字节': '9', '磁盘字节': '9'}}),
            (0, {'字节核验': {'匹配': True, 'IDB字节': None, '磁盘字节': None}}),
            (0, {'字节核验': None}), (0, {'字节核验': []}),
            (1, {'地址': '0x1002'}),  # 主连续块提前断开。
            (1, {'地址': '0x1000'}),  # 指令重叠。
            (1, {'字节核验': {'匹配': True, 'IDB字节': '90909090',
                             '磁盘字节': '90909090'}}),  # 主块越过库存结尾。
            (2, {'地址': '0x2000'}),  # 尾块越过可执行段。
        ]
        for index, changes in row_changes:
            with self.subTest(index=index, row=changes):
                bad = copy.deepcopy(valid)
                bad['完整汇编'][index].update(changes)
                self.assertIsNone(gate(bad, known, code_ranges, inventory))

        self.assertIsNone(gate(valid, known, code_ranges,
                               {'0x1000': {'span_bytes': 5, 'end_va': '0x1004'}}))
        self.assertIsNone(gate(valid, known, code_ranges,
                               {'0x1000': {'span_bytes': 4, 'end_va': '0x1005'}}))
        self.assertIsNone(gate(valid, known, code_ranges,
                               {'0x1000': {'span_bytes': 4}}))

    def test_chinese_sources_deduplicate_with_english_and_keep_sites_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / '全量分析'
            topics = base / '专题' / '夹具'
            root.mkdir()
            topics.mkdir(parents=True)
            inventory = [{'va': '0x1000', 'span_bytes': 4, 'end_va': '0x1004'},
                         {'va': '0x1010', 'span_bytes': 1, 'end_va': '0x1011'},
                         {'va': '0x1020', 'span_bytes': 1, 'end_va': '0x1021'},
                         {'va': '0x1030', 'span_bytes': 1, 'end_va': '0x1031'},
                         {'va': '0x1040', 'span_bytes': 1, 'end_va': '0x1041'}]
            (root / 'functions.json').write_text(json.dumps(inventory), encoding='utf-8')
            (root / 'segments.json').write_text(json.dumps([{
                'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1
            }]), encoding='utf-8')
            second = {'地址': '0x1010', '大小': 1, '字节一致': True,
                      '完整汇编': [self.row(0x1010, 'c3')]}
            bad = {'地址': '0x1030', '大小': 1, '字节一致': True,
                   '伪代码': '不能仅凭伪代码计入', '完整汇编': []}
            site = {'地址': '0x1040', '汇编': 'ret', '字节核验': {
                '匹配': True, 'IDB字节': 'c3', '磁盘字节': 'c3'}}
            (topics / 'a.json').write_text(json.dumps([
                self.valid_record(), second, bad, site,
                {'地址': '0x1030', '伪代码': '只有伪代码'},
                {'地址': '0x1040', '状态': '已分析', '结论': '只有结论'},
                {'va': '0x1030', 'assembly': 'ret', 'function': '0x1030'},
                {'va': '0x1020', 'assembly': [{'va': '0x1020', 'text': 'ret'}]}
            ], ensure_ascii=False), encoding='utf-8')
            (topics / 'b.json').write_text(json.dumps([
                self.valid_record(), second
            ], ensure_ascii=False), encoding='utf-8')
            with patch.object(merge_evidence, 'ROOT', root), patch.object(
                    merge_evidence, 'TOPICS', base / '专题'), contextlib.redirect_stdout(io.StringIO()):
                merge_evidence.main()
            result = json.loads((root / 'evidence_coverage.json').read_text(encoding='utf-8'))
            self.assertEqual(result['unique_exported_functions'], 3)
            self.assertEqual(result['total_identified_functions'], 5)
            self.assertEqual(result['outside_inventory'], [])
            self.assertEqual(result['instruction_observation_count'], 1)
            self.assertEqual(result['instruction_observations'][0]['va'], '0x1030')
            self.assertEqual(result['navigation_window_count'], 0)
            by_va = {record['va']: record['evidence'] for record in result['functions']}
            self.assertEqual(set(by_va), {'0x1000', '0x1010', '0x1020'})
            self.assertEqual(by_va['0x1000'], ['专题/夹具/a.json', '专题/夹具/b.json'])
            self.assertEqual(by_va['0x1010'], ['专题/夹具/a.json', '专题/夹具/b.json'])
            self.assertEqual(by_va['0x1020'], ['专题/夹具/a.json'])


class CompleteBodySourceTest(unittest.TestCase):
    @staticmethod
    def body():
        return {'va': '0x1000', 'end_va': '0x1002', 'bytes_match_disk': True,
                'assembly': [{'va': '0x1000', 'text': 'nop'}, {'va': '0x1001', 'text': 'ret'},
                             {'va': '0x1100', 'text': 'ret'}],
                'declared_chunks': [{'start_va': '0x1000', 'end_va': '0x1002', 'is_main': True},
                                    {'start_va': '0x1100', 'end_va': '0x1101', 'is_main': False}],
                'byte_ranges': [{'va': '0x1000', 'size': 2, 'matching': True,
                                 'idb_hex': '90c3', 'disk_hex': '90c3'},
                                {'va': '0x1100', 'size': 1, 'matching': True,
                                 'idb_hex': 'c3', 'disk_hex': 'c3'}]}

    def test_gate_rejects_partial_malformed_or_overlapping_bodies(self):
        gate = merge_evidence.strict_complete_body_address
        inventory = {'0x1000': {'end_va': '0x1002', 'span_bytes': 2}}
        ranges = [(0x1000, 0x2000)]
        body = self.body()
        self.assertEqual(gate(body, inventory, ranges), '0x1000')
        for changes in ({'owner_va': '0x1000'}, {'owner': '0x1000'}, {'prefix': True},
                        {'scope': '96字节前缀导航'}, {'assembly': []}, {'bytes_match_disk': False},
                        {'va': '0x1200'}, {'declared_chunks': []}, {'byte_ranges': []},
                        {'end_va': '0x1001'}):
            with self.subTest(changes=changes):
                candidate = copy.deepcopy(body)
                candidate.update(changes)
                self.assertIsNone(gate(candidate, inventory, ranges))
        for changes in ({'size': True}, {'matching': False}, {'disk_hex': '90cc'},
                        {'idb_hex': 'xx'}, {'va': '0x2000'}, {'size': 1},
                        {'size': 1, 'idb_hex': '90', 'disk_hex': '90'}):
            with self.subTest(span=changes):
                candidate = copy.deepcopy(body)
                candidate['byte_ranges'][0].update(changes)
                self.assertIsNone(gate(candidate, inventory, ranges))
        for field in ('declared_chunks', 'byte_ranges', 'assembly'):
            candidate = copy.deepcopy(body)
            candidate[field].append(copy.deepcopy(candidate[field][0]))
            with self.subTest(overlap=field):
                self.assertIsNone(gate(candidate, inventory, ranges))
        candidate = copy.deepcopy(body)
        candidate['assembly'][0]['va'] = '0x1100'
        self.assertIsNone(gate(candidate, inventory, ranges))

    def test_whitelist_reads_only_top_level_bodies_and_deduplicates_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / '全量分析'
            topics = base / '专题'
            topics.mkdir()
            special = root / '异常尾块与清理契约'
            special.mkdir(parents=True)
            (root / 'functions.json').write_text(json.dumps([
                {'va': '0x1000', 'end_va': '0x1002', 'span_bytes': 2},
                {'va': '0x1100', 'end_va': '0x1101', 'span_bytes': 1}
            ]), encoding='utf-8')
            (root / 'segments.json').write_text(json.dumps([{
                'start_va': '0x1000', 'end_va': '0x2000', 'permission': 1
            }]), encoding='utf-8')
            body = self.body()
            false_entry = {'va': '0x1100', 'assembly': [{'va': '0x1100', 'text': 'ret'}]}
            contents = {'functions': [body, false_entry], 'thunks': [false_entry],
                        'owners': [false_entry], 'prefixes': [false_entry]}
            for name in ('cleanup_targets_full.json', 'unwind_runtime.json', 'cleanup_evidence.json'):
                (special / name).write_text(json.dumps(contents), encoding='utf-8')
            (topics / 'raw.json').write_text(json.dumps({'va': '0x1000', 'assembly': []}), encoding='utf-8')
            with patch.object(merge_evidence, 'ROOT', root), patch.object(
                    merge_evidence, 'TOPICS', topics), contextlib.redirect_stdout(io.StringIO()):
                merge_evidence.main()
            result = json.loads((root / 'evidence_coverage.json').read_text(encoding='utf-8'))
            self.assertEqual(result['unique_exported_functions'], 1)
            self.assertEqual(result['outside_inventory'], [])
            self.assertEqual(result['functions'][0]['evidence'], [
                '专题/raw.json',
                '全量分析/异常尾块与清理契约/cleanup_targets_full.json',
                '全量分析/异常尾块与清理契约/unwind_runtime.json'])


if __name__ == '__main__':
    unittest.main()
