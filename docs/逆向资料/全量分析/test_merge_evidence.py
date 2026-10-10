"""未声明嵌套代码块应单列，不改变已声明函数分母。"""

import contextlib
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


if __name__ == '__main__':
    unittest.main()
