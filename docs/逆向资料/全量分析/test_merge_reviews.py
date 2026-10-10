"""独立回归：地址字典清单可合并，来源、原分级和结论边界不丢失。"""
import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('review_merge_under_test', HERE / 'merge_reviews.py')
MERGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGER)


class ReviewSchemaTests(unittest.TestCase):
    def nodes(self, data):
        return {pointer: node for node, pointer in MERGER.walk(data)}

    def test_direct_address_key(self):
        source = {'0x64ff10': {'status': '静态契约已审阅', 'conclusion': '八槽筛选'}}
        row = self.nodes(source)['/0x64ff10']
        self.assertEqual(row['va'], '0x64ff10')
        self.assertNotIn('va', source['0x64ff10'])  # 遍历不能改写输入档案。

    def test_nested_address_key_and_pointer_escaping(self):
        data = {'a/b~c': {'functions': {'0x64ff10': {'status': '局部审阅'}}}}
        row = self.nodes(data)['/a~1b~0c/functions/0x64ff10']
        self.assertEqual(row['va'], '0x64ff10')

    def test_key_is_not_inherited_by_descendants(self):
        data = {'0x64ff10': {'child': {'status': '无独立地址'}, 'items': [{'conclusion': '局部'}]}}
        nodes = self.nodes(data)
        self.assertNotIn('va', nodes['/0x64ff10/child'])
        self.assertNotIn('va', nodes['/0x64ff10/items/0'])

    def test_array_indices_and_non_hex_keys_are_not_addresses(self):
        data = {'items': [{'status': '局部审阅'}], '123': {'status': '数字键'},
                '0xnothex': {'status': '坏地址'}, 'named': {'status': '名称'}}
        for pointer, node in self.nodes(data).items():
            with self.subTest(pointer=pointer):
                self.assertNotIn('va', node)

    def test_explicit_address_wins(self):
        row = self.nodes({'0x64ff10': {'va': '0x7f7400'}})['/0x64ff10']
        self.assertEqual(row['va'], '0x7f7400')
        for field in ('address', 'ea', '地址'):
            with self.subTest(field=field):
                row = self.nodes({'0x64ff10': {field: '0x7f7400'}})['/0x64ff10']
                self.assertNotIn('va', row)
                self.assertEqual(row[field], '0x7f7400')

    def test_record_keeps_unknown_boundary_reuse_and_grade(self):
        node = {'status': '复用已有语义', 'conclusion': '返回this+4地址',
                'unknown': '其他成员未知', 'boundary': '只复用薄接口',
                'reuse_reference': '专题/原证.json#/functions/0', 'evidence': ['原证.json']}
        record = MERGER.review_record(node, '专题/清单.json', '/0x63e000',
                                      node['status'], node['conclusion'])
        for key in ('status', 'conclusion', 'unknown', 'boundary', 'reuse_reference', 'evidence'):
            self.assertEqual(record[key], node[key], key)
        self.assertEqual(record['source'], '专题/清单.json')
        self.assertEqual(record['json_pointer'], '/0x63e000')

    def test_boundary_fills_only_missing_unknown(self):
        for field in ('unknown', 'unknowns', '未知项', 'unresolved'):
            with self.subTest(field=field):
                node = {field: '已有未知项', 'boundary': '范围限制'}
                record = MERGER.review_record(node, '清单', '/', '局部审阅', '原结论')
                self.assertEqual(record['unknown'], '已有未知项')
                self.assertEqual(record['boundary'], '范围限制')
        record = MERGER.review_record({'boundary': '范围限制'}, '清单', '/', '局部审阅', '原结论')
        self.assertEqual(record['unknown'], '范围限制')

    def test_real_eight_role_manifest(self):
        path = HERE.parent / '专题/八角色命中筛选契约/证据/function_review.json'
        data = json.loads(path.read_text(encoding='utf-8'))
        nodes = self.nodes(data)
        inventory = {row['va'] for row in json.loads((HERE / 'functions.json').read_text(encoding='utf-8'))}
        self.assertEqual(len(data), 17)  # 固定专题清单，不固定全项目持续增长的合并总数。
        for address, original in data.items():
            with self.subTest(address=address):
                node = nodes['/' + address]
                self.assertEqual(node['va'], address)
                self.assertIn(address, inventory)
                record = MERGER.review_record(node, path.relative_to(HERE.parent).as_posix(),
                                              '/' + address, node['status'], node['conclusion'])
                for field in ('status', 'conclusion', 'boundary'):
                    self.assertEqual(record[field], original[field])
                self.assertEqual(record['unknown'], original['boundary'])
                if 'reuse_reference' in original:
                    self.assertEqual(record['reuse_reference'], original['reuse_reference'])

    def test_only_explicit_undeclared_ranges_are_reviews(self):
        row = {'start_va': '0x81b8b0', 'end_va': '0x81b973'}
        self.assertEqual(MERGER.explicit_range(row, '未声明代码区间已审阅'),
                         ('0x81b8b0', '0x81b973'))
        self.assertIsNone(MERGER.explicit_range(row, '人工导航窗口'))
        self.assertIsNone(MERGER.explicit_range({'start_va': '0x81b8b0'},
                                                '未声明代码区间已审阅'))

    def test_undeclared_ranges_stay_outside_function_inventory(self):
        evidence = json.loads((HERE / 'evidence_coverage.json').read_text(encoding='utf-8'))
        review = json.loads((HERE / 'review_coverage.json').read_text(encoding='utf-8'))
        wanted = {'0x81b8b0', '0x855b10', '0x886fb0', '0x887310'}
        self.assertTrue(wanted <= set(evidence['outside_inventory']))
        ranges = {row['va']: row for row in review['unrecognized_range_reviews']}
        self.assertTrue(wanted <= set(ranges))
        self.assertTrue(all(len(ranges[va]['reviews']) == 1 for va in wanted))
        self.assertFalse(wanted & {row['va'] for row in review['functions']})


if __name__ == '__main__':
    unittest.main()
