"""Bind seven complete bodies to unmodified source rows and current chunk audits."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def binding(path, pointer, base='docs'):
    data = ((DOCS if base == 'docs' else HERE.parent) / path).read_bytes()
    node = json.loads(data)
    for part in pointer.lstrip('/').split('/'):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return dict(base=base, path=path, sha256=sha(data), json_pointer=pointer), node


def normalized(record, ranges):
    assembly = record.get('assembly', record.get('instructions'))
    return dict(
        va=record.get('va', record.get('seed_va')),
        name=record['name'],
        end_va=record.get('end_va', hex(max(int(b.get('start_va', b.get('va')), 16) + b['size'] for b in ranges))),
        assembly=[dict(va=i.get('va', i.get('site_va')), text=i['text'], is_code=i.get('is_code', True)) for i in assembly],
        pseudocode=record['pseudocode'],
        decompile_error=record.get('decompile_error', record.get('pseudocode_error')),
        error_field_present='decompile_error' in record or 'pseudocode_error' in record,
        chunk_byte_ranges=[dict(va=b.get('start_va', b.get('va')), size=b['size'],
            idb_hex=b.get('idb_hex', b.get('ida_hex')), disk_hex=b['disk_hex'],
            matching=b.get('matching', b.get('equal')),
            sha256=sha(bytes.fromhex(b.get('idb_hex', b.get('ida_hex'))))) for b in ranges],
    )


def build():
    raw = json.loads((HERE / 'bounded_raw.json').read_bytes())
    functions = []
    for i, record in enumerate(raw['functions']):
        source, original = binding('证据/bounded_raw.json', '/functions/' + str(i), 'topic')
        row = normalized(record, record['chunk_byte_ranges'])
        row.update(source=source, source_record=original, coverage_origin='本批新增完整主体')
        functions.append(row)
    for va, path, index in (
        ('0x90ce80', '专题/文本宽度到字符位置/证据/width_position.json', 0),
        ('0x90d120', '专题/文本宽度到字符位置/证据/width_position.json', 6),
        ('0x90d310', '专题/文本宽度到字符位置/证据/width_position.json', 7),
        ('0x8fae70', '专题/727F控件状态接口/证据/text_dependencies.json', 1),
    ):
        source, original = binding(path, '/functions/' + str(index))
        ai, audit = next((i, f) for i, f in enumerate(raw['current_chunk_audits']) if f['seed_va'] == va)
        current, current_record = binding('证据/bounded_raw.json', '/current_chunk_audits/' + str(ai), 'topic')
        row = normalized(original, audit['chunk_byte_ranges'])
        assert row['va'] == va
        row.update(source=source, source_record=original, current_audit_source=current,
            current_audit_record=current_record, coverage_origin='指定旧主体完整静态复核；不计新增')
        functions.append(row)
    for f in functions:
        f['declared_chunks'] = [dict(start_va=b['va'], end_va=hex(int(b['va'], 16) + b['size']), is_main=b['va'] == f['va']) for b in f['chunk_byte_ranges']]
        f['bytes_match_disk'] = all(b['matching'] is True for b in f['chunk_byte_ranges'])
        f['status'] = '原证无损适配；语义分级见函数审阅清单.json'
    dependencies = []
    for va, path, index, conclusion in (
        ('0x8f4b10', '专题/列表控件行记录与布局/证据/list_functions.json', 16, '可见宽度带关联对象扣减；有符号结果无非负钳制'),
        ('0x8f4ba0', '专题/列表控件行记录与布局/证据/list_functions.json', 18, '可见行容量有符号除法；零分母与溢出未设门'),
        ('0x8f4c20', '专题/列表控件行记录与布局/证据/list_functions.json', 19, '仅index<C门，回收描述及A0h行搬移，负index未拒绝'),
        ('0x8f39d0', '专题/列表控件行记录与布局/证据/list_dependencies.json', 5, '行创建/移位受配置和数量上限限制，可能不创建'),
        ('0x8eb410', '专题/控件回调与事件表/证据/注册与生命周期.json', 9, '范围约束位置后同步虚表通知；动态目标与重入未知'),
    ):
        source, record = binding(path, '/functions/' + str(index))
        assert record['va'] == va
        dependencies.append(dict(va=va, source=source, source_record=record,
            contract=conclusion, scope='仅指定旧依赖调用契约；不计本批完整主体或新增成果'))
    result = dict(schema='richonline-caret-formal-adaptation-1', disk_sha256=raw['disk_sha256'],
        source_sha256=sha((HERE / 'bounded_raw.json').read_bytes()), functions=functions,
        dependencies=dependencies, scope='三新完整主体、四指定旧主体完整复核；五旧短依赖只用于调用契约')
    (HERE / 'formal_functions.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(functions=len(functions), dependencies=len(dependencies))))


if __name__ == '__main__':
    build()
