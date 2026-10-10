"""无损适配新本体、旧无字节导航和固定旧契约；不修改任何原证。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'b54d51310320c1d05b44407c76fd02177ad3f196b87f8175ef00dc24df8e75fa'
HELPER = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
SPECS = [
    ('专题/图像资源/证据/20261009_图像加载函数群.json', '/functions/18', '0x6d7660', '既有取槽包装；追加本批当前块字节，不改旧instructions'),
    ('专题/图像资源/证据/20261009_图像加载函数群.json', '/functions/19', '0x6dfd10', '既有递减取槽；追加本批当前块字节，不改旧instructions'),
    ('专题/4019系列事件/证据/resource_loader_scope.json', '/functions/0', '0x6d8130', '旧完整机械原证；语义只审OTHER分组路径6DA1A1..6DA473'),
    ('专题/124字节共享数组生命周期/证据/reused_raw.json', '/records/4/original_record', '0x622d50', '既有等步长构造迭代器契约'),
    ('专题/124字节共享数组生命周期/证据/reused_raw.json', '/records/9/original_record', '0x91f7e0', '既有delete[]包装；不扩大底层释放和异常语义'),
    ('专题/4060系列事件/证据/callees.json', '/functions/10', '0x91f6d0', '既有栈诊断正常相等路径保留EAX'),
    ('专题/SysRes鼠标资源加载/证据/bounded_raw.json', '/functions/1', '0x6db9d0', '既有100项鼠标数量消费者；只连接group4与record+4'),
]


def pointer(obj, path):
    for k in path.strip('/').split('/'):
        obj = obj[int(k)] if isinstance(obj, list) else obj[k]
    return obj


def main():
    assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == 'd8a99e346ee86d452233f9060877452f29f5e2846ccac11cb84bd04dde788753'
    adapt = runpy.run_path(str(HELPER))['adapt']
    raw = (HERE / 'bounded_raw.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RAW_SHA
    data = json.loads(raw)
    path = '专题/资源配置分组记录生产/证据/bounded_raw.json'
    rows = [adapt(r, path, '/functions/' + str(i), RAW_SHA, '本批新本体完整局部分析') for i, r in enumerate(data['functions'])]
    (HERE / 'formal_functions.json').write_text(json.dumps(dict(disk_sha256=SHA, functions=rows), ensure_ascii=False, indent=2) + '\n', 'utf-8')
    rows = []
    for source, ptr, va, scope in SPECS:
        source_bytes = (DOCS / source).read_bytes()
        original = pointer(json.loads(source_bytes), ptr)
        assert original.get('va', original.get('seed_va')) == va
        augmented = dict(original)
        if not any(k in original for k in ('byte_ranges', 'chunk_byte_ranges', 'chunks')):
            indexes = [i for i, a in enumerate(data['current_chunk_audits']) if a['seed_va'] == va]
            assert len(indexes) == 1
            index = indexes[0]
            augmented['chunk_byte_ranges'] = data['current_chunk_audits'][index]['chunk_byte_ranges']
            augmented['current_bytes_source'] = dict(source_path=path, source_pointer='/current_chunk_audits/' + str(index), source_sha256=RAW_SHA)
        row = adapt(augmented, source, ptr, hashlib.sha256(source_bytes).hexdigest(), scope)
        row['source_field_pointers'] = {k: ptr + '/' + k for k in original}
        for item in row['normalized_assembly']:
            item['normalized_item_kind'] = 'data' if item['text'].lstrip().split()[0].lower() in ('db', 'dw', 'dd', 'dq') else 'code'
        rows.append(row)
    (HERE / 'reused_functions.json').write_text(json.dumps(dict(disk_sha256=SHA, functions=rows), ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print('4 new bodies; 7 historical records; two historical navigation records joined to current IDA chunks')


if __name__ == '__main__':
    main()
