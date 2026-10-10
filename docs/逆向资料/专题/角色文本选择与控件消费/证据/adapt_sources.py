"""固定来源无损适配；角色文本为历史目录名，本批恢复图像数值选择。"""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
HELPER = DOCS/'专题/地图选择字段与列表消费/证据/adapt_sources.py'
spec = importlib.util.spec_from_file_location('bounded_adapter', HELPER)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def main():
    raw = (HERE/'bounded_raw.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'd3f6cc36649f163aab76931e1fa8b62573be4027e6f57f7a5cdc06764df053a6'
    data = json.loads(raw)
    rows = [adapter.adapt(row, '专题/角色文本选择与控件消费/证据/bounded_raw.json',
                          '/functions/'+str(i), hashlib.sha256(raw).hexdigest(),
                          '本批新主体完整原证；语义分级见函数审阅清单')
            for i, row in enumerate(data['functions'])]
    result = dict(disk_sha256=SHA, adapter_helper_sha256=hashlib.sha256(HELPER.read_bytes()).hexdigest(), functions=rows)
    (HERE/'formal_functions.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    specs = [
        ('业务提示与期限映射/证据/callers.json', ['0x756460', '0x762e10'], '历史完整原证；本批仅相关消费路径部分分析'),
        ('业务提示与期限映射/证据/followups.json', ['0x627c20', '0x6dba40'], '历史helper局部契约复用'),
        ('TeachMode对象与消费者/证据/teachmode_raw.json', ['0x6276a0', '0x627760', '0x646610', '0x6fa7f0'], '历史helper局部契约复用'),
        ('Avatar配置与角色图片/证据/supplement_raw.json', ['0x646590'], '历史helper局部契约复用'),
        ('控件图像状态记录/证据/functions_raw.json', ['0x8e1c70'], '历史helper局部契约复用'),
    ]
    rows = []
    for suffix, addresses, scope in specs:
        path = '专题/'+suffix
        raw = (DOCS/path).read_bytes()
        source = json.loads(raw)
        for address in addresses:
            matches = [(ptr, row) for ptr, row in adapter.walk(source)
                       if row.get('va', row.get('address')) == address
                       and any(key in row for key in ('assembly', 'instructions'))]
            assert len(matches) == 1, (path, address)
            ptr, row = matches[0]
            rows.append(adapter.adapt(row, path, ptr, hashlib.sha256(raw).hexdigest(), scope))
    (HERE/'reused_functions.json').write_text(json.dumps(dict(disk_sha256=SHA, functions=rows), ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print('adapted: 2 new, 2 reused consumers, 8 historical contracts')


if __name__ == '__main__':
    main()
