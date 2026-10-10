"""保留本批及固定旧记录全部原字段，只新增来源与规范化阅读字段。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'daf27638a4dab260e7e3c119247001fa9d5a767428b7241d2d4b6e8f09d123ff'
HELPER = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
SPECS = [
    ('40B0系列事件/证据/monster_helpers.json', 0, '0x627760', '旧配置根身份窄契约'),
    ('40B0系列事件/证据/request_helpers.json', 1, '0x6278f0', '旧鼠标根身份窄契约'),
    ('游戏鼠标对象与业务门/证据/bounded_raw.json', 0, '0x6baac0', '旧100槽构造契约'),
    ('40B0系列事件/证据/request_helpers.json', 35, '0x6bad80', '旧光标选择契约'),
    ('游戏鼠标对象与业务门/证据/destructor_raw.json', 0, '0x6bab00', '旧100槽释放契约'),
    ('游戏鼠标对象与业务门/证据/exit_dependency_raw.json', 1, '0x629890', '旧删除包装契约'),
    ('40EE系列事件/证据/direct_helpers.json', 5, '0x629ed0', '既有HWND全局读取窄契约'),
    ('4060系列事件/证据/callees.json', 10, '0x91f6d0', '旧栈诊断正常返回保留EAX窄契约'),
    ('CRT格式化入口契约/证据/sprintf_raw.json', 0, '0x9206d0', '旧sprintf入口契约；格式化引擎不重认'),
    ('4060系列事件/证据/helpers.json', 36, '0x91fbb0', '旧cookie相等三指令返回契约；异常分支不展开'),
]


def main():
    assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == 'd8a99e346ee86d452233f9060877452f29f5e2846ccac11cb84bd04dde788753'
    adapt = runpy.run_path(str(HELPER))['adapt']
    source = '专题/SysRes鼠标资源加载/证据/bounded_raw.json'
    raw = (DOCS / source).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RAW_SHA
    data = json.loads(raw)
    assert [r['seed_va'] for r in data['functions']] == ['0x6bab70', '0x6db9d0']
    rows = [adapt(row, source, '/functions/' + str(i), RAW_SHA, '本批新本体无损适配')
            for i, row in enumerate(data['functions'])]
    (HERE / 'formal_functions.json').write_text(json.dumps(dict(disk_sha256=SHA, adapter_helper_sha256=hashlib.sha256(HELPER.read_bytes()).hexdigest(), functions=rows), ensure_ascii=False, indent=2) + '\n', 'utf-8')
    rows = []
    for name, index, va, scope in SPECS:
        path = '专题/' + name
        raw = (DOCS / path).read_bytes()
        row = json.loads(raw)['functions'][index]
        assert row.get('va', row.get('seed_va')) == va
        adapted = adapt(row, path, '/functions/' + str(index), hashlib.sha256(raw).hexdigest(), scope)
        # 旧源可能未给is_code；原文db填充另列数据，不把多字节填充当一条指令。
        for item in adapted['normalized_assembly']:
            item['normalized_item_kind'] = 'data' if item['text'].lstrip().split()[0].lower() in ('db', 'dw', 'dd', 'dq') else 'code'
        rows.append(adapted)
    (HERE / 'reused_functions.json').write_text(json.dumps(dict(disk_sha256=SHA, functions=rows), ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print('2 new bodies; 10 historical records adapted without altering source fields')


if __name__ == '__main__':
    main()
