"""闭合Avatar构造/释放/容量来源；主代理先查覆盖，再显式传记录构造目标。"""
import importlib.util
import json
from pathlib import Path

import ida_bytes
import idautils

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent


def bridge(va):
    raw = ida_bytes.get_bytes(va, 5)
    assert raw is not None and len(raw) == 5 and raw[0] == 0xE9, hex(va)
    return dict(va=hex(va), size=5, hex=raw.hex(),
                target=hex(va + 5 + int.from_bytes(raw[1:], 'little', signed=True)))


def resolve():
    return [bridge(va) for va in (0x608321, 0x60F4AA)]


def export(db, record_constructor=None):
    assert record_constructor is not None, '先resolve并核中央覆盖，再传入允许新导的真实目标'
    constructor = bridge(0x608321)
    assert int(constructor['target'], 16) == record_constructor
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('avatar_supplement', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, (record_constructor, 0x646590, 0x6294D0), HERE / 'supplement_raw.json')
    spec = importlib.util.spec_from_file_location('avatar_windows', HERE / 'export_avatar.py')
    windows_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(windows_module)
    windows = []
    for site in (0x6245C9, 0x624609):
        owner, rows = windows_module.context(site, before=15, after=14)
        assert owner == '0x624080' and rows
        windows.append(dict(site=hex(site), owner=owner, context=rows,
                            status='全局退出有限窗口，不认领624080完整主体'))
    incoming = []
    for xref in idautils.XrefsTo(0x6294D0, 0):
        owner, rows = windows_module.context(xref.frm, before=7, after=4)
        incoming.append(dict(seed='0x6294d0', site=hex(xref.frm), kind=int(xref.type),
                             owner=owner, context=rows, status='外层释放引用导航'))
    data = [bridge(va) for va in (0x608321, 0x60F4AA, 0x609A91, 0x60E29E)]
    for row in data:
        row.update(scope='显式E9桥，目标和当前PE须独立核验')
    result = dict(schema=1, scope='显式允许的新依赖；622D50构造迭代器必须复用MapView',
                  data=data, literals=[], windows=windows, incoming=incoming,
                  context_disk_status='待离线逐条当前PE核验')
    (HERE / 'supplement_context.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(group=summary, windows=len(windows), incoming=len(incoming), bridges=len(data))


def export_coordinate(db):
    # 本批坐标回调另文件采集，不能冒充已经包含在三主体补证文件内。
    assert int(bridge(0x60F4AA)['target'], 16) == 0x641550
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('avatar_coordinate', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_group(db, (0x641550,), HERE / 'coordinate_constructor_raw.json')
