"""第二十八批角色描述与界面构造有限采证；仅root串行执行export。"""
import hashlib
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parents[2]
ROOT = HERE.parents[4]
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
CORE_SHA = '565b9efb2ebc21730bc492fe5ca429885ba675f62b112a2a4dd5703a70654609'
NEW = (0x6423C0, 0x6FC210)
REUSED = (0x642480, 0x6E1D90, 0x6E93D0)
CONFIG = dict(
    topic='角色外观描述与界面实例',
    seeds=NEW + REUSED,
    owner_sites=(0x6E9420, 0x7F438E, 0x7F4424, 0x7F45D4, 0x7F466A),
    # 仅核首槽，不把四字节前缀声明成完整虚表。
    data_windows=((0xA27600, 4),),
    reuse_navigation=(
        '专题/角色与精灵动画/证据/角色精灵_IDA原始导出.json',
        '专题/提示文本生命周期/证据/lifecycle.json',
        '专题/界面系统/第二批/ida_ui_batch2_raw.json',
        '专题/角色1416字段来源/证据/functions.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖已有原证'
    assert hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    assert hashlib.sha256(CORE.read_bytes()).hexdigest() == CORE_SHA
    coverage = json.loads((DOCS / '全量分析/evidence_coverage.json').read_text('utf-8'))
    known = {int(row['va'], 16) for row in coverage['functions']}
    assert not (set(NEW) & known), '新种子已进入中央原证，须先核去重，不得重复登记'
    assert set(REUSED) <= known, '固定旧主体必须复用，禁止因漏识别重导为新本体'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    assert report['new_function_exports'] == 2 and report['reused_seeds'] == 3
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
