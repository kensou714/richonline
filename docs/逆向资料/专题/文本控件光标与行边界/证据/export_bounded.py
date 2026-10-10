"""第二十四批文本控件光标与行边界；加载不访问IDA。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='文本控件光标与行边界',
    seeds=(0x8FC6A0, 0x8FC830, 0x8FCCD0, 0x90CE80, 0x90D120, 0x90D310, 0x8FAE70),
    owner_sites=(0x8FB12F, 0x8FB3D2, 0x8FB3DD, 0x8FE17C, 0x8FE19F, 0x90149D),
    # IDB导入槽与当前PE不同；另存两份字节及导入枚举，不纳入相等断言。
    data_windows=(),
    reuse_navigation=(
        '专题/文本宽度到字符位置/证据/width_position.json',
        '专题/727F控件状态接口/证据/text_dependencies.json',
    ),
)


def export():
    assert not (HERE / 'bounded_raw.json').exists(), '禁止覆盖既有原证'
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
