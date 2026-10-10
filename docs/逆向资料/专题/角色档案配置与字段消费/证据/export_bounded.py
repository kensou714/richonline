"""第二十四批角色档案固定范围；加载不执行采证，由主代理串行调用。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='角色档案配置与字段消费',
    seeds=(0x7F2C20, 0x7F2C40, 0x7F2C90, 0x629750, 0x6A25A0,
           0x7F35F0, 0x7F3630, 0x6276A0, 0x6B7930, 0x646590),
    owner_sites=(0x623BFE, 0x64181C, 0x749F98, 0x749F9F,
                 0x751E47, 0x751E4E, 0x752224, 0x75222B),
    # 字符串含实际末尾NUL；A69330是四字节未知数据，不能按路径解释。
    data_windows=((0xA766D0, 4), (0xA69330, 4),
                  (0xA2DB78, 5), (0xA2DB88, 5), (0xA2DB80, 5), (0xA2DB90, 5),
                  (0xA2DB98, 5), (0xA2DBA0, 5), (0xA2DBA8, 4), (0xA2DBAC, 9),
                  (0xA2DBB8, 7), (0xA2DBC0, 7), (0xA2DBC8, 8), (0xA2DBD0, 9),
                  (0xA2DBDC, 10), (0xA2DBE8, 4), (0xA2DBEC, 10), (0xA2DBF8, 7),
                  (0xA2DC00, 7), (0xA2DC08, 5), (0xA2DC10, 9), (0xA2DC1C, 4),
                  (0xA2DC20, 6), (0xA2DC28, 8), (0xA2DC30, 5), (0xA2DC38, 9),
                  (0xA2DC44, 4), (0xA2DC48, 6), (0xA2DC50, 10),
                  (0xA2DB6C, 5), (0xA2DB70, 1), (0xA2DB74, 4)),
    reuse_navigation=(
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json',
        '专题/音频系统/证据/audio_highlevel_functions.json',
        '专题/Avatar配置与角色图片/证据/supplement_raw.json',
        '专题/事件文字记录器/证据/resource_parser.json',
        '专题/文本过滤与字码转换/证据/functions_raw.json',
        '专题/全局数值配置/证据/functions.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
