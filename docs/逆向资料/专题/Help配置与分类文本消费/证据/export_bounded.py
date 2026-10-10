"""第二十三批 Help 配置与分类文本固定范围；加载不执行采证。"""
import hashlib
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1] / '四类型辅助请求与队列/证据/export_preparation_core.py'
CONFIG = dict(
    topic='Help配置与分类文本消费',
    seeds=(0x69C740, 0x69C790, 0x69C880, 0x69C930, 0x69CBB0,
           0x69CE30, 0x69D190, 0x69D510, 0x629480, 0x628A80),
    owner_sites=(0x628AD9, 0x629491, 0x623F5A, 0x69D7F1,
                 0x69D821, 0x69D851, 0x69D881, 0x69D8B1),
    # 字符串尺寸含末尾 NUL，已从当前基线磁盘核定；不把邻接字符串并为结构。
    data_windows=((0xA766F8, 4), (0xA2364C, 14), (0xA2365C, 3),
                  (0xA23660, 4), (0xA23664, 7), (0xA2366C, 5),
                  (0xA23674, 4), (0xA23678, 7), (0xA23680, 6),
                  (0xA23688, 4), (0xA2368C, 8), (0xA23694, 3),
                  (0xA23698, 5), (0xA236A0, 5), (0xA236A8, 4),
                  (0xA236AC, 4), (0xA236B0, 6), (0xA236B8, 3),
                  (0xA236BC, 5), (0xA236C4, 5), (0xA236CC, 5),
                  (0xA236D4, 5), (0xA236DC, 3)),
    reuse_navigation=(
        '专题/TeachMode对象与消费者/证据/teachmode_raw.json',
        '专题/游戏时间与计时调度/证据/functions.json',
        '专题/文本与容器/证据/parser_kpd_functions.json',
        '专题/40D0系列事件/证据/ui_helpers.json',
    ),
)


def export():
    report = runpy.run_path(str(CORE))['export'](CONFIG, HERE)
    return dict(report, prepared_wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
