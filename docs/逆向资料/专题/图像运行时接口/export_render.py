"""只读导出图像运行时接口；不解码资源、不调用图形API或修改IDA。"""
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/图像运行时接口'
SEEDS = [0x6DC650, 0x6DC730, 0x6DC7D0, 0x6DC850, 0x6DC8F0,
         0x6DCBA0, 0x6DCC00, 0x6DCDD0, 0x917330]
DEPENDENCIES = [0x814320, 0x814120, 0x814930, 0x814EC0, 0x813B20,
                0x6DFAD0, 0x6DFA80]
FRAMES = [0x6DCC40, 0x6DCD60, 0x6DC090]


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    return [export(db, SEEDS, str(HERE / '证据/candidate_seeds.json')),
            export(db, DEPENDENCIES, str(HERE / '证据/render_dependencies.json')),
            export(db, FRAMES, str(HERE / '证据/frame_dependencies.json'))]
