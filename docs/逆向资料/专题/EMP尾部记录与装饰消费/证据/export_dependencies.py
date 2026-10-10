"""只读复核既有图像实参接口、Map绘制调用来源及尾部谓词。"""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
ADDRESSES = (0x6DC470, 0x6DB580, 0x63F3C0, 0x64F780)


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    spec = importlib.util.spec_from_file_location('emp_dependencies_export', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.export_group(db, ADDRESSES, HERE / 'dependencies_raw.json')
    sources = [ROOT / 'docs/逆向资料/专题/图像资源/证据/20261009_图像加载函数群.json',
               ROOT / 'docs/逆向资料/专题/TeachMode对象与消费者/证据/teachmode_raw.json']
    output = dict(scope='既有原证来源；本轮只深化装饰参数和尾部谓词契约',
                  sources=[dict(path=str(path.relative_to(ROOT)),
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                           for path in sources])
    (HERE / 'dependency_sources.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return summary
