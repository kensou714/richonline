"""有限补证：仅由主代理串行执行，不在导入时连接IDA。"""
from pathlib import Path
import hashlib

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/NewProps与CombCard配置/证据'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def export(db):
    assert hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest() == EXPECTED_SHA
    callback = db.bytes.get_bytes_at(0x609695, 5)
    assert callback and callback[0] == 0xE9
    target = 0x60969A + int.from_bytes(callback[1:], 'little', signed=True)
    assert target == 0x7FEA30
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    return namespace['export_group'](db, (0x609695, target, 0x7FEBF0), str(HERE / 'supplement_raw.json'))
