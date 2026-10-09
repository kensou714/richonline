"""保存MD5压缩函数与填充常量；不执行游戏或修改数据库。"""
import hashlib
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/文件访问与路径契约'


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    report = export(db, [0x8284E0], str(HERE / '证据/digest_transform.json'))
    raw = db.bytes.get_bytes_at(0xA67750, 64)
    data = dict(disk_sha256=hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest(),
                spans=[dict(va='0xa67750', size=64, idb_hex=raw.hex(),
                            scope='828E90直接引用的填充区；磁盘对应由离线验证器独立核验')])
    (HERE / '证据/digest_padding.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
