"""在已授权的当前IDA只读lease中执行；仅重建本目录函数原证，不修改IDB。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/406D系列事件/证据'
# db由IDA-MCP环境注入。公共导出器只读数据库与当前PE，并在文档目录保存证据。
exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'))
review = json.loads((BASE / 'function_review.json').read_text(encoding='utf-8'))
for source in review['sources']:
    existing = json.loads((BASE / source).read_text(encoding='utf-8'))
    addresses = [int(f['va'],16) for f in existing['functions']]
    print(source, export_group(db, addresses, BASE / source))
# 注册来源为基础对象与分派专题；仅函数刷新不会覆盖原有绑定和数据取证。
# 如更换客户端版本，必须重新核24项注册、4条虚表跳板和资源指纹后再生成清单。
