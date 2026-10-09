"""在IDA只读租约重建本专题函数/数据原证，不修改或保存IDB。"""
from pathlib import Path
import hashlib
import json

ROOT=Path('F:/大富翁online/Richonline')
BASE=ROOT/'docs/逆向资料/专题/事件文字记录器/证据'
assert hashlib.sha256((ROOT/'RnClient.exe').read_bytes()).hexdigest()=='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
exec((ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'))
review=json.loads((BASE/'function_review.json').read_text('utf-8'))
for source in review['sources']:
    old=json.loads((BASE/source).read_text('utf-8'))
    print(source,export_group(db,[int(f['va'],16) for f in old['functions']],BASE/source))
path=BASE/'export_data.py'
exec(compile(path.read_text('utf-8'),str(path),'exec'),{'db':db,'__file__':str(path)})
