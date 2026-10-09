"""在当前IDA-MCP lease内只读重导完整函数chunks；不写IDB。"""
from pathlib import Path
import json

ROOT=Path('F:/大富翁online/Richonline')
BASE=ROOT/'docs/逆向资料/专题/控件回调与事件表/证据'
source=(ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8')
needle='        insns = list(db.functions.get_instructions(f))'
assert source.count(needle)==1, '公共导出器变化，请人工核对完整chunks适配点'
source=source.replace(needle, '''        chunks = list(db.functions.get_chunks(f))
        insns = [ins for chunk in chunks
                 for ins in db.instructions.get_between(chunk.start_ea, chunk.end_ea)]''')
source=source.replace('        spans = []', "        record['chunks'] = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]\n        spans = []")
exec(compile(source,'控件回调完整chunks导出器','exec'))
def run(db):
    results=[]
    for name in ['注册与生命周期.json','基础消费者.json','输入复用.json','清理与复制依赖.json','游戏界面桥接.json']:
        path=BASE/name
        raw=json.loads(path.read_text(encoding='utf-8'))
        results.append(dict(source=name,**export_group(db,[int(f['va'],16) for f in raw['functions']],path)))
    return results
