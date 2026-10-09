"""在IDA-MCP内运行：只读重导专题函数，显式枚举所有主块及异常尾块。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT/'docs/逆向资料/专题/40A0系列事件/证据'
source = (ROOT/'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8')
# 本专题适配当前公共导出器，避免改动其他代理共同使用的文件。
needle = '        insns = list(db.functions.get_instructions(f))'
replacement = '''        chunks = list(db.functions.get_chunks(f))
        insns = [ins for chunk in chunks
                 for ins in db.instructions.get_between(chunk.start_ea, chunk.end_ea)]'''
assert source.count(needle) == 1, '公共导出器已变化，请核对适配点'
source = source.replace(needle, replacement)
source = source.replace("        spans = []", "        record['chunks'] = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]\n        spans = []")
exec(compile(source, '40A0专题全chunk导出器', 'exec'))
def run(db):
    results = []
    for name in ['handlers.json','helpers.json','consumers.json','ui_and_slots.json','ui_callbacks.json']:
        path = BASE/name
        previous = json.loads(path.read_text(encoding='utf-8'))
        addresses = [int(f['va'],16) for f in previous['functions']]
        if name == 'ui_callbacks.json' and 0x8E3340 not in addresses:
            addresses.append(0x8E3340)
        result = export_group(db, addresses, path)
        results.append(dict(source=name, **result))
    return results
