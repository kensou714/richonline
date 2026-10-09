"""在IDA-MCP当前Richonline数据库中执行；只读重导全部函数chunks。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/40D0系列事件/证据'
source = (ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8')
needle = '        insns = list(db.functions.get_instructions(f))'
replacement = '''        chunks = list(db.functions.get_chunks(f))
        insns = [ins for chunk in chunks
                 for ins in db.instructions.get_between(chunk.start_ea, chunk.end_ea)]'''
assert source.count(needle) == 1, '公共导出器改变，需核对完整chunks适配点'
source = source.replace(needle, replacement)
source = source.replace("        spans = []", "        record['chunks'] = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]\n        spans = []")
exec(compile(source, '40D0完整chunks导出器', 'exec'))
def run(db):
    result = []
    for path in sorted(BASE.glob('*.json')):
        if path.name in {'resources.json', 'binding_and_data.json'}:
            continue
        previous = json.loads(path.read_text(encoding='utf-8'))
        if 'functions' not in previous:
            continue
        addresses = [int(f['va'], 16) for f in previous['functions']]
        result.append(dict(source=path.name, **export_group(db, addresses, path)))
    return result
