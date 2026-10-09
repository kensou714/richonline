"""文件访问专题第一阶段只读查询；由现有IDA-MCP db执行，不修改数据库。"""
import json
import re
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/文件访问与路径契约'


def run(db):
    (HERE / '证据').mkdir(parents=True, exist_ok=True)
    candidates = []
    symbols = re.compile(r'(CreateDirectory|RemoveDirectory|GetCurrentDirectory|SetCurrentDirectory|GetFullPathName|GetModuleFileName|GetTempPath|FindFirstFile|FindNextFile|GetFileAttributes|DeleteFile|MoveFile|CopyFile|(^|_)mkdir$|(^|_)fopen$|(^|_)fclose$|(^|_)fread$|(^|_)fwrite$)', re.I)
    for address, name in db.names.get_all():
        if not symbols.search(name) or name.startswith('j_'):
            continue
        pending = [address]
        seen = set()
        refs = []
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in db.xrefs.to_ea(target):
                f = db.functions.get_at(x.from_ea)
                row = dict(site=hex(x.from_ea), target=hex(target), kind=int(x.type),
                           function=hex(f.start_ea) if f else None)
                raw = db.bytes.get_bytes_at(x.from_ea, 5)
                if x.type == 19 and raw and raw[0] == 0xE9:
                    pending.append(x.from_ea)
                    row['thunk'] = True
                refs.append(row)
        candidates.append(dict(va=hex(address), name=name, references=refs))
    (HERE / '证据/api_references.json').write_text(json.dumps(candidates, ensure_ascii=False, indent=2), encoding='utf-8')
    exporter = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    result = exporter(db, [0x81B980, 0x827B30, 0xA0E76A, 0x923D90, 0x924000, 0x9243C0, 0x924480], str(HERE / '证据/file_seeds.json'))
    # 保留81B8B0的IDA声明状态，旧窗口仍引用原专题，不擅自create_func。
    f = db.functions.get_at(0x81B8B0)
    result['81b8b0_declared_parent'] = hex(f.start_ea) if f else None
    result['api_symbols'] = len(candidates)
    (HERE / '证据/query_status.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result
