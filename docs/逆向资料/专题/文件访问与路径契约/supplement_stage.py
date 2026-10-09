"""补齐摘要、锁和未声明写文件区间；只读 IDA，不创建函数。"""
import hashlib
import json
import runpy
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/文件访问与路径契约'


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    report = export(db, [0x8283C0, 0x828DD0, 0x828E90, 0x6BFA00, 0x6BFA40],
                    str(HERE / '证据/digest_dependencies.json'))
    source = json.loads((ROOT / 'docs/逆向资料/专题/录像文件与执行链/证据/undeclared_io_windows.json').read_text(encoding='utf-8'))
    old = next(row for row in source if row['start_va'] == '0x81b8b0')
    raw = db.bytes.get_bytes_at(0x81B8B0, 0x81B980 - 0x81B8B0)
    assert raw.hex() == old['idb_hex']
    rows = []
    for address in (0x81B8B0, 0x81B980, 0x827B30, 0x81C350):
        refs = []
        pending = [address]
        seen = set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in db.xrefs.to_ea(target):
                f = db.functions.get_at(x.from_ea)
                r = dict(site=hex(x.from_ea), target=hex(target), kind=int(x.type),
                         function=hex(f.start_ea) if f else None)
                b = db.bytes.get_bytes_at(x.from_ea, 5)
                if x.type == 19 and b and b[0] == 0xE9:
                    r['thunk'] = True
                    pending.append(x.from_ea)
                refs.append(r)
        rows.append(dict(va=hex(address), references=refs))
    result = dict(disk_sha256=hashlib.sha256((ROOT / 'RnClient.exe').read_bytes()).hexdigest(),
                  references=rows, code_range=dict(start_va='0x81b8b0', end_va='0x81b973',
                  scope='人工判读指令区间，IDA未声明函数；不含紧随的pFout字符串及对齐字节',
                  idb_hex=raw[:0xC3].hex(), assembly=[i for i in old['assembly'] if int(i['va'], 16) < 0x81B973]),
                  adjacent_data=dict(start_va='0x81b973', end_va='0x81b980', idb_hex=raw[0xC3:].hex()))
    (HERE / '证据/undeclared_write.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
