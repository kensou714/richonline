"""沿E9找到图像运行时接口的真实引用者，只读当前数据库。"""
import json
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/图像运行时接口'


def run(db):
    rows = []
    for ea in [0x6DC090, 0x6DC650, 0x6DC730, 0x6DC7D0, 0x6DC850, 0x6DC8F0,
               0x6DCBA0, 0x6DCC00, 0x6DCC40, 0x6DCD60, 0x6DCDD0]:
        pending, seen, refs = [ea], set(), []
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
                    row['thunk'] = True
                    pending.append(x.from_ea)
                refs.append(row)
        rows.append(dict(va=hex(ea), references=refs))
    (HERE / '证据/consumer_references.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(targets=len(rows), references=sum(len(r['references']) for r in rows))
