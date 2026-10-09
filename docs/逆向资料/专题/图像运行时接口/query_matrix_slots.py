"""矩阵间接入口必须读取真实指针及引用者，不依据伪签名认定D3DX名称。"""
import json
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/图像运行时接口'


def run(db):
    rows = []
    for address in [0xA6AB00, 0xA6AB74]:
        raw = db.bytes.get_bytes_at(address, 4)
        target = int.from_bytes(raw, 'little')
        f = db.functions.get_at(target)
        rows.append(dict(va=hex(address), size=4, idb_hex=raw.hex(), value=hex(target),
                         target_function=hex(f.start_ea) if f else None,
                         references=[dict(site=hex(x.from_ea), kind=int(x.type),
                                          function=hex(db.functions.get_at(x.from_ea).start_ea)
                                          if db.functions.get_at(x.from_ea) else None)
                                     for x in db.xrefs.to_ea(address)]))
    (HERE / '证据/matrix_slots.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    return rows
