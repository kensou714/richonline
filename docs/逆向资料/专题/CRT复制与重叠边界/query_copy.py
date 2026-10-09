"""在现有IDA只读取证；不纠正数据库中的代码/数据标记。"""
import json
import runpy
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
TABLES = [(0x921404, 3, '正向对齐'), (0x921480, 8, '正向展开'),
          (0x9214EC, 4, '正向尾字节'), (0x921590, 3, '反向对齐'),
          (0x92161C, 8, '反向展开'), (0x921688, 4, '反向尾字节')]


def run(db):
    export = runpy.run_path(str(ROOT / 'docs/逆向资料/全量分析/export_function_group.py'))['export_group']
    result = export(db, [0x62BA10, 0x62BDE0, 0x62BD10, 0x9213A0, 0x9217B0],
                    HERE / '证据/crt_copy.json')
    rows = []
    for delta in (0, 0x410):
        for va, count, purpose in TABLES:
            raw = db.bytes.get_bytes_at(va + delta, count * 4)
            targets = struct.unpack('<' + 'I' * count, raw)
            rows.append(dict(va=hex(va + delta), purpose=purpose, size=len(raw),
                             idb_hex=raw.hex(), targets=[hex(t) for t in targets]))
    payload = dict(note='从完整块原字节独立解析；表项不是可执行指令。', tables=rows)
    (HERE / '证据/跳表原证.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8', newline='\n')
    return dict(export=result, tables=len(rows))
