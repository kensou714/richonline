"""保存四个switch尾随数据窗口；窗口不是新增函数覆盖。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/627830懒单例')


def run(db):
    spans = [dict(va=hex(ea), size=size, idb_hex=db.bytes.get_bytes_at(ea, size).hex())
             for ea, size in [(0x6DD6E2, 46), (0x6DD7DC, 52),
                              (0x6DDB32, 46), (0x6DDD6D, 35)]]
    (HERE / '证据/switch_windows.json').write_text(json.dumps(dict(spans=spans, limitation='尾随原始数据窗口；不计声明函数覆盖。'), ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    return dict(windows=len(spans), bytes=sum(row['size'] for row in spans))
