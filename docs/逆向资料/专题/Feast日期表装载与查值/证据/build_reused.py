"""复用 4050 日期链原证，保存原来源哈希；不改写既有专题。"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
BASE = Path(__file__).resolve().parent
SOURCE = '专题/4050系列事件/证据/date_and_bridge.json'
ADDRESSES = ('0x6288b0', '0x7080d0', '0x7d8de0', '0x7d8e60', '0x7d90e0')
SUPPORT = {
    SOURCE: ('0x7eff90', '0x63e590', '0x727a70', '0x727a90', '0x63f420'),
    '专题/4050系列事件/证据/handlers.json': ('0x662dc0',),
    '专题/4050系列事件/证据/helpers.json': ('0x694320',),
    '专题/KoNpc记录与消费者/证据/npc_dependencies_raw.json': ('0x63e210',),
    '专题/40EE系列事件/证据/direct_helpers.json': ('0x63eca0', '0x63edf0'),
}


def main():
    reused, thunks, hashes = [], {}, {}
    for source_path, support in SUPPORT.items():
        blob = (ROOT / 'docs/逆向资料' / source_path).read_bytes()
        source = json.loads(blob)
        hashes[source_path] = hashlib.sha256(blob).hexdigest()
        index = {row['va'].lower(): row for row in source['functions']}
        selected = (*ADDRESSES, *support) if source_path == SOURCE else support
        targets = set()
        for va in selected:
            row = index[va]
            if not row.get('byte_ranges'):
                raise ValueError('复用记录缺少原字节范围：' + va)
            reused.append(dict(va=va, source=source_path, record=row,
                               role='主体复用' if va in ADDRESSES else '日期生产、显示与模式支撑复用',
                               coverage_boundary=('原来源保留指令与声明块' if row.get('chunk_byte_ranges')
                                                  else '原来源保留范围；旧版未独立枚举声明尾块')))
            targets.update(item for call in row['calls'] for item in call.get('thunks', []))
        selected_thunks = [row for row in source['thunks'] if row['va'] in targets]
        if targets - {row['va'] for row in selected_thunks}:
            raise ValueError('来源缺少调用链使用桥：' + source_path)
        for row in selected_thunks:
            if row['va'] in thunks and thunks[row['va']] != row:
                raise ValueError('同址复用桥原证不一致：' + row['va'])
            thunks[row['va']] = row
    output = dict(scope='复用日期链原证；不计新增 IDA 函数导出或新的语义审阅；未补造声明尾块',
                  source_hashes=hashes,
                  reused=reused,
                  thunks=list(thunks.values()))
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'reused_evidence.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('reused records:', len(reused))


if __name__ == '__main__':
    main()
