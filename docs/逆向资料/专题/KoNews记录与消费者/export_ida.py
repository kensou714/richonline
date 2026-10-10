"""只读导出 KoNews 容器、转换、消费者及引用；由主任务持有 IDA lease 执行。"""
from pathlib import Path
import json

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNews记录与消费者/证据'
SEEDS = (0x64F2A0, 0x808E40, 0x808D40, 0x808C70, 0x6DAA10,
         0x64F000, 0x8190B0, 0x62B830, 0x627760)


def export(db):
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), namespace)
    result = namespace['export_group'](db, SEEDS, str(BASE / 'closure_raw.json'))
    incoming = []
    for target in (0x8069A0, 0x600EDC, 0x808E40, 0x60ED89,
                   0x808D40, 0x60654E, 0x808C70, 0x605531):
        rows = []
        for edge in db.xrefs.to_ea(target):
            owner = db.functions.get_at(edge.from_ea)
            window = []
            if owner:
                instructions = list(db.instructions.get_between(owner.start_ea, owner.end_ea))
                index = next((i for i, item in enumerate(instructions) if item.ea == edge.from_ea), None)
                if index is not None:
                    window = [dict(va=hex(item.ea), text=db.instructions.get_disassembly(item))
                              for item in instructions[max(0, index - 12):index + 18]]
            rows.append(dict(source=hex(edge.from_ea), kind=int(edge.type),
                             owner=hex(owner.start_ea) if owner else None, window=window))
        incoming.append(dict(target=hex(target), edges=rows))
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'incoming.json').write_text(json.dumps(incoming, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    # 从既有 806670 指令保存 sscanf 格式地址及字节；不用反编译类型判断格式。
    raw = json.loads((ROOT / 'docs/逆向资料/专题/地图建筑等级配置/证据/functions_raw.json').read_text('utf-8'))
    loader = next(item for item in raw['functions'] if item['va'] == '0x806670')
    formats = []
    for item in loader['assembly']:
        if item['va'] != '0x806811':
            continue
        ea = int(item['va'], 16)
        for edge in db.xrefs.from_ea(ea):
            if edge.to_ea != 0xA2E5CC:
                continue
            blob = bytearray()
            for offset in range(256):
                value = db.bytes.get_bytes_at(edge.to_ea + offset, 1)
                if not value:
                    break
                blob.extend(value)
                if value == b'\0':
                    break
            formats.append(dict(site=item['va'], va=hex(edge.to_ea), raw_hex=blob.hex(),
                                ascii=bytes(blob).decode('ascii', errors='replace')))
    (BASE / 'formats.json').write_text(json.dumps(formats, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    return dict(exported=result, incoming_targets=len(incoming), formats=len(formats))
