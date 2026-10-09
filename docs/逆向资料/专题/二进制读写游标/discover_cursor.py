"""只读查找游标邻近函数和入口跳板调用者；不把邻近关系当作同类证明。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/二进制读写游标')


def run(db):
    neighborhoods = []
    for start, end in [(0x867000, 0x868C00), (0x87AF00, 0x87B900), (0x87CC00, 0x87D500)]:
        for f in db.functions.get_between(start, end):
            neighborhoods.append(dict(va=hex(f.start_ea), end_va=hex(f.end_ea),
                                      name=db.functions.get_name(f)))
    inbound = []
    for entry in [0x867470, 0x868530, 0x87B140, 0x87D060, 0x87D0D0]:
        pending = [entry]
        seen = set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            for x in db.xrefs.to_ea(target):
                f = db.functions.get_at(x.from_ea)
                item = dict(entry=hex(entry), target=hex(target), site=hex(x.from_ea),
                            kind=int(x.type), function=hex(f.start_ea) if f else None)
                raw = db.bytes.get_bytes_at(x.from_ea, 5)
                if x.type == 19 and raw and raw[0] == 0xE9:
                    pending.append(x.from_ea)
                    item['kind_note'] = '跳板引用，继续追踪'
                elif f:
                    item['window'] = [dict(va=hex(i.ea), text=db.instructions.get_disassembly(i))
                                      for i in db.instructions.get_between(max(f.start_ea, x.from_ea - 32),
                                                                          min(f.end_ea, x.from_ea + 24))]
                inbound.append(item)
    result = dict(neighborhoods=neighborhoods, inbound=inbound)
    (HERE / '证据/cursor_discovery.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(neighborhoods=len(neighborhoods), inbound=len(inbound),
                caller_functions=len({x['function'] for x in inbound if x['function']}))
