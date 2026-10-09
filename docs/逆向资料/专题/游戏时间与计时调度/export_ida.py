"""只读导出游戏时钟、主循环节拍和连接计时候选；保留完整声明块。"""
import json
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/游戏时间与计时调度')
ROOT = HERE.parents[3]
SEEDS = {0x81ED10, 0x81EE60, 0x81F1A0, 0x81F360, 0x81BC30,
         0x6AA530, 0x625070, 0x740000, 0x641EE0, 0x623EE0,
         0x6BC3A0, 0x6BC3D0, 0x6BC560, 0x71FC00, 0x625D70, 0x6AB5F0}


def collect(db, extra=()):
    path = HERE / '证据/functions.json'
    addresses = set(SEEDS)
    if path.exists():
        addresses.update(int(row['va'], 16) for row in json.loads(path.read_text(encoding='utf-8'))['functions'])
    addresses.update(extra)
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), namespace)
    result = namespace['export_group'](db, addresses, str(path))
    data = json.loads(path.read_text(encoding='utf-8'))
    for function in data['functions']:
        for row in function['assembly']:
            row['size'] = db.instructions.get_at(int(row['va'], 16)).size
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


def recheck(db):
    data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    rows, mismatches = [], []
    for saved in data['functions']:
        function = db.functions.get_at(int(saved['va'], 16))
        chunks = list(db.functions.get_chunks(function))
        declared = [dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea), is_main=c.is_main) for c in chunks]
        actual = {hex(i.ea): i.size for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)}
        expected = {i['va']: i['size'] for i in saved['assembly']}
        if declared != saved['declared_chunks'] or actual != expected:
            mismatches.append(saved['va'])
        if any(db.bytes.get_bytes_at(int(r['va'], 16), r['size']).hex() != r['idb_hex']
               for r in saved['byte_ranges'] + saved['chunk_byte_ranges']):
            mismatches.append(saved['va'])
        rows.append(dict(va=saved['va'], declared_chunks=declared,
                         instruction_count=len(actual), instruction_bytes=sum(actual.values())))
    result = dict(disk_sha256=data['disk_sha256'], functions=rows, mismatches=sorted(set(mismatches)))
    (HERE / '证据/ida_recheck.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if mismatches:
        raise ValueError(mismatches)
    return dict(functions=len(rows), mismatches=[])


def supplement(db):
    """补齐定时任务的登记、状态助手和调度调用者；原始引用保留对象归属边界。"""
    extra = {0x6BE030, 0x6BE050, 0x81EFB0, 0x81EDD0, 0x81EF20}
    queue, seen, edges = [0x6BC3A0, 0x6BE030, 0x6BE050], set(), []
    while queue:
        target = queue.pop()
        if target in seen:
            continue
        seen.add(target)
        for ref in db.xrefs.to_ea(target):
            raw = db.bytes.get_bytes_at(ref.from_ea, 5)
            bridge = bool(raw and raw[0] == 0xE9 and
                          ref.from_ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
            function = db.functions.get_at(ref.from_ea)
            edges.append(dict(source=hex(ref.from_ea), target=hex(target), kind=int(ref.type),
                              function=hex(function.start_ea) if function else None,
                              e9_bridge=bridge, idb_hex=raw.hex() if bridge else None))
            if bridge:
                queue.append(ref.from_ea)
            elif function:
                extra.add(function.start_ea)
    result = collect(db, extra)
    (HERE / '证据/引用闭合.json').write_text(json.dumps(edges, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(export=result, edges=len(edges))


def close_effect_family(db):
    """补齐六类画面效果的登记回调、槽初始化及资源释放；不据时间API命名网络任务。"""
    return collect(db, {0x6BC190, 0x6BC1B0, 0x6BDF90, 0x6BE070,
                        0x6BC700, 0x6BC7A0, 0x6BC8E0,
                        0x6BC990, 0x6BCA30, 0x6BCBA0,
                        0x6BCC50, 0x6BCCF0, 0x6BCEC0,
                        0x6BCF70, 0x6BD010, 0x6BD180,
                        0x6BD230, 0x6BD2D0, 0x6BD4A0,
                        0x6BD550, 0x6BD5F0, 0x6BD880})


def capture_contract(db):
    """保存作为参数传入的回调跳板与效果常量；这些不是直接call，需单独取证。"""
    result = collect(db, {0x6BC110, 0x6BC140})
    callbacks = [0x605E6E, 0x6076BF, 0x605EBE, 0x6104A9, 0x605423,
                 0x60D8A3, 0x60BB4D, 0x60C1B5, 0x60F266, 0x601D7D, 0x60CB01,
                 0x610CEC, 0x6098A7, 0x601D78, 0x602DE0, 0x6003C9, 0x5FF91F,
                 0x61231C, 0x605F3B, 0x601332]
    namespace = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text(encoding='utf-8'), namespace)
    # 借已验证导出器的身份映射处理直接回调桥；独立数据保留当前字节供PE复核。
    rows = []
    for address in callbacks:
        raw = db.bytes.get_bytes_at(address, 5)
        if not raw or raw[0] != 0xE9:
            raise ValueError(hex(address))
        rows.append(dict(va=hex(address), size=5, idb_hex=raw.hex(),
                         target=hex(address + 5 + int.from_bytes(raw[1:], 'little', signed=True))))
    constants = [dict(va=hex(address), size=4, idb_hex=db.bytes.get_bytes_at(address, 4).hex())
                 for address in (0xA673B8, 0xA673BC, 0xA673C0)]
    (HERE / '证据/回调与常量.json').write_text(json.dumps(dict(callbacks=rows, constants=constants), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(export=result, callbacks=len(rows), constants=len(constants))
