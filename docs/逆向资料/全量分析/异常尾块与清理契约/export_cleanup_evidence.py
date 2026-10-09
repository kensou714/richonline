"""只读导出中央尾块关联的异常表、主函数指令与清理目标，不修改 IDB。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
OUT = ROOT / 'docs/逆向资料/全量分析/异常尾块与清理契约'

def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for i in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + opt + 40 * i
        vs, rva, size, off = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((base + rva, size, off))
    def identity(va, size):
        raw = db.bytes.get_bytes_at(va, size)
        disk = None
        for start, count, off in sections:
            if start <= va and va + size <= start + count:
                disk = blob[off + va-start:off + va-start + size]
                break
        return dict(va=hex(va), size=size, idb_hex=raw.hex(),
                    disk_hex=disk.hex() if disk is not None else None, matching=raw == disk)
    def instructions(start, end):
        return [dict(va=hex(i.ea), size=i.size, text=db.instructions.get_disassembly(i))
                for i in db.instructions.get_between(start, end)]
    source = ROOT / 'docs/逆向资料/全量分析/尾块完整性审计'
    central = json.loads((source / 'current_tail_supplements.json').read_text(encoding='utf-8'))
    gaps = json.loads((source / 'current_gaps.json').read_text(encoding='utf-8'))['gaps']
    wanted = {int(c['va'],16) for c in central['chunks']}
    parents = {va: [] for va in wanted}
    for function in db.functions.get_all():
        for chunk in db.functions.get_chunks(function):
            if not chunk.is_main and chunk.start_ea in wanted:
                parents[chunk.start_ea].append(hex(function.start_ea))
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(),
                  central_source_sha256=hashlib.sha256((source / 'current_tail_supplements.json').read_bytes()).hexdigest(),
                  scope='只读原证；展开表状态与对象类型需逐项审阅', records=[])
    targets = {}
    for tail in central['chunks']:
        va = int(tail['function_va'], 16)
        fun = db.functions.get_at(va)
        main = next(c for c in db.functions.get_chunks(fun) if c.is_main)
        rec = dict(function_va=hex(va), tail=tail,
                   chunk_parents=parents[int(tail['va'],16)],
                   sources=[g for g in gaps if int(g['va'], 16) == va],
                   main_bytes=identity(main.start_ea, main.end_ea-main.start_ea),
                   main_assembly=instructions(main.start_ea, main.end_ea), func_info=None,
                   state_writes=[])
        rec['state_writes'] = [i for i in rec['main_assembly']
                               if ('var_4]' in i['text'] or '[ebp-4]' in i['text']) and
                               i['text'].lstrip().startswith(('mov ', 'and ', 'or ', 'inc ', 'dec '))]
        raw = bytes.fromhex(tail['idb_hex'])
        if len(raw) >= 10 and raw[-10] == 0xb8 and raw[-5] == 0xe9:
            fi = struct.unpack_from('<I', raw, len(raw)-9)[0]
            ident = identity(fi, 36)
            vals = struct.unpack('<Ii7I', bytes.fromhex(ident['idb_hex']))
            if vals[0] not in (0x19930520, 0x19930521, 0x19930522) or not 0 <= vals[1] <= 1024:
                raise ValueError(('非预期 FuncInfo', hex(va), vals))
            rec['func_info'] = dict(bytes=ident, magic=hex(vals[0]), max_state=vals[1],
                                    unwind_map_va=hex(vals[2]), try_block_count=vals[3],
                                    try_block_map_va=hex(vals[4]), remaining_words=[hex(v) for v in vals[5:]],
                                    unwind_entries=[])
            if vals[1]:
                table = identity(vals[2], vals[1] * 8)
                rec['func_info']['unwind_bytes'] = table
                for state in range(vals[1]):
                    to_state, action = struct.unpack_from('<iI', bytes.fromhex(table['idb_hex']), state * 8)
                    rec['func_info']['unwind_entries'].append(dict(state=state, to_state=to_state, action=hex(action)))
        for ins in tail['assembly']:
            for x in db.xrefs.from_ea(int(ins['va'], 16)):
                if x.type not in (16, 17, 18, 19):
                    continue
                target = x.to_ea
                chain = []
                for _ in range(16):
                    b = db.bytes.get_bytes_at(target, 5)
                    if not b or b[0] != 0xe9:
                        break
                    audit = identity(target, 5)
                    nxt = target + 5 + int.from_bytes(b[1:], 'little', signed=True)
                    audit['target'] = hex(nxt)
                    chain.append(audit)
                    target = nxt
                if target not in targets:
                    f = db.functions.get_at(target)
                    targets[target] = dict(va=hex(target), name=db.functions.get_name(f) if f else None,
                                            thunk_chain=chain, prefix_bytes=identity(target, 96),
                                            prefix_assembly=instructions(target, target+96))
                ins.setdefault('direct_targets', []).append(dict(target=hex(x.to_ea), implementation=hex(target)))
        result['records'].append(rec)
    result['cleanup_targets'] = list(targets.values())
    # 旧式SEH scope项独立保存，不能混入C++ FuncInfo的结构解释。
    scope = identity(0xa31a90, 12)
    enclosing, filter_va, handler_va = struct.unpack('<iII', bytes.fromhex(scope['idb_hex']))
    result['seh_scope'] = dict(function_va='0x91fbb0', bytes=scope, enclosing_level=enclosing,
                               filter_va=hex(filter_va), handler_va=hex(handler_va))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'cleanup_evidence.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(records=len(result['records']), targets=len(targets),
                func_info=sum(r['func_info'] is not None for r in result['records']))
