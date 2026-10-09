"""在IDA-MCP中只读导出指定函数；保留指令/尾块字节、磁盘对应与直接跳板。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')

def export_group(db, addresses, output_path):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for i in range(count):
        at = pe + 24 + optional_size + 40 * i
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((rva, raw_size, raw_offset))
    def disk_bytes(ea, size):
        for rva, raw_size, offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= raw_size:
                return blob[offset + relative:offset + relative + size]
        return None
    def identity(ea, size):
        original = db.bytes.get_bytes_at(ea, size)
        disk = disk_bytes(ea, size)
        return dict(va=hex(ea), size=size, idb_hex=original.hex(),
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=original == disk)
    functions = []
    thunks = {}
    for ea in sorted(set(addresses)):
        f = db.functions.get_at(ea)
        if f is None or f.start_ea != ea:
            raise ValueError('函数入口未声明或不匹配：' + hex(ea))
        # 此版本get_instructions只返回主范围，必须显式枚举异常处理等尾块。
        chunks = list(db.functions.get_chunks(f))
        by_address = {}
        for chunk in chunks:
            for instruction in db.instructions.get_between(chunk.start_ea, chunk.end_ea):
                by_address[instruction.ea] = instruction
        insns = [by_address[address] for address in sorted(by_address)]
        record = dict(va=hex(ea), end_va=hex(f.end_ea),
                      name=db.functions.get_name(f), status='仅导出',
                      pseudocode=[], assembly=[], calls=[], references=[],
                      declared_chunks=[dict(start_va=hex(c.start_ea), end_va=hex(c.end_ea),
                                            is_main=c.is_main) for c in chunks])
        try:
            record['pseudocode'] = db.pseudocode.get_text(ea)
        except Exception as exc:
            record['decompile_error'] = str(exc)
        spans = []
        for ins in sorted(insns, key=lambda i: i.ea):
            record['assembly'].append(dict(va=hex(ins.ea), text=db.instructions.get_disassembly(ins)))
            if spans and spans[-1][1] == ins.ea:
                spans[-1][1] = ins.ea + ins.size
            else:
                spans.append([ins.ea, ins.ea + ins.size])
            for x in db.xrefs.from_ea(ins.ea):
                if x.type not in (16, 17):
                    continue
                target = x.to_ea
                chain = []
                while target not in chain and len(chain) < 16:
                    raw = db.bytes.get_bytes_at(target, 5)
                    if not raw or raw[0] != 0xe9:
                        break
                    chain.append(target)
                    audit = identity(target, 5)
                    next_target = target + 5 + int.from_bytes(raw[1:], 'little', signed=True)
                    audit['target'] = hex(next_target)
                    thunks[hex(target)] = audit
                    target = next_target
                record['calls'].append(dict(site=hex(ins.ea), target=hex(x.to_ea),
                                            implementation=hex(target),
                                            thunks=[hex(t) for t in chain]))
        record['byte_ranges'] = [identity(start, end-start) for start, end in spans]
        # IDA可能把块内填充折叠成一条db dup，insn.size不足以覆盖数据总长。
        # 独立保留声明块原始字节；不把这些字节伪装为已解码指令。
        record['chunk_byte_ranges'] = [identity(c.start_ea, c.end_ea-c.start_ea)
                                       for c in chunks]
        record['bytes_match_disk'] = all(r['matching'] for r in
                                        record['byte_ranges'] + record['chunk_byte_ranges'])
        record['references'] = [dict(source=hex(x.from_ea), kind=int(x.type))
                                for x in db.xrefs.to_ea(ea)]
        functions.append(record)
    result = dict(disk_sha256=hashlib.sha256(blob).hexdigest(),
                  baseline_reference='全量分析/版本核验_第二批.json',
                  scope='当前IDA数据库；逐块保存指令范围与声明块原始字节，两者重叠不相加；块内数据语义及外部依赖另核',
                  functions=functions, thunks=list(thunks.values()))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(functions=len(functions), thunks=len(thunks),
                function_mismatches=[r['va'] for r in functions if not r['bytes_match_disk']],
                thunk_mismatches=[r['va'] for r in thunks.values() if not r['matching']])
