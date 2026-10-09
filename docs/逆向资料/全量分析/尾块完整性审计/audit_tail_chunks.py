"""只读审计旧函数原证的范围；输出仅写本目录，补证不提升语义等级。"""
import collections
import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
DOCS = ROOT / 'docs/逆向资料'
OUT = DOCS / '全量分析/尾块完整性审计'


def write(name, value):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def address(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise ValueError('没有可解析地址')


def key_address(item):
    for key in ('va', 'ea', 'address', 'start', 'start_va'):
        if key in item:
            return address(item[key])
    raise ValueError('缺少地址')


def span(item):
    start = key_address(item)
    for key in ('size', 'byte_count'):
        if isinstance(item.get(key), int):
            return start, start + item[key]
    for key in ('end_va', 'end'):
        if key in item:
            return start, address(item[key])
    for key in ('idb_hex', 'ida_bytes_hex', 'bytes_hex', 'bytes'):
        if isinstance(item.get(key), str):
            return start, start + len(bytes.fromhex(item[key]))
    raise ValueError('缺少范围')


def normalized(item):
    va = key_address(item)
    rows = []
    byte_kind = []
    for key in ('byte_ranges', 'chunks', 'ranges'):
        value = item.get(key)
        if not isinstance(value, list):
            continue
        for block in value:
            if not isinstance(block, dict):
                continue
            # 纯声明的chunks不算保存了字节或逐块字节指纹。
            if not any(k in block for k in ('idb_hex', 'bytes_hex', 'bytes', 'idb_sha256', 'ida_sha256', 'disk_sha256')):
                continue
            try:
                rows.append(span(block))
                byte_kind.append('原字节' if any(k in block for k in ('idb_hex', 'bytes_hex', 'bytes')) else '范围指纹')
            except (ValueError, TypeError):
                pass
    if isinstance(item.get('ida_bytes_hex'), str):
        rows.append((va, va + len(bytes.fromhex(item['ida_bytes_hex']))))
        byte_kind.append('原字节')
    if not rows and 'idb_sha256' in item and any(k in item for k in ('size', 'byte_count', 'end', 'end_va')):
        rows.append(span(item))
        byte_kind.append('范围指纹')
    addresses = set()
    has_assembly = False
    addressless = 0
    for key in ('assembly', 'instructions', 'disassembly'):
        value = item.get(key)
        if not isinstance(value, list):
            continue
        has_assembly = True
        for ins in value:
            try:
                ea = key_address(ins) if isinstance(ins, dict) else address(ins[0]) if isinstance(ins, list) and ins else None
                if ea is None:
                    addressless += 1
                else:
                    addresses.add(ea)
                    if isinstance(ins, dict) and isinstance(ins.get('bytes'), str):
                        rows.append((ea, ea + len(bytes.fromhex(ins['bytes']))))
                        byte_kind.append('逐指令原字节')
            except (ValueError, TypeError):
                addressless += 1
    if not rows and not has_assembly and 'pseudocode' not in item:
        return None
    return dict(va=hex(va), byte_ranges=[[hex(a), hex(b)] for a, b in sorted(set(rows))],
                byte_evidence_kind=sorted(set(byte_kind)), has_assembly=has_assembly,
                assembly_addresses=[hex(a) for a in sorted(addresses)], addressless_lines=addressless,
                standard_schema=isinstance(item.get('byte_ranges'), list) and isinstance(item.get('assembly'), list) and 'va' in item)


def scan_sources(output_name='source_snapshot.json'):
    records, files, failures = [], {}, []

    def walk(obj, source, pointer):
        if isinstance(obj, dict):
            try:
                row = normalized(obj)
            except (ValueError, TypeError):
                row = None
            if row is not None:
                row.update(source=source, json_pointer=pointer)
                records.append(row)
                return
            for key, value in obj.items():
                if key not in ('assembly', 'instructions', 'disassembly', 'pseudocode'):
                    walk(value, source, pointer + '/' + key.replace('~', '~0').replace('/', '~1'))
        elif isinstance(obj, list):
            for index, value in enumerate(obj):
                walk(value, source, pointer + '/' + str(index))

    # 聚合覆盖率/审阅迁移不是原证，避免把其内拷贝当成新增独立原证。
    for path in sorted(DOCS.rglob('*.json')):
        if '全量分析' in path.relative_to(DOCS).parts:
            continue
        raw = path.read_bytes()
        source = path.relative_to(DOCS).as_posix()
        before = len(records)
        try:
            walk(json.loads(raw.decode('utf-8-sig')), source, '')
        except Exception as exc:
            failures.append(dict(source=source, error=str(exc)))
        if len(records) != before:
            files[source] = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                                 inspected_utc=datetime.now(timezone.utc).isoformat(), mtime_ns=path.stat().st_mtime_ns)
    snapshot = dict(created_utc=datetime.now(timezone.utc).isoformat(), scope='专题及原始证据；排除全量分析聚合副本',
                    files=files, records=records, parse_failures=failures,
                    unique_functions=sorted({r['va'] for r in records}, key=lambda x: int(x, 16)))
    write(output_name, snapshot)
    return dict(files=len(files), records=len(records), unique_functions=len(snapshot['unique_functions']), failures=len(failures))


def disk_reader():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 60)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + i * 40 + 8) for i in range(count)]

    def read(ea, size):
        r = ea - base
        for _, rva, raw_size, offset in sections:
            if rva <= r and r + size <= rva + raw_size:
                return blob[offset + r - rva:offset + r - rva + size]
        return None
    return hashlib.sha256(blob).hexdigest(), read


def covered(start, end, spans):
    cursor = start
    for left, right in sorted(spans):
        if right <= cursor:
            continue
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= end:
            return True
    return cursor >= end


def run_batch(db, start, size=100, snapshot_name='source_snapshot.json', batch_folder='batches'):
    snapshot = json.loads((OUT / snapshot_name).read_text(encoding='utf-8'))
    funcs = snapshot['unique_functions'][start:start + size]
    rows_by_va = collections.defaultdict(list)
    for row in snapshot['records']:
        rows_by_va[row['va']].append(row)
    disk_hash, read_disk = disk_reader()
    details, gaps, supplements, errors = [], [], [], []
    for va in funcs:
        try:
            ea = int(va, 16)
            func = db.functions.get_at(ea)
            if func is None or func.start_ea != ea:
                errors.append(dict(va=va, reason='当前IDA未声明相同入口', sources=[dict(source=r['source'], json_pointer=r['json_pointer']) for r in rows_by_va[va]]))
                continue
            chunks = list(db.functions.get_chunks(func))
            result = dict(va=va, name=db.functions.get_name(func), chunks=[])
            for chunk in chunks:
                insns = list(db.instructions.get_between(chunk.start_ea, chunk.end_ea))
                c = dict(start_va=hex(chunk.start_ea), end_va=hex(chunk.end_ea), is_main=chunk.is_main,
                         instructions=[dict(va=hex(i.ea), size=i.size) for i in insns])
                result['chunks'].append(c)
                needs_tail = False
                for row in rows_by_va[va]:
                    spans = [(int(a, 16), int(b, 16)) for a, b in row['byte_ranges']]
                    asm = {int(a, 16) for a in row['assembly_addresses']}
                    byte_missing = [hex(i.ea) for i in insns if spans and not covered(i.ea, i.ea + i.size, spans)]
                    asm_missing = [hex(i.ea) for i in insns if asm and i.ea not in asm]
                    raw_covered = covered(chunk.start_ea, chunk.end_ea, spans) if spans else None
                    # 缺少可定位原证仅列未知，不把“未存字节”冒充“遗漏尾块”。
                    if byte_missing or asm_missing or (not chunk.is_main and raw_covered is False):
                        gaps.append(dict(va=va, source=row['source'], json_pointer=row['json_pointer'],
                                         chunk_start=c['start_va'], chunk_end=c['end_va'], is_main=chunk.is_main,
                                         missing_byte_instruction_vas=byte_missing, missing_assembly_vas=asm_missing,
                                         declared_chunk_raw_bytes_covered=raw_covered,
                                         byte_evidence_kind=row['byte_evidence_kind'],
                                         assembly_assessment='可按地址比较' if asm else '无地址或未保存，不能判完整'))
                        needs_tail = needs_tail or not chunk.is_main
                if needs_tail:
                    raw = db.bytes.get_bytes_at(chunk.start_ea, chunk.end_ea - chunk.start_ea)
                    disk = read_disk(chunk.start_ea, chunk.end_ea - chunk.start_ea)
                    supplements.append(dict(function_va=va, status='仅补充导出，未提升语义审阅等级',
                                            va=c['start_va'], end_va=c['end_va'], size=chunk.end_ea - chunk.start_ea,
                                            idb_hex=raw.hex() if raw else None, disk_hex=disk.hex() if disk else None,
                                            matching=raw is not None and raw == disk,
                                            assembly=[dict(va=hex(i.ea), size=i.size, text=db.instructions.get_disassembly(i)) for i in insns]))
            details.append(result)
        except Exception as exc:
            errors.append(dict(va=va, reason=str(exc)))
    write(f'{batch_folder}/batch_{start:05d}.json', dict(start=start, requested=len(funcs), disk_sha256=disk_hash,
          source_snapshot_sha256=hashlib.sha256((OUT / snapshot_name).read_bytes()).hexdigest(),
          functions=details, gaps=gaps, tail_supplements=supplements, errors=errors))
    return dict(start=start, requested=len(funcs), functions=len(details), gap_records=len(gaps),
                tail_supplements=len(supplements), errors=errors)


if __name__ == '__main__':
    print(json.dumps(scan_sources(), ensure_ascii=False))
