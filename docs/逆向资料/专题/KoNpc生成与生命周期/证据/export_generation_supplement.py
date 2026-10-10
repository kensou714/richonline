"""只读保存销毁依赖和未声明 NPC 调用窗口；不创建 IDA 函数或类型。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/KoNpc生成与生命周期/证据'


def export(db):
    helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    namespace = {}
    exec(compile(helper.read_text('utf-8'), str(helper), 'exec'), namespace)
    requested = {0x808FD0, 0x8093C0, 0x809D40, 0x805430, 0x624080}
    ledger = json.loads((ROOT / 'docs/逆向资料/全量分析/evidence_coverage.json').read_text('utf-8'))
    existing = {int(row['va'], 16): row for row in ledger['functions']}
    result = namespace['export_group'](db, requested - existing.keys(), str(BASE / 'lifecycle_dependencies_raw.json'))
    (BASE / 'dependency_reuse.json').write_text(json.dumps(
        [existing[ea] for ea in sorted(requested & existing.keys())], ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    section_count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    start, end = 0x807559, 0x807750
    disk = None
    for index in range(section_count):
        header = pe + 24 + optional_size + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, header + 12)
        relative = start - image_base - rva
        if 0 <= relative and relative + end - start <= size:
            disk = blob[offset + relative:offset + relative + end - start]
            break
    raw = db.bytes.get_bytes_at(start, end - start)
    assembly, calls = [], []
    for instruction in db.instructions.get_between(start, end):
        owner = db.functions.get_at(instruction.ea)
        assembly.append(dict(va=hex(instruction.ea), size=instruction.size,
                             text=db.instructions.get_disassembly(instruction),
                             owner=hex(owner.start_ea) if owner else None))
        for edge in db.xrefs.from_ea(instruction.ea):
            if edge.type in (16, 17, 19):
                calls.append(dict(site=hex(instruction.ea), target=hex(edge.to_ea), kind=int(edge.type)))
    window = dict(scope='未声明代码导航窗口，不认作函数入口或完整函数审阅',
                  start_va=hex(start), end_va=hex(end), idb_hex=raw.hex(),
                  disk_hex=disk.hex() if disk is not None else None, matching=raw == disk,
                  disk_sha256=hashlib.sha256(blob).hexdigest(), assembly=assembly, calls=calls,
                  incoming=[dict(site=hex(edge.from_ea), target=hex(edge.to_ea), kind=int(edge.type))
                            for ea in (0x807560, 0x807589) for edge in db.xrefs.to_ea(ea)])
    (BASE / 'unowned_npc_window.json').write_text(json.dumps(window, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(result=result, reused=len(requested & existing.keys()),
                window_matching=window['matching'], window_instructions=len(assembly))
