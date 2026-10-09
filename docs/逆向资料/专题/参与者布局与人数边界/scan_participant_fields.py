"""在 IDA-MCP 内只读扫描候选位移；不是能消除所有指针别名的类型分析器。"""
import hashlib
import json
import re
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')


def scan_participant_fields(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', blob, 0x3c)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for i in range(count):
        at = pe + 24 + optional_size + 40 * i
        _, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((rva, raw_size, raw_offset))

    def disk_bytes(ea, size):
        for rva, raw_size, raw_offset in sections:
            rel = ea - image_base - rva
            if 0 <= rel and rel + size <= raw_size:
                return blob[raw_offset + rel:raw_offset + rel + size]
        return None

    hits = []
    functions = instructions = 0
    # 包括常见等价的G+DFC+4*n，即G+E00+4*(n-1)。
    pattern = re.compile(r'(?<![0-9A-F])0?(?:DFC|E0[048C]|E1[048C]|E20)h\b', re.I)
    for function in db.functions.get_all():
        functions += 1
        for ins in db.functions.get_instructions(function):
            instructions += 1
            text = db.instructions.get_disassembly(ins) or ''
            if not pattern.search(text):
                continue
            memory_destination = '[' in text.split(',', 1)[0]
            mnemonic = text.split()[0].lower()
            raw = db.bytes.get_bytes_at(ins.ea, ins.size)
            disk = disk_bytes(ins.ea, ins.size)
            hits.append(dict(function=hex(function.start_ea), va=hex(ins.ea), text=text,
                             candidate_write=memory_destination and mnemonic in
                             ('mov', 'add', 'sub', 'inc', 'dec', 'xchg', 'and', 'or', 'xor'),
                             idb_hex=raw.hex(), disk_hex=disk.hex() if disk is not None else None,
                             bytes_match_disk=raw == disk))
    report = dict(disk_sha256=hashlib.sha256(blob).hexdigest(),
                  scope='遍历已声明函数指令；位移匹配只是候选，含非G对象命中，不覆盖指针别名、间接写入或未识别代码',
                  functions_scanned=functions, instructions_scanned=instructions, hits=hits)
    path = ROOT / 'docs/逆向资料/专题/参与者布局与人数边界/证据/participant_field_scan.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(functions=functions, instructions=instructions, hits=len(hits),
                candidate_writes=[x for x in hits if x['candidate_write']],
                mismatches=[x['va'] for x in hits if not x['bytes_match_disk']])
