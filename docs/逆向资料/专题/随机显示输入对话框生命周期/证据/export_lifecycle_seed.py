"""只读补导最小生命周期依赖；四个旧入口复用并逐主尾块核对当前 PE。"""
from pathlib import Path
import hashlib
import json
import re
import struct

ROOT = Path('F:/大富翁online/Richonline')
BASE = ROOT / 'docs/逆向资料/专题/随机显示输入对话框生命周期/证据'
SOURCE = ROOT / 'docs/逆向资料/专题/随机数状态与取样边界/证据/functions_raw.json'
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
REUSED = (0x911AB0, 0x913E90, 0x914220, 0x9157F0)
DEPENDENCIES = (0x916E80, 0x912ED0, 0x913DE0, 0x917130, 0x919960)
BRIDGES = (0x60CD09, 0x60C17E, 0x60B8D2, 0x6068AF, 0x60E154,
           0x60E0E1, 0x60AE05, 0x605248, 0x60CC37)


def export(db):
    blob = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == EXPECTED_SHA
    source_bytes = SOURCE.read_bytes()
    source = json.loads(source_bytes.decode('utf-8'))
    assert source['disk_sha256'] == EXPECTED_SHA
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, raw_size, raw_offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((image_base + rva, raw_size, raw_offset))

    def disk_bytes(va, size):
        for start, length, offset in sections:
            if start <= va and va + size <= start + length:
                return blob[offset + va - start:offset + va - start + size]
        return None

    def identity(va, size):
        live = db.bytes.get_bytes_at(va, size)
        disk = disk_bytes(va, size)
        return dict(va=hex(va), size=size, idb_hex=live.hex() if live is not None else None,
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=live == disk if disk is not None else False)

    reused = []
    for function in source['functions']:
        if int(function['va'], 16) not in REUSED:
            continue
        chunks = [identity(int(item['va'], 16), item['size'])
                  for item in function['chunk_byte_ranges']]
        instructions = [identity(int(item['va'], 16), item['size'])
                        for item in function['byte_ranges']]
        assert all(item['matching'] for item in chunks + instructions)
        assert [item['disk_hex'] for item in chunks] == [
            item['disk_hex'] for item in function['chunk_byte_ranges']]
        reused.append(dict(va=function['va'], source=str(SOURCE.relative_to(ROOT)),
                           scope='历史随机局部已审；本专题拟深化输入及生命周期',
                           declared_chunks=function['declared_chunks'],
                           chunk_byte_ranges=chunks, byte_ranges=instructions))
    assert len(reused) == len(REUSED)
    namespace = {}
    shared = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
    exec(compile(shared.read_text('utf-8'), str(shared), 'exec'), namespace)
    BASE.mkdir(parents=True, exist_ok=True)
    summary = namespace['export_group'](db, DEPENDENCIES, str(BASE / 'functions_raw.json'))
    dependency_data = json.loads((BASE / 'functions_raw.json').read_text('utf-8'))
    incoming = []
    for target in REUSED + DEPENDENCIES + BRIDGES:
        references = []
        for xref in db.xrefs.to_ea(target):
            ins = db.instructions.get_at(xref.from_ea)
            owner = db.functions.get_at(xref.from_ea)
            references.append(dict(site=hex(xref.from_ea), kind=int(xref.type),
                                   function=hex(owner.start_ea) if owner else None,
                                   disassembly=db.instructions.get_disassembly(ins) if ins else None,
                                   bytes=identity(xref.from_ea, ins.size) if ins else None))
        incoming.append(dict(target=hex(target), references=references))
    windows = [dict(identity(0xA6917C, 32), scope='两组各四行指针；不推断邻接对象'),
               dict(identity(0xA316D0, 0x58), scope='显示字符串邻接窗口；逐项边界待审')]
    pointers = struct.unpack('<8I', bytes.fromhex(windows[0]['disk_hex']))
    for pointer in dict.fromkeys(pointers):
        data = disk_bytes(pointer, 128)
        if data is None:
            continue
        zero = data.find(b'\0')
        size = zero + 1 if zero >= 0 else 128
        windows.append(dict(identity(pointer, size), scope='表指针引用的有界字节窗口',
                            nul_found=zero >= 0))
    constructor = next(item for item in dependency_data['functions'] if item['va'] == '0x916e80')
    candidates = set()
    for ins in constructor['assembly']:
        if re.match(r'mov\s+.*\[.*\].*offset ', ins['text']):
            match = re.search(r'offset (?:off|unk)_([0-9A-Fa-f]+)', ins['text'])
            if match:
                candidates.add(int(match.group(1), 16))
    for candidate in sorted(candidates):
        windows.append(dict(identity(candidate, 64), scope='构造写入 offset 候选；窗口不等同完整虚表'))
    assert all(item['matching'] for item in windows)
    result = dict(disk_sha256=EXPECTED_SHA,
                  source_path=str(SOURCE.relative_to(ROOT)),
                  source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  scope='直接引用导航及最小依赖；间接站点解析不等同完整 GUI 生命周期',
                  reused_functions=reused, incoming=incoming, windows=windows,
                  export_summary=summary)
    (BASE / 'seed_navigation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                             encoding='utf-8')
    return dict(summary, reused_functions=len(reused), incoming_targets=len(incoming),
                windows=len(windows))
