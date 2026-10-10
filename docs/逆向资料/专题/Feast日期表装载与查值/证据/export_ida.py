"""Feast 显式只读导出入口；由持共享 IDA 租约的主任务调用。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
BASE = Path(__file__).resolve().parent
SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
NEW_SEEDS = (0x7D8BE0, 0x7D89D0)
SEEDS = (*NEW_SEEDS, 0x6288B0, 0x7080D0)
NAV_TARGETS = (*NEW_SEEDS, 0x6288B0, 0x7D8DE0, 0x7D8E60, 0xA766D4)


def disk_view(blob):
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((base + rva, size, offset))

    def read(va, size):
        for start, count, offset in sections:
            relative = va - start
            if 0 <= relative and relative + size <= count:
                return blob[offset + relative:offset + relative + size]
        return None
    return read


def run(db, phase='core'):
    if phase not in ('core', 'navigation', 'supplemental'):
        raise ValueError('未知阶段：' + str(phase))
    blob = (ROOT / 'RnClient.exe').read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError('磁盘 EXE 指纹变化，须重新核定基线')
    if phase in ('core', 'supplemental'):
        helper = ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        namespace = {}
        exec(compile(helper.read_text('utf-8'), str(helper), 'exec'), namespace)
        if phase == 'core':
            return namespace['export_group'](db, SEEDS, BASE / 'core_raw.json')
        supplemental = namespace['export_group'](db, (0x7D8EB0,), BASE / 'supplemental_raw.json')
    else:
        supplemental = None
    read = disk_view(blob)

    def identity(va, size):
        current, disk = db.bytes.get_bytes_at(va, size), read(va, size)
        return dict(va=hex(va), size=size,
                    idb_hex=current.hex() if current is not None else None,
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=current == disk if disk is not None else None,
                    storage='磁盘映射' if disk is not None else '仅 IDB 当前值')

    if phase == 'supplemental':
        contexts = []
        for site, before, after in ((0x7C19E0, 32, 16), (0x624864, 4, 14)):
            owner = db.functions.get_at(site)
            if owner is None:
                raise ValueError('局部调用点没有声明函数：' + hex(site))
            instructions = list(db.instructions.get_between(owner.start_ea, owner.end_ea))
            index = next(i for i, instruction in enumerate(instructions) if instruction.ea == site)
            selected = instructions[max(0, index - before):index + after + 1]
            contexts.append(dict(site=hex(site), owner=hex(owner.start_ea),
                                 scope='仅调用点前后已解码指令；不代表完整函数审阅',
                                 assembly=[dict(va=hex(ins.ea), text=db.instructions.get_disassembly(ins))
                                           for ins in selected],
                                 instructions=[identity(ins.ea, ins.size) for ins in selected]))
        branch = db.bytes.get_bytes_at(0x7D8A5D, 7)
        if branch[:3] != b'\xff\x24\x95':
            raise ValueError('日期分发不是预期间接跳转指令')
        table = int.from_bytes(branch[3:], 'little')
        output = dict(disk_sha256=SHA256, contexts=contexts,
                      switch_table=identity(table, 13 * 4))
        (BASE / 'context_raw.json').write_text(
            json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return dict(core=supplemental, contexts=len(contexts), table=hex(table))

    targets = []
    for seed in NAV_TARGETS:
        pending, visited, references = [seed], set(), []
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            for edge in db.xrefs.to_ea(target):
                site = edge.from_ea
                owner = db.functions.get_at(site)
                instruction = db.instructions.get_at(site)
                raw = db.bytes.get_bytes_at(site, 5)
                bridge = bool(raw and raw[0] == 0xE9 and
                              site + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target)
                references.append(dict(
                    target=hex(target), site=hex(site), kind=int(edge.type),
                    owner=hex(owner.start_ea) if owner else None, bridge=bridge,
                    disassembly=db.instructions.get_disassembly(instruction) if instruction else None,
                    bytes=identity(site, instruction.size) if instruction else None))
                if bridge:
                    pending.append(site)
        targets.append(dict(seed=hex(seed), references=references))
    output = dict(disk_sha256=SHA256,
                  scope='反向调用与全局槽导航；不代表调用者、别名或动态可达性已闭合',
                  targets=targets,
                  windows=[identity(0x623EFF, 28), identity(0xA2233C, 16),
                           identity(0xA766D4, 4)])
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / 'navigation_raw.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(targets=len(targets), references=sum(len(row['references']) for row in targets))
