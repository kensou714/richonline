"""StockName / StockRace 的显式只读导出入口；载入时不访问 IDA 或写文件。"""
import hashlib
import json
import struct
from pathlib import Path

ST_ROOT = Path('F:/大富翁online/Richonline')
ST_BASE = ST_ROOT / 'docs/逆向资料/专题/StockName与StockRace/证据'
ST_SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
ST_PHASES = {
    'core': (0x6284B0, 0x6285F0, 0x628630, 0x6C5550, 0x6C5580, 0x6C5CC0),
    'dependencies': (0x6C55F0, 0x6C56E0, 0x6C5730, 0x6C5750, 0x6C5910,
                     0x6C5930, 0x6C5BA0, 0x6C66F0, 0x6C6740, 0x6C6770,
                     0x6C6C00, 0x6C6C60, 0x6C6C90, 0x6C7420, 0x6C7A10,
                     0x6C8200),
}
ST_NAV_TARGETS = (0x6283E0, 0x6C0E50, 0x6C1260, 0x6C14E0, 0x6C1A60,
                  0xA76744, 0xACB970)


def disk_view(blob):
    """按 PE 原始区映射字节；无磁盘映射的全局槽不补造零字节。"""
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    image_base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional_size + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((image_base + rva, size, offset))

    def read(va, size):
        for start, count, offset in sections:
            relative = va - start
            if 0 <= relative and relative + size <= count:
                return blob[offset + relative:offset + relative + size]
        return None
    return read


def run(db, phase='core'):
    """仅由持当前共享租约的执行者显式调用；一次执行一个阶段。"""
    if phase not in (*ST_PHASES, 'navigation'):
        raise ValueError('未知阶段：' + str(phase))
    blob = (ST_ROOT / 'RnClient.exe').read_bytes()
    if hashlib.sha256(blob).hexdigest() != ST_SHA256:
        raise ValueError('磁盘 EXE 指纹已变化，需先重定证据基线')
    if phase in ST_PHASES:
        namespace = {}
        source = ST_ROOT / 'docs/逆向资料/全量分析/export_function_group.py'
        exec(compile(source.read_text('utf-8'), str(source), 'exec'), namespace)
        return namespace['export_group'](db, ST_PHASES[phase],
                                         ST_BASE / (phase + '_raw.json'))

    read = disk_view(blob)

    def identity(va, size):
        live = db.bytes.get_bytes_at(va, size)
        disk = read(va, size)
        return dict(va=hex(va), size=size,
                    idb_hex=live.hex() if live is not None else None,
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=live == disk if disk is not None else None,
                    storage='磁盘映射' if disk is not None else '仅 IDB 当前值')

    targets = []
    for target in ST_NAV_TARGETS:
        references = []
        for ref in db.xrefs.to_ea(target):
            instruction = db.instructions.get_at(ref.from_ea)
            function = db.functions.get_at(ref.from_ea)
            references.append(dict(
                site=hex(ref.from_ea), kind=int(ref.type),
                function=hex(function.start_ea) if function else None,
                disassembly=db.instructions.get_disassembly(instruction)
                if instruction else None,
                bytes=identity(ref.from_ea, instruction.size) if instruction else None))
        targets.append(dict(target=hex(target), references=references))
    result = dict(disk_sha256=ST_SHA256,
                  scope='仅入口与全局槽反向引用导航；不代表调用者或表消费者已闭合',
                  targets=targets,
                  data_records=[identity(0xA76744, 4), identity(0xACB970, 4)])
    ST_BASE.mkdir(parents=True, exist_ok=True)
    path = ST_BASE / 'navigation_raw.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                    encoding='utf-8')
    return dict(targets=len(targets),
                references=sum(len(item['references']) for item in targets))
