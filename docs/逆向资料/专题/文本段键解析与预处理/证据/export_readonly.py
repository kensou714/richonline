"""只读导出文本加载、段键定位、清理和CR预处理；不修改IDA数据库。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = Path(__file__).resolve().parent
SEEDS = (0x8191D0, 0x819220, 0x819250, 0x8193F0,
         0x819470, 0x819660, 0x819FB0)
BRIDGES = (0x608F8D, 0x60BA26, 0x60ACA7, 0x607C3C,
           0x608335, 0x609528, 0x60D71D)


def export(db):
    ns = {}
    exec((ROOT / 'docs/逆向资料/全量分析/export_function_group.py').read_text('utf-8'), ns)
    result = ns['export_group'](db, SEEDS, str(HERE / 'functions_raw.json'))
    image = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + i * 40 + 8)
                for i in range(struct.unpack_from('<H', image, pe + 6)[0])]

    def identity(ea, size):
        disk = None
        for _, rva, length, offset in sections:
            relative = ea - base - rva
            if 0 <= relative and relative + size <= length:
                disk = image[offset + relative:offset + relative + size]
                break
        raw = db.bytes.get_bytes_at(ea, size)
        return dict(va=hex(ea), size=size, idb_hex=raw.hex(),
                    disk_hex=disk.hex() if disk is not None else None,
                    matching=disk == raw)

    bridges = []
    for ea, target in zip(BRIDGES, SEEDS):
        row = identity(ea, 5)
        raw = bytes.fromhex(row['idb_hex'])
        assert raw[0] == 0xE9 and ea + 5 + int.from_bytes(raw[1:], 'little', signed=True) == target
        row['target'] = hex(target)
        bridges.append(row)
    data = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    constants = {}
    for f in data['functions']:
        for ins in f['assembly']:
            for edge in db.xrefs.from_ea(int(ins['va'], 16)):
                if not 1 <= int(edge.type) < 16:
                    continue
                ea = edge.to_ea
                # 仅文件模式常量；BSS暂存区不能伪装成磁盘初始化字节。
                if 0xA00000 <= ea < 0xA70000:
                    constants[ea] = identity(ea, 128)
    (HERE / 'bridges_constants_raw.json').write_text(json.dumps(
        dict(disk_sha256=hashlib.sha256(image).hexdigest(), bridges=bridges,
             constant_windows=list(constants.values()),
             shared_buffers=[dict(va='0xabaa60', storage='BSS', capacity='未知'),
                             dict(va='0xabab00', storage='BSS', capacity='未知')]),
        ensure_ascii=False, indent=2), 'utf-8')
    return dict(functions=result, bridges=len(bridges), constant_windows=len(constants))
