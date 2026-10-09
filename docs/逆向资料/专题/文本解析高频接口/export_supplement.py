"""IDA-MCP 只读导出引用点、字符串常量与验证所需字节。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/大富翁online/Richonline')
HERE = ROOT / 'docs/逆向资料/专题/文本解析高频接口'


def export(db):
    disk = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    base = struct.unpack_from('<I', disk, pe + 52)[0]
    count = struct.unpack_from('<H', disk, pe + 6)[0]
    opt = struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', disk, pe + 24 + opt + 40 * i + 8)
                for i in range(count)]

    def identity(va, size):
        saved = db.bytes.get_bytes_at(va, size)
        actual = None
        for _, rva, raw_size, offset in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                actual = disk[offset + relative:offset + relative + size]
                break
        return dict(va=hex(va), size=size, idb_hex=saved.hex(),
                    disk_hex=actual.hex() if actual is not None else None,
                    matching=saved == actual)

    entries = []
    for va, thunk in [(0x90F150, 0x60559F), (0x90FA00, 0x603817),
                      (0x82A900, 0x60DF01), (0x82AB80, 0x6005E0),
                      (0x9100A0, 0x60AC11), (0x9105D0, 0x601472)]:
        bridge = identity(thunk, 5)
        raw = bytes.fromhex(bridge['idb_hex'])
        bridge['target'] = hex(thunk + 5 + int.from_bytes(raw[1:], 'little', signed=True))
        if raw[0] != 0xE9 or int(bridge['target'], 16) != va:
            raise ValueError('入口跳板不匹配')
        sites = []
        for x in db.xrefs.to_ea(thunk):
            if x.type not in (16, 17):
                continue
            ins = db.instructions.get_at(x.from_ea)
            f = db.functions.get_at(x.from_ea)
            sites.append(dict(site=hex(x.from_ea), function=hex(f.start_ea) if f else None,
                              instruction=db.instructions.get_disassembly(ins),
                              bytes=identity(x.from_ea, ins.size)))
        unowned_sites = [s['site'] for s in sites if s['function'] is None]
        entries.append(dict(entry=hex(va), thunk=bridge, direct_call_sites=sites,
                            call_site_count=len(sites),
                            caller_function_count=len({s['function'] for s in sites if s['function'] is not None}),
                            unowned_call_site_count=len(unowned_sites),
                            unowned_call_sites=unowned_sites))
    constants = []
    for site in [0x9100A9, 0x910273, 0x90ECF6]:
        for x in db.xrefs.from_ea(site):
            if x.type not in (1, 2, 3):
                continue
            raw = bytearray()
            for n in range(128):
                byte = db.bytes.get_bytes_at(x.to_ea + n, 1)
                raw.extend(byte)
                if byte == b'\0':
                    break
            else:
                continue
            constants.append(dict(site=hex(site), value=raw[:-1].decode('ascii'),
                                  bytes=identity(x.to_ea, len(raw))))
    result = dict(disk_sha256=hashlib.sha256(disk).hexdigest(),
                  scope='直接调用点数量不等于独立功能数量；未导出的调用者不计语义审阅',
                  entries=entries, constants=constants)
    (HERE / '证据/call_sites_and_constants.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return [(r['entry'], r['call_site_count'], r['caller_function_count'], r['unowned_call_sites'])
            for r in entries]
