"""独立审阅：从当前磁盘 PE 复算关键机器指令，不调用 IDA、不访问网络。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EXPECTED_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    disk = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(disk).hexdigest()
    assert digest == EXPECTED_SHA
    pe = struct.unpack_from('<I', disk, 0x3C)[0]
    assert disk[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    assert struct.unpack_from('<H', disk, opt)[0] == 0x10B
    base = struct.unpack_from('<I', disk, opt + 28)[0]
    table = opt + struct.unpack_from('<H', disk, pe + 20)[0]
    sections = [struct.unpack_from('<4I', disk, table + 40 * i + 8)
                for i in range(struct.unpack_from('<H', disk, pe + 6)[0])]

    def read(ea, size):
        matches = [(rva, raw_offset) for _, rva, raw_size, raw_offset in sections
                   if base + rva <= ea and ea + size <= base + rva + raw_size]
        assert len(matches) == 1, hex(ea)
        rva, raw_offset = matches[0]
        offset = ea - base - rva + raw_offset
        return disk[offset:offset + size]

    def cstring(ea):
        data = bytearray()
        for i in range(512):
            b = read(ea + i, 1)[0]
            if not b:
                return data.decode('ascii')
            data.append(b)
        raise AssertionError(hex(ea))

    checks = []

    def exact(ea, expected, meaning):
        actual = read(ea, len(bytes.fromhex(expected))).hex()
        assert actual == expected, (hex(ea), actual, expected)
        checks.append(dict(va=hex(ea), disk_hex=actual, meaning=meaning))

    def relative(ea, opcode, target, meaning):
        raw = read(ea, 5)
        assert raw[0] == opcode
        assert ea + 5 + struct.unpack_from('<i', raw, 1)[0] == target
        checks.append(dict(va=hex(ea), disk_hex=raw.hex(), target=hex(target), meaning=meaning))

    exact(0x81E10B, '894dfc8b4dfc', '保存ECX并在调用清理前恢复ECX')
    relative(0x81E111, 0xE8, 0x60AE82, '清理包装器的直接call')
    relative(0x60AE82, 0xE9, 0x81E1C0, '清理包装器的E9终点')
    exact(0x81E2C2, '837d10007415', '比较文件名指针本身是否为NULL，未读指向字节')
    exact(0x81E3F0, '3b910c0100007670', '容量比较与无符号jbe')
    exact(0x81E48E, 'ff150c40ad00', '唯一直接InternetReadFile导入调用')
    exact(0x81E4D9, '6a01', '写盘助手的ElementCount实参为1')
    relative(0x81E4EF, 0xE8, 0x60FEAF, '四参数写盘助手，内部另审')
    relative(0x60FEAF, 0xE9, 0x9243E0, '写盘助手的E9终点')
    exact(0x8198FD, '8b8890000000', '取parser+144输入指针')
    exact(0x819988, 'c60200eb64', '写终止NUL后直接跳往事后检查')
    exact(0x8199F4, '3b550c7e17', '计数与容量做有符号比较，jle跳过assert')
    key_sites = ((0x62312F, 0xA2202C, 'num'),
                 (0x6232FF, 0xA22058, 'reg'),
                 (0x623447, 0xA22074, 'win'))
    for site, pointer, key in key_sites:
        exact(site, (b'\x68' + struct.pack('<I', pointer)).hex(), 'push立即地址，不是解引用：' + key)
        assert cstring(pointer) == key

    import_rva, import_size = struct.unpack_from('<II', disk, opt + 104)
    imports = {}
    for offset in range(0, import_size, 20):
        original, stamp, forwarder, name, first = struct.unpack('<5I', read(base + import_rva + offset, 20))
        if not any((original, stamp, forwarder, name, first)):
            break
        dll = cstring(base + name)
        source = original or first
        for i in range(4096):
            entry = struct.unpack('<I', read(base + source + i * 4, 4))[0]
            if entry == 0:
                break
            if entry & 0x80000000:
                symbol = 'ordinal:' + str(entry & 0xFFFF)
            else:
                symbol = cstring(base + entry + 2)
            imports[base + first + i * 4] = dict(dll=dll, name=symbol)
        else:
            raise AssertionError('未终止导入数组')
    expected = {0xAD4004: 'InternetOpenUrlA', 0xAD4008: 'HttpQueryInfoA',
                0xAD400C: 'InternetReadFile', 0xAD4010: 'InternetCloseHandle',
                0xAD4014: 'InternetOpenA'}
    for slot, symbol in expected.items():
        assert imports[slot] == dict(dll='WININET.dll', name=symbol)

    evidence = json.loads((HERE / 'functions_raw.json').read_text('utf-8'))
    functions = {f['va']: f for f in evidence['functions']}
    reader = functions['0x81e290']
    reader_calls = [a for a in reader['assembly'] if 'InternetReadFile' in a['text']]
    assert [a['va'] for a in reader_calls] == ['0x81e48e']
    for f in functions.values():
        for span in f['chunk_byte_ranges']:
            assert read(int(span['va'], 16), span['size']).hex() == span['idb_hex'] == span['disk_hex']
    result = dict(status='PASS', disk_sha256=digest, instruction_checks=checks,
                  import_names={hex(ea): imports[ea] for ea in expected},
                  scope='独立磁盘指令、导入名称及主原证声明块；未运行客户端或补认领下游语义')
    (HERE / 'independent_validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(status=result['status'], checks=len(checks), disk_sha256=digest)))


if __name__ == '__main__':
    main()
