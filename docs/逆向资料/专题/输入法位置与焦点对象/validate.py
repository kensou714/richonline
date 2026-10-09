"""复核输入法专题的磁盘范围、导入包装、分支立即数和逐入口分级。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EVIDENCE = HERE / '证据'
FILES = ['ime_seeds.json', 'ime_dependencies.json', 'ime_import_wrappers.json', 'ime_init_caller.json']
REVIEWS = {
    0x625C10: ('局部语义确认', '焦点下沿位置、四次HIMC访问、Get/Set不检查BOOL及候选参数保留边界'),
    0x629EF0: ('字段访问器确认', '返回ECX对象+356的DWORD'),
    0x629F20: ('字段访问器确认', '返回ECX对象+360的DWORD；自动RibbonButton识别不作为真实类型'),
    0x629F50: ('字段访问器确认', '返回ECX对象+364的DWORD'),
    0x629F80: ('字段访问器确认', '返回ECX对象+20716焦点指针；没有this空检查'),
    0x629FB0: ('字段访问器确认', '读取全局A76504的DWORD'),
    0x7A4830: ('字段访问器确认', '返回byte_A76690；用户配置名未确认'),
    0x7A29E0: ('局部分支确认', 'UI分派在特殊消息前，0x10D调用625C10后仍到默认窗口过程'),
    0x8E8A10: ('局部分支确认', '0x10D在两段接受范围之外，返回0；仅确认IME相关分派边界'),
    0x8E30D0: ('复用局部核对', '子对象+360/+364累计父绝对坐标并回写相对值'),
    0x623AD0: ('局部分支确认', 'ImmGetContext(HWND)返回值写A76504，不检查失败'),
    0x623B60: ('局部分支确认', '进入其他初始化前调用623AD0；其他初始化依赖未完整分析'),
}
IMPORTS = {0x82759E: 0xAD3B0C, 0x8275A4: 0xAD3B1C, 0x8275AA: 0xAD3B10,
           0x8275B0: 0xAD3B14, 0x8275B6: 0xAD3B18}


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    opt_size = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + opt_size + 40*i + 8) for i in range(count)]

    def disk(ea, size):
        for vs, rva, rs, off in sections:
            delta = ea - base - rva
            if 0 <= delta and delta + size <= rs:
                return blob[off+delta:off+delta+size]
        raise AssertionError(('无磁盘映射', hex(ea), size))

    comparisons, ranges, functions, bridges = 0, {}, {}, {}

    def verify(row):
        nonlocal comparisons
        address, size = int(row['va'], 16), row['size']
        actual = disk(address, size)
        assert actual.hex() == row['idb_hex'] == row['disk_hex']
        assert row['matching'] is True
        ranges[(address, size)] = actual
        comparisons += 1

    for name in FILES:
        data = json.loads((EVIDENCE / name).read_text(encoding='utf-8'))
        assert data['disk_sha256'] == digest
        for function in data['functions']:
            address = int(function['va'], 16)
            assert address not in functions
            functions[address] = (name, function)
            assert function['bytes_match_disk']
            assert len(function['declared_chunks']) == len(function['chunk_byte_ranges'])
            for chunk, row in zip(function['declared_chunks'], function['chunk_byte_ranges']):
                assert row['va'] == chunk['start_va']
                assert row['size'] == int(chunk['end_va'], 16) - int(chunk['start_va'], 16)
            for row in function['byte_ranges'] + function['chunk_byte_ranges']:
                verify(row)
        for row in data['thunks']:
            verify(row)
            raw = bytes.fromhex(row['idb_hex'])
            assert raw[0] == 0xE9 and int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(row['target'], 16)
            bridges[row['va']] = row
    refs = json.loads((EVIDENCE / 'ime_references.json').read_text(encoding='utf-8'))
    assert refs['disk_sha256'] == digest
    for row in refs['globals']:
        verify(row)
        assert row['disk_backed'] and not row['pe_zero_fill']
    for target in refs['inbound']:
        for row in target['bridges']:
            verify(row)
            bridges[row['va']] = row
    for ea, target in IMPORTS.items():
        assert disk(ea, 6) == b'\xff\x25' + struct.pack('<I', target)
        REVIEWS[ea] = ('导入包装核对', '六字节FF25跳转到已列明IME导入槽；不分析系统API内部')
    assert set(functions) == set(REVIEWS)
    assert disk(0x625C72, 7) == bytes.fromhex('c745cc20000000')
    # 0x10D越过键盘上界，再作无符号减0x200后的鼠标上界比较。
    assert disk(0x8E8A5A, 8) == bytes.fromhex('0500ffffff83f805')
    assert disk(0x8E8B0D, 9) == bytes.fromhex('8d8100feffff83f80a')
    assert disk(0x8E8B16, 2) == bytes.fromhex('0f87')
    catalog = dict(scope='17声明入口按本专题实际局部核对；不代表完整IME输入链已分析',
                   disk_sha256=digest, functions=[dict(va=hex(ea), status=REVIEWS[ea][0],
                   conclusion=REVIEWS[ea][1], evidence=[functions[ea][0]], full_dependency_closure=False,
                   unknown='动态调用、句柄完整释放、不同IME实机表现及派生编辑控件不在本专题验证范围') for ea in sorted(functions)])
    (EVIDENCE / 'function_review.json').write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    intervals = sorted((a, a+s) for a, s in ranges)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    result = dict(disk_sha256=digest, functions=len(functions),
                  declared_chunks=sum(len(f[1]['declared_chunks']) for f in functions.values()),
                  byte_comparisons=comparisons, unique_ranges=len(ranges), bridges=len(bridges),
                  union_bytes=sum(end-start for start, end in merged), import_wrappers=5,
                  scope='离线磁盘证据一致性及关键指令核对；未启动游戏、未执行IME API')
    (EVIDENCE / 'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
