"""逐块核磁盘原字节，生成显式局部审阅清单；不把导出上下文当全分析。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FILES = ('entries.json', 'callers.json', 'followups.json', 'ctor_and_loaders.json')
CONCLUSIONS = {
    0x6C22E0: '逐分支核1..8/default到RichStr编号，显示UI71后交文本；ECX仅保存，retn4；当前文本编号全缺。',
    0x6F4AA0: '两个cdecl整数参数按类别0/1/2取物品期限，完整映射至type10图像槽；signed门槛1500，其他期限空句柄。',
    0x627B60: 'A766DC懒建12B字符串对象；内存不足保留0；构造仅另核6D7170。',
    0x627C20: 'A766E0懒建0x14C物品配置对象；未装载前首记录指针0，输入索引不在getter钳制。',
    0x629D90: 'thiscall/retn4，返回DWORD[this+8]+DWORD[this]*编号，无边界与缺项检测。',
    0x6DBA40: '仅审type10分支：signed校验group与frame0..99，取12B槽+4句柄；非法返回-1；retn10h。',
    0x800AD0: 'thiscall/retn4，以1128B记录+68/+72/+76计算365*y+30*m+d，无索引校验。',
    0x800B30: 'thiscall/retn4，以1128B记录+80/+84/+88计算365*y+30*m+d，无索引校验。',
    0x800B90: 'thiscall/retn4，以1128B记录+92/+96/+100计算365*y+30*m+d，无索引校验。',
    0x6D7170: '字符串对象构造仅写this+8=0，未写size/count；不能据此认定缺项默认空串。',
    0x7FEA80: '局部核物品管理器构造清首记录指针及一组计数/指针；没有装载与期限资源键赋值。',
}
RESULT_CALLERS = {0x6C2590, 0x6C2790, 0x6C2870, 0x6C29A0, 0x6C2B80, 0x6C2D70,
                  0x6C2E70, 0x6C3000, 0x6C3120, 0x6C32E0, 0x6C34A0, 0x6C35B0, 0x6C3670}
ICON_CALLERS = {0x741820, 0x747E10, 0x749D60, 0x756460, 0x75AD50, 0x762A80,
                0x762E10, 0x766B50, 0x767860, 0x77F590, 0x77FEF0}


def icon_slot(n):
    if n >= 1500:
        return (15, 19)
    return {1: (38, 40), 2: (47, 15), 3: (38, 41), 5: (51, 87), 7: (38, 44),
            15: (38, 42), 30: (38, 43), 180: (38, 45), 365: (38, 51)}.get(n, (38, -1))


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    count = struct.unpack_from('<H', blob, pe + 6)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional + 40*i + 8)
                for i in range(count)]

    def disk(va, size):
        for _, rva, raw_size, raw in sections:
            offset = va-base-rva
            if 0 <= offset and offset+size <= raw_size:
                return blob[raw+offset:raw+offset+size]
        raise AssertionError('PE无原始字节映射：' + hex(va))

    def check(item):
        raw = disk(int(item['va'], 16), item['size']).hex()
        assert raw == item['disk_hex'] == item['idb_hex'], item['va']

    functions, thunks, records = {}, {}, []
    instruction_bytes, declared_bytes = 0, 0
    for name in FILES:
        evidence = json.loads((HERE / '证据' / name).read_text(encoding='utf-8'))
        assert evidence['disk_sha256'] == digest
        for f in evidence['functions']:
            va = int(f['va'], 16)
            assert va not in functions
            functions[va] = f
            for r in f['byte_ranges']:
                check(r)
                instruction_bytes += r['size']
            for r in f['chunk_byte_ranges']:
                check(r)
                declared_bytes += r['size']
            if va in CONCLUSIONS:
                conclusion = CONCLUSIONS[va]
            elif va in RESULT_CALLERS:
                conclusion = '仅审首参数非0转6056EE->6C22E0，0继续数据处理；其余容器/窗口业务未全审。'
                assert any(c['implementation'] == '0x6c22e0' for c in f['calls'])
            else:
                assert va in ICON_CALLERS
                conclusion = '仅审期限图标调用点：两个整数参数经60CF11->6F4AA0，调用后add esp8；记录来源见02文档。'
                sites = {c['site'] for c in f['calls'] if c['implementation'] == '0x6f4aa0'}
                assert sites
                for site in sites:
                    i = next(i for i, s in enumerate(f['assembly']) if s['va'] == site)
                    assert f['assembly'][i+1]['text'] == 'add     esp, 8'
            records.append(dict(va=f['va'], status='局部静态语义已审阅', conclusion=conclusion,
                                unknown='未实机验证；完整调用者业务、UI71响应、装载字段映射、索引有效性与图像生命周期不计闭环。',
                                evidence='证据/' + name))
        for t in evidence['thunks']:
            check(t)
            va = int(t['va'], 16)
            raw = disk(va, 5)
            assert raw[0] == 0xE9 and va+5+int.from_bytes(raw[1:], 'little', signed=True) == int(t['target'], 16)
            thunks[t['va']] = t
    assert set(functions) == set(CONCLUSIONS) | RESULT_CALLERS | ICON_CALLERS

    # 跳表及各分支立即数直接来自磁盘，独立于伪码的case注释。
    switch = disk(0x6C2313, 7)
    assert switch[:3] == bytes.fromhex('ff2495')
    table = struct.unpack_from('<I', switch, 3)[0]
    cases = struct.unpack('<8I', disk(table, 32))
    text_ids = (1123, 1124, 1121, 1125, 1126, 1127, 1128, 1120)
    for target, text_id in zip(cases, text_ids):
        assert disk(target, 6) == bytes.fromhex('6a006a006a47')
        assert disk(target+18, 1) == b'\x68'
        assert struct.unpack('<I', disk(target+19, 4))[0] == text_id
    icon_switch = disk(0x6F4B4E, 7)
    assert icon_switch[:3] == bytes.fromhex('ff2485')
    icon_table = struct.unpack_from('<I', icon_switch, 3)[0]
    assert struct.unpack('<7I', disk(icon_table, 28)) == (
        0x6F4B6F, 0x6F4BAE, 0x6F4B78, 0x6F4BCC, 0x6F4BBE, 0x6F4BCC, 0x6F4B93)
    stores = {0x6F4B6F: (0xF8, 40), 0x6F4B78: (0xF8, 41), 0x6F4B81: (0xF8, 42),
              0x6F4B8A: (0xF8, 43), 0x6F4B93: (0xF8, 44), 0x6F4B9C: (0xF8, 45),
              0x6F4BA5: (0xF8, 51), 0x6F4BAE: (0xF8, 15), 0x6F4BB5: (0xF4, 47),
              0x6F4BBE: (0xF8, 87), 0x6F4BC5: (0xF4, 51),
              0x6F4BD5: (0xF4, 15), 0x6F4BDC: (0xF8, 19)}
    for va, (offset, value) in stores.items():
        assert disk(va, 7) == b'\xc7\x45' + bytes([offset]) + struct.pack('<I', value)
    assert disk(0x6F4BCC, 7) == b'\x81\x7d\xfc' + struct.pack('<I', 1500)
    assert disk(0x6F4BD3, 1) == b'\x7c'  # signed jl
    n_cases = (-2147483648, -1, 0, 1, 2, 3, 4, 5, 6, 7, 14, 15, 16, 30, 31,
               180, 365, 395, 1499, 1500, 1501, 2147483647)
    samples = [dict(n=n, group=icon_slot(n)[0], frame=icon_slot(n)[1]) for n in n_cases]
    assert icon_slot(1499) == (38, -1) and icon_slot(1500) == (15, 19)
    assert icon_slot(2) == (47, 15) and icon_slot(5) == (51, 87)
    frame_asm = {s['va']: s['text'] for s in functions[0x6DBA40]['assembly']}
    assert frame_asm['0x6dbad5'].startswith('jl ')
    assert frame_asm['0x6dbadb'].startswith('jge ')
    resources = json.loads((HERE / '证据/resources.json').read_text(encoding='utf-8'))
    for r in resources['records']:
        assert hashlib.sha256((ROOT / r['source']).read_bytes()).hexdigest() == r['source_sha256']
        assert r['strict_roundtrip']
    assert resources['records'][0]['missing_indices'] == [str(i) for i in range(1120, 1130)]
    result = dict(disk_sha256=digest, functions=len(records), instruction_bytes=instruction_bytes,
                  declared_chunk_bytes=declared_bytes, byte_accounting='两种范围重叠，不相加',
                  unique_e9_thunks=len(thunks), resource_files=len(resources['records']),
                  all_current_disk_bytes_match=True, runtime_verified=False,
                  result_code_switch={'table_va': hex(table), 'targets': [hex(a) for a in cases], 'text_ids': list(text_ids)},
                  icon_switch_table_va=hex(icon_table), icon_immediate_stores_checked=len(stores),
                  icon_model_samples=samples, review_counts={'局部静态语义已审阅': len(records)})
    (HERE / '审阅清单.json').write_text(json.dumps(dict(scope='两个映射入口及局部调用来源，非完整窗口闭环', functions=records), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in {'icon_model_samples', 'result_code_switch'}}, ensure_ascii=True))


if __name__ == '__main__':
    main()
