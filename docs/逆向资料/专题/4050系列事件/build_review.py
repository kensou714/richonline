"""复核4050系列原证与当前磁盘，生成显式局部审阅记录；不自动提升未读函数。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
FILES = ('handlers.json', 'helpers.json', 'inventory_followup.json', 'date_and_bridge.json')
CONCLUSIONS = {
    0x662BF0: '4050校验GmsvID后逐角色比较8个group0 ID；不一致尝试发送两字节0003、Sleep1000并断言；不覆盖库存。',
    0x662D00: '4051按signed BYTE选择P；flag非零先减去group0槽0全部数量，再以signed WORD ID、数量1插入；无本处续接或直接确认发送。',
    0x662DC0: '4052以ECX=G+C44将signed WORD及两个signed BYTE交给694320；只写日期三字段。',
    0x64F710: '比较WORD[G+14784h]与GmsvID；不符MessageBoxA后返回0。',
    0x7F86A0: '按group0/1/2读取P+1520/282/330的6字节记录signed ID；4050固定group0。',
    0x6942F0: '两字节错误消息构造器只写首WORD0003并返回this。',
    0x6BF380: '局部核验状态<12与A76724单例对象首字节非零门，包装后向事件9交付；首字节完整语义未闭环，被调用不证明消息发送成功。',
    0x7F8710: '按group0/1/2读取6字节记录的signed数量；4051固定group0槽0。',
    0x7F8920: 'group0数量窄WORD相减，signed<=0清数量与ID；满足本地角色判断后刷新UI12。',
    0x7F8780: '扫描group0首个空ID槽插入；调用配方合成及UI12通知；P+1416非零可强制返回1。',
    0x694320: '写WORD[this+8]、BYTE[this+10/+11]；4052调用时this=G+C44。',
    0x63E560: '比较传入角色号与DWORD[this+8]；库存刷新调用点this来自DWORD[P+1404]。',
    0x6279C0: 'UI管理器单例getter，首次分配6C0h并调用构造；构造内部不在本批范围。',
    0x6E4640: '锁定后查132字节UI槽+4对象，存在才调用vtbl+10h；本批不穷尽间接消费者。',
    0x63E210: '返回this+1628，库存合成调用点来自P+1404所指对象。',
    0x627C20: '配方等资源表管理器单例getter，分配14Ch；资源装载不在本批范围。',
    0x800FD0: '局部核验60字节配方记录、按ID匹配8库存槽并原地清材料写产物；未穷尽资源表有效性。',
    0x7FDC30: '返回this+16字符串，合成通知从此取得文字；MFC识别标签不作业务命名。',
    0x6E46D0: '锁定后查UI槽对象，调用vtbl+1Ch传入通知地址。',
    0x7FD7A0: '返回BYTE[P+1416]；7F8780据非零值强制返回1。',
    0x63E440: '返回DWORD[this+4]；导出作C共享对象字段对照，日期写入不覆盖此字段。',
    0x693710: '写DWORD[this+4]；导出作C共享对象字段对照，非4052直接调用。',
    0x7EFF50: '4050桥接，将首个参数装入ECX为G并push第二参数packet转发662BF0。',
    0x7EFF70: '4051桥接，将首个参数装入ECX为G并push第二参数packet转发662D00。',
    0x7EFF90: '4052桥接，将首个参数装入ECX为G并push第二参数packet转发662DC0。',
    0x63E590: '返回G+C44共享对象地址。',
    0x7080D0: '局部核验C日期经特殊日期检索选择数字图集，月/日前两字符写控件81..84；另显示G+83804到85/86。',
    0x727A70: '读取signed BYTE[C+10]，UI及日期表将它用作月字段。',
    0x727A90: '读取signed BYTE[C+11]，UI及日期表将它用作日字段。',
    0x7D90E0: '读取signed WORD[C+8]，日期表以该值减2004选择年份段。',
    0x7D8E60: '取得C年/月/日，调用7D8DE0并比较返回值是否非-1。',
    0x7D8DE0: '按(year-2004)*26扫描13对月/日，命中返回索引否则-1；无此处年份边界钳制。',
    0x6288B0: '日期表单例getter，只见340h分配；装载及完整年份容量未核。',
    0x63F420: '返回DWORD[G+83804]，日期UI同时显示该值但本批不命名。',
}


def main():
    blob = (PROJECT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    count, optional = struct.unpack_from('<H', blob, pe + 6)[0], struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    sections = []
    for index in range(count):
        at = pe + 24 + optional + index * 40
        _, rva, size, raw = struct.unpack_from('<IIII', blob, at + 8)
        sections.append((rva, size, raw))

    def check(item):
        va, size = int(item['va'], 16), item['size']
        for rva, raw_size, raw in sections:
            relative = va - base - rva
            if 0 <= relative and relative + size <= raw_size:
                current = blob[raw + relative:raw + relative + size].hex()
                assert current == item['disk_hex'] == item['idb_hex'], item['va']
                return
        raise AssertionError('无PE原始映射：' + item['va'])

    records, thunks, total = [], {}, 0
    for name in FILES:
        evidence = json.loads((HERE / '证据' / name).read_text(encoding='utf-8'))
        assert evidence['disk_sha256'] == digest
        for function in evidence['functions']:
            va = int(function['va'], 16)
            assert va in CONCLUSIONS
            for chunk in function['byte_ranges']:
                check(chunk)
                total += chunk['size']
            records.append(dict(va=function['va'], status='局部语义已审阅',
                                conclusion=CONCLUSIONS[va], evidence='证据/' + name,
                                unknown='未实机验证；上游长度/参数校验、资源装载和间接UI消费者不计为已闭环。'))
        for thunk in evidence['thunks']:
            check(thunk)
            thunks[thunk['va']] = thunk
    assert len(records) == len(CONCLUSIONS) == 34
    assert len({r['va'] for r in records}) == len(records)
    output = dict(scope='4050系列及库存、共享日期消费者局部静态语义审阅', functions=records)
    (HERE / '函数审阅清单.json').write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    result = dict(disk_sha256=digest, functions=len(records), function_instruction_bytes=total,
                  unique_e9_thunks=len(thunks), all_current_disk_bytes_match=True,
                  excluded_candidate_scan='证据/field_scan.json只用于搜索线索，不作函数分析覆盖证明')
    (HERE / '验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
