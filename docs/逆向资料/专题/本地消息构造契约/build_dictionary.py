"""核验字节与显式默认值，生成中文构造契约；调用站点枚举不自动变成业务已分析。"""
import hashlib
import json
import re
import struct
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
# 人工核对的额外写入：offset、width、原始无符号值；首WORD操作码统一另加。
DEFAULTS = {
    0x6000: [(8, 4, 0), (12, 4, 0), (16, 4, 0)],
    0x6001: [(4, 1, 0), (5, 1, 0), (8, 4, 0)],
    0x6002: [(5, 1, 0), (6, 1, 1), (8, 4, 0)],
    0x6003: [(6, 1, 0), (5, 1, 0), (4, 1, 0), (8, 4, 0), (12, 4, 0), (16, 4, 0), (20, 4, 0)],
    0x6007: [(5, 1, 0), (8, 4, 0)],
    0x6008: [(4, 4, 0), (8, 4, 0)], 0x600A: [(8, 4, 0)],
    0x601A: [(6, 1, 255), (5, 1, 255)], 0x6051: [(4, 1, 1)],
    0x6060: [(6, 1, 0), (5, 1, 0), (4, 1, 0), (3, 1, 0)],
    0x6061: [(7, 1, 0), (9, 1, 0), (8, 1, 0), (6, 1, 1)],
    0x6062: [(4, 1, 0), (3, 1, 0)], 0x6067: [(4, 1, 0), (3, 1, 0)],
    0x606A: [(4, 1, 0), (3, 1, 0)], 0x606B: [(5, 1, 0), (4, 1, 0)],
    0x6071: [(5, 1, 1)], 0x6072: [(4, 1, 1), (5, 1, 1)], 0x6080: [(3, 1, 255)],
}


def read(name):
    return json.loads((BASE / '证据' / name).read_text(encoding='utf-8'))


def number(text):
    return int(text[:-1], 16) if text.endswith('h') else int(text)


def intervals(values):
    spans = []
    for value in sorted(values):
        if spans and spans[-1][-1] + 1 == value:
            spans[-1].append(value)
        else:
            spans.append([value])
    return '、'.join(str(span[0]) if len(span) == 1 else f'{span[0]}..{span[-1]}' for span in spans) or '无'


def main():
    constructors, callers, links = read('constructors.json'), read('callers.json'), read('contract_links.json')
    blob = (ROOT / 'RnClient.exe').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    pe = struct.unpack_from('<I', blob, 60)[0]
    count, optional = struct.unpack_from('<H', blob, pe+6)[0], struct.unpack_from('<H', blob, pe+20)[0]
    imagebase = struct.unpack_from('<I', blob, pe+52)[0]
    sections = [struct.unpack_from('<IIII', blob, pe+24+optional+40*i+8) for i in range(count)]
    verified = {}

    def verify(item):
        address, size = int(item['va'], 16), item['size']
        expected = bytes.fromhex(item['idb_hex'])
        assert len(expected) == size
        for _, rva, rawsize, raw in sections:
            delta = address - imagebase - rva
            if 0 <= delta and delta + size <= rawsize:
                assert blob[raw+delta:raw+delta+size] == expected, item['va']
                if 'disk_hex' in item:
                    assert item['disk_hex'] == item['idb_hex']
                verified[(address, size)] = size
                return
        raise AssertionError('区间无原始映射：' + item['va'])

    functions = {item['va']: item for item in constructors['functions']}
    caller_functions = {item['va']: item for item in callers['functions']}
    for group in (constructors, callers):
        assert group['disk_sha256'] == digest
        for function in group['functions']:
            for chunk in function['byte_ranges']:
                verify(chunk)
        for thunk in group['thunks']:
            verify(thunk)
    for item in links['metadata_ranges'] + links['constructor_thunks']:
        verify(item)

    lines = ['// 本地消息构造字典：偏移/容量均以字节计，编号为十六进制。',
             '// 每项首WORD由构造器写为该编号；额外写入之外的字节不保证初始化。',
             '// RTC是精确对应调用点的栈对象容量；入队前缀是保守识别候选，不是线上包长。',
             '// “未写”仅指构造器未写；调用者可能稍后赋值，也可能保留0xCC或原值。', '//']
    navigation = ['// 构造器调用导航：完整1351个站点见构造契约.json及证据/contract_links.json。',
                  '// 每项给一条证据完整的代表站点；不把调用函数全文导出算作全文审阅。', '//']
    records, entries = [], []
    for candidate in sorted(links['candidates'], key=lambda item: int(item['opcode'], 16)):
        opcode, address = int(candidate['opcode'], 16), candidate['function']
        function = functions[address]
        writes, this_registers = [], set()
        for instruction in function['assembly']:
            text = instruction['text'].split(';')[0].strip()
            alias = re.fullmatch(r'mov\s+(eax|ecx|edx), \[ebp\+var_4\]', text)
            if alias:
                this_registers.add(alias[1])
            match = re.fullmatch(r'mov\s+(byte|word|dword) ptr \[(eax|ecx|edx)(?:\+([0-9A-F]+h?))?\], ([0-9A-F]+h?)', text)
            if match:
                assert match[2] in this_registers
                writes.append((number(match[3]) if match[3] else 0,
                               {'byte': 1, 'word': 2, 'dword': 4}[match[1]], number(match[4])))
            assert not text.startswith(('call ', 'jmp ', 'jz ', 'jnz ')), address
        expected = [(0, 2, opcode)] + DEFAULTS.get(opcode, [])
        assert writes == expected, (address, writes, expected)
        sites = [site for site in links['callsites'] if site['constructor'] == address]
        for site in sites:
            assert site['caller'] in caller_functions
            assert any(ins['va'] == site['site'] for ins in caller_functions[site['caller']]['assembly'])
        rtc_sizes = sorted({match['size'] for site in sites for match in site['rtc_matches']})
        prefix_sizes = sorted({match['size'] for site in sites for match in site['queue_prefix_candidates']})
        written = {offset+i for offset, width, value in writes for i in range(width)}
        extent = max(written) + 1
        capacity = rtc_sizes[0] if len(rtc_sizes) == 1 else (prefix_sizes[0] if len(prefix_sizes) == 1 else extent)
        assert extent <= capacity
        extra = '；'.join(f'+{offset} { {1:"BYTE",2:"WORD",4:"DWORD"}[width]}={value}' for offset, width, value in writes[1:]) or '无，只有首WORD'
        aliases = [item['va'] for item in links['constructor_thunks'] if item['target'] == address]
        lines.extend([f'// {opcode:04X}  构造器{address}  跳板{", ".join(aliases)}',
                      f'//   额外默认：{extra}。',
                      f'//   RTC容量={rtc_sizes or "未登记"}；入队前缀={prefix_sizes or "未对应"}；调用站点={len(sites)}。',
                      f'//   {"RTC容量" if rtc_sizes else "已见前缀"}内未写偏移：{intervals(set(range(capacity))-written)}。', '//'])
        sample = next((site for site in sites if site['rtc_matches'] and site['queue_prefix_candidates']), sites[0])
        navigation.append(f'// {opcode:04X}  {sample["caller"]} 内 {sample["site"]} -> {sample["target"]} -> {address}')
        if sample['rtc_matches']:
            match = sample['rtc_matches'][0]
            navigation.append(f'//   EBP{match["offset"]:+d}；RTC表头{match["header"]}、条目{match["descriptor"]}；size={match["size"]}。')
        if sample['queue_prefix_candidates']:
            match = sample['queue_prefix_candidates'][0]
            navigation.append(f'//   入队候选{match["site"]}；Size压栈{match["size_push"]}={match["size"]}。')
        entry = dict(opcode=candidate['opcode'], va=address, aliases=aliases,
                     writes=[dict(offset=o, width=w, value=v) for o, w, v in writes],
                     write_extent=extent, rtc_sizes=rtc_sizes, queue_prefix_sizes=prefix_sizes, callsites=sites)
        entries.append(entry)
        records.append(dict(va=address, status='局部语义已审阅',
                            conclusion=f'{opcode:04X}构造器：首WORD及额外默认值{extra}；构造范围无调用或条件分支。',
                            evidence='证据/constructors.json',
                            unknown='构造写入不证明全部字段含义、完整调用者业务或线上协议；RTC/前缀分别见字典。'))
    assert len(entries) == 66 and len(links['callsites']) == 1351
    for function in callers['functions']:
        records.append(dict(va=function['va'], status='仅导出',
                            conclusion='仅为构造调用站点、RTC容量和入队前缀核对保存完整函数原证；本次不主张全文业务已分析。',
                            evidence='证据/callers.json', unknown='调用者业务及间接调用未按全文审阅。'))
    (BASE/'01_逐项构造字典.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    (BASE/'02_调用站点与容量导航.txt').write_text('\n'.join(navigation)+'\n', encoding='utf-8')
    (BASE/'构造契约.json').write_text(json.dumps(dict(entries=entries), ensure_ascii=False, indent=2), encoding='utf-8')
    (BASE/'函数审阅清单.json').write_text(json.dumps(dict(functions=records), ensure_ascii=False, indent=2), encoding='utf-8')
    result = dict(disk_sha256=digest, constructors=len(entries), callers_export_only=len(callers['functions']),
                  callsites=len(links['callsites']), rtc_matched_callsites=sum(bool(s['rtc_matches']) for s in links['callsites']),
                  queue_candidate_callsites=sum(bool(s['queue_prefix_candidates']) for s in links['callsites']),
                  byte_intervals=len(verified), interval_bytes=sum(verified.values()), all_current_disk_bytes_match=True)
    (BASE/'验证结果.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
