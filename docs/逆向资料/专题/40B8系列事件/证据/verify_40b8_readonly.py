"""只读核验当前PE的函数块、跳板、注册和虚表；只读解包指定KPD记录。"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def resource(path, encoding, section, wanted):
    packed = (ROOT / path).read_bytes()
    if len(packed) < 9:
        raise ValueError('KPD头不完整：'+path)
    decoded = bytes((byte-packed[0]) & 255 for byte in packed[1:])
    size, compressed = struct.unpack_from('<II', decoded)
    if len(decoded)-8 != compressed or not 0 < size <= 16*1024*1024:
        raise ValueError('KPD长度或本工具上限不符：'+path)
    plain = lzokay.decompress(decoded[8:], size)
    if len(plain) != size:
        raise ValueError('KPD解压长度不符：'+path)
    records = {}
    for block in plain.decode(encoding, errors='strict').split('['+section+']')[1:]:
        values = {}
        for line in block.splitlines():
            text = line.strip()
            if text.startswith('['):
                break
            if '=' in text and not text.startswith('//'):
                key, value = text.split('=', 1)
                values[key.strip()] = value.strip()
        if 'indx' in values and int(values['indx']) in wanted:
            index = int(values['indx'])
            if index in records:
                raise ValueError('重复指定资源记录：'+path+'/'+str(index))
            records[index] = values
    if set(records) != wanted:
        raise ValueError('资源缺项：'+path+'/'+str(wanted-set(records)))
    return {'source': path, 'encoding': encoding+'严格解码', 'packed_sha256': sha(packed),
            'plain_sha256': sha(plain), 'plain_size': len(plain), 'records': records}


def main():
    exe = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', exe, 60)[0]
    count = struct.unpack_from('<H', exe, pe+6)[0]
    optional_size = struct.unpack_from('<H', exe, pe+20)[0]
    imagebase = struct.unpack_from('<I', exe, pe+52)[0]
    sections = [struct.unpack_from('<IIII', exe, pe+24+optional_size+40*i+8) for i in range(count)]

    def read_va(address, size):
        rva = address-imagebase
        for _, start, rawsize, offset in sections:
            if start <= rva and rva+size <= start+rawsize:
                return exe[offset+rva-start:offset+rva-start+size]
        raise ValueError(f'区间不在当前PE磁盘节：{address:#x}/{size}')

    def compare(item, kind):
        expected = bytes.fromhex(item['idb_hex'])
        if len(expected) != item['size']:
            raise ValueError('原证长度不符：'+item['va'])
        actual = read_va(int(item['va'], 16), item['size'])
        return {'kind': kind, 'va': item['va'], 'size': item['size'], 'equal': expected == actual,
                'idb_sha256': sha(expected), 'disk_sha256': sha(actual)}

    groups = json.loads((BASE / 'export_groups.json').read_text(encoding='utf-8'))
    functions, thunks, checks = {}, {}, []
    for filename in groups:
        raw = json.loads((BASE / filename).read_text(encoding='utf-8'))
        for function in raw['functions']:
            if function['va'] in functions and function != functions[function['va']]:
                raise ValueError('重叠导出函数原证不一致：'+function['va'])
            functions[function['va']] = function
        for thunk in raw['thunks']:
            if thunk['va'] in thunks and thunk != thunks[thunk['va']]:
                raise ValueError('重叠跳板原证不一致：'+thunk['va'])
            thunks[thunk['va']] = thunk
    for function in functions.values():
        checks.extend(compare(item, 'function_byte_range') for item in function['byte_ranges'])
    checks.extend(compare(item, 'direct_thunk') for item in thunks.values())
    chunks = json.loads((BASE / '完整函数块审核.json').read_text(encoding='utf-8'))
    if chunks['functions'] != len(functions) or chunks['coverage_gaps'] or chunks['chunk_api_mismatches']:
        raise ValueError('完整函数块审核存在缺口')
    checks.extend(compare(item, 'complete_chunk') for item in chunks['chunks'])
    extras = json.loads((BASE / '补充区间.json').read_text(encoding='utf-8'))
    checks.extend(compare(item, item['kind']) for item in extras['ranges']+extras['code_ranges'])
    failed = [item for item in checks if not item['equal']]
    report = {'disk_sha256': sha(exe),
              'idb_input_sha256': 'CB35F69F3D49C2093897D4EA2CB547A1E38B213F3A8DF0AF52B859F9E661DE77',
              'method': 'PE原始节VA映射逐区间；完整chunk及每个导出前缀交叉检查；不依赖整文件相同',
              'all_equal': not failed, 'checks': checks, 'failures': failed,
              'counts': dict(Counter(item['kind'] for item in checks))}
    save(BASE / '当前磁盘核验.json', report)
    notes = json.loads((BASE / 'review_annotations.json').read_text(encoding='utf-8'))['entries']
    if {item['address'] for item in notes if item['kind'] == 'function'} != set(functions):
        raise ValueError('人工清单没有覆盖每个函数')
    match_by_address = {address: all(compare(region, 'function_byte_range')['equal']
                                    for region in function['byte_ranges'])
                        for address, function in functions.items()}
    for region in extras['code_ranges']:
        match_by_address[region['va']] = compare(region, region['kind'])['equal']
    for item in notes:
        item['disk_match'] = match_by_address[item['address']]
    save(BASE.parent / '函数审阅清单.json', {'method': '人工逐项结论；导出与磁盘匹配不提升语义完成度；跨专题按VA去重',
                                          'functions': [item for item in notes if item['kind'] == 'function'],
                                          'code_ranges': [item for item in notes if item['kind'] == 'code_range'],
                                          'counts': dict(Counter(item['status'] for item in notes))})
    lines = ['// ============================================================================', '// 40B8系列 / 逐函数结论与未完成范围',
             '// ============================================================================', '// 已分析仅限条目写明的路径，复用函数不重复统计为新游戏能力。', '//']
    for item in notes:
        lines.extend(['// '+item['address']+'  '+item['status'], '//   结论：'+item['conclusion'],
                      '//   未知：'+item['unknown'], '//   证据：'+item['evidence'],
                      '//   复用：'+('；'.join(item['reuse']) or '无'), '//'])
    (BASE.parent / '06_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    resources = [resource('Data/Prop.kpd', 'big5', 'PROP', set(range(1039, 1047)) | {1071}),
                 resource('Data/RichStr.kpd', 'big5', 'ITEM', {40, 41, 264, 359}),
                 resource('Data/Anim.kpd', 'gbk', 'ANIM', {18}),
                 resource('Data/GValue.kpd', 'gbk', 'ITEM', {0, 5, 7, 8, 9, 11, 19, 21})]
    save(BASE / '资源摘要.json', {'scope': '只摘录本专题使用的记录；繁体原文不改写；不将下一节前置注释混入当前记录',
                                 'sources': resources})
    bad_lines = []
    for path in BASE.parent.glob('*.txt'):
        for index, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if line and not line.startswith('//'):
                bad_lines.append(f'{path.name}:{index}')
    summary = {'functions': len(functions), 'complete_chunks': len(chunks['chunks']),
               'thunks': len(thunks), 'code_ranges': len(extras['code_ranges']),
               'extra_ranges': len(extras['ranges']), 'checked_intervals': len(checks),
               'all_equal': not failed, 'status_counts': dict(Counter(item['status'] for item in notes)),
               'txt_bad_lines': bad_lines}
    save(BASE / '核验摘要.json', summary)
    print(json.dumps(summary, ensure_ascii=True))
    if failed or bad_lines:
        raise SystemExit('本专题核验不通过')


if __name__ == '__main__':
    main()
