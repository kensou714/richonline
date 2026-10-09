"""只读当前客户端和KPD，生成逐区间核验、资源原文与逐函数人工范围清单。"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import re
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def decode_kpd(relative):
    raw = (ROOT / relative).read_bytes()
    if len(raw) < 9:
        raise ValueError('KPD头短于9字节')
    decoded = bytes((value-raw[0]) & 255 for value in raw[1:])
    size, compressed = struct.unpack_from('<II', decoded)
    if compressed != len(decoded)-8 or not 0 < size <= 16*1024*1024:
        raise ValueError('KPD声明长度或审阅上限不符')
    plain = lzokay.decompress(decoded[8:], size)
    if len(plain) != size:
        raise ValueError('实际解包长度不符')
    return plain, {'source': relative, 'source_size': len(raw), 'source_sha256': sha(raw),
                   'declared_size': size, 'decoded_sha256': sha(plain)}


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
        raise ValueError(f'区间不在当前EXE原始节内: {address:#x}')

    source = json.loads((BASE / '4080_IDA原证.json').read_text(encoding='utf-8'))
    annotations = json.loads((BASE / 'review_annotations.json').read_text(encoding='utf-8'))

    def compare(item, key):
        expected = bytes.fromhex(item['bytes_hex'])
        actual = read_va(int(item[key], 16), len(expected))
        return {'address': item[key], 'size': len(expected), 'equal': actual == expected,
                'idb_sha256': sha(expected), 'disk_sha256': sha(actual)}

    checks = [{'address': f['address'], 'chunks': [compare(c, 'start') for c in f['chunks']]}
              for f in source['functions']+source['code_ranges']]
    thunks = [compare(t, 'address') for t in source['thunks']]
    data = [compare(d, 'address') for d in source['data_ranges']]
    intervals = [chunk for f in checks for chunk in f['chunks']] + thunks + data
    failures = [interval for interval in intervals if not interval['equal']]
    report = {'disk_exe_sha256': sha(exe), 'idb_input_sha256': source['database_input_sha256'],
              'method': '只读PE节表VA映射；核验全部函数chunk、代码区间、跳板和虚表',
              'checks': checks, 'thunks': thunks, 'data_ranges': data,
              'all_equal': not failures, 'failures': failures}
    save(BASE / '4080_当前磁盘核验.json', report)
    disk = {item['address']: all(c['equal'] for c in item['chunks']) for item in checks}
    manifest = []
    for item in annotations['entries']:
        entry = dict(item)
        entry['disk_match'] = disk[item['address']]
        entry['evidence'] = '证据/4080_IDA原证.json/' + ('code_ranges/' if item['kind'] == 'code_range' else 'functions/') + item['address']
        manifest.append(entry)
    save(BASE.parent / '函数审阅清单.json', {'method': '人工范围逐项固定，完整原证不等于完整语义，按VA跨专题去重',
                                           'functions': [x for x in manifest if x['kind'] != 'code_range'],
                                           'code_ranges': [x for x in manifest if x['kind'] == 'code_range'],
                                           'counts': dict(Counter(x['status'] for x in manifest))})
    lines = ['// ============================================================================', '// 4080系列：逐函数范围与未知',
             '// ============================================================================', '// 完整原证及PE匹配不自动提升人工审阅状态。', '//']
    for item in manifest:
        lines.extend(['// '+item['address']+'  '+item['status'], '//   结论：'+item['conclusion'],
                      '//   未知：'+item['unknown'], '//   复用：'+('；'.join(item['reuse']) or '无')])
    (BASE.parent / '05_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    rich, rich_source = decode_kpd('Data/RichStr.kpd')
    anim, anim_source = decode_kpd('Data/Anim.kpd')
    wanted_text = set(range(216, 232)) | {262}
    texts = {}
    for block in rich.decode('big5', errors='strict').split('[ITEM]')[1:]:
        match = re.search(r'^\s*indx\s*=\s*(\d+)', block, re.M)
        if match and int(match[1]) in wanted_text:
            texts[match[1]] = block.strip()
    animations = {}
    for block in anim.decode('gbk', errors='strict').split('[ANIM]')[1:]:
        match = re.search(r'^\s*indx\s*=\s*(\d+)', block, re.M)
        if match and int(match[1]) in {9, 11, 14, 15, 16, 17}:
            # 注释位于下一节标记之前，不把下一动画的名称错贴到当前条目。
            animations[match[1]] = '\n'.join(line for line in block.strip().splitlines()
                                              if line.strip() and not line.lstrip().startswith('//'))
    if set(map(int, texts)) != wanted_text or len(animations) != 6:
        raise ValueError('资源摘录缺少指定文本或动画')
    save(BASE / '4080_资源摘要.json', {'sources': [rich_source, anim_source],
                                    'encoding': {'RichStr': 'Big5严格解码', 'Anim': 'GBK严格解码'},
                                    'selected_richstr': texts, 'selected_anim': animations})
    bad_lines = []
    for path in BASE.parent.glob('*.txt'):
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if line and not line.startswith('//'):
                bad_lines.append(f'{path.name}:{number}')
    print(json.dumps({'functions': len(source['functions']), 'code_ranges': len(source['code_ranges']),
                      'chunks': sum(len(f['chunks']) for f in source['functions']+source['code_ranges']),
                      'thunks': len(thunks), 'data': len(data), 'all_equal': not failures,
                      'status_counts': dict(Counter(x['status'] for x in manifest)),
                      'txt_bad_lines': bad_lines}, ensure_ascii=False))
    if failures or bad_lines:
        raise SystemExit('核验不通过，禁止宣称本批全部已匹配')


if __name__ == '__main__':
    main()
