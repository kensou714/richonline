"""只读原始 EXE/资源，仅在本专题写出核验报告与脱敏摘要。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]

def sha(data):
    return hashlib.sha256(data).hexdigest().upper()

def save(name, value):
    (BASE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def main():
    exe = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', exe, 60)[0]
    count = struct.unpack_from('<H', exe, pe + 6)[0]
    optional_size = struct.unpack_from('<H', exe, pe + 20)[0]
    imagebase = struct.unpack_from('<I', exe, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', exe, pe + 24 + optional_size + 40*i + 8) for i in range(count)]
    def read_va(address, size):
        rva = address - imagebase
        for _, start, rawsize, offset in sections:
            if start <= rva and rva + size <= start + rawsize:
                return exe[offset + rva - start:offset + rva - start + size]
        raise ValueError(f'核验区间不在原始节内: {address:#x}')
    source = json.loads((BASE / '持久化_IDA原始导出.json').read_text(encoding='utf-8'))
    def compare(item, key):
        original = bytes.fromhex(item['bytes_hex'])
        actual = read_va(int(item[key], 16), len(original))
        return {'address': item[key], 'size': len(original), 'equal': actual == original,
                'disk_sha256': sha(actual)}
    checks = [{'address': f['address'], 'review_scope': f['review_scope'],
               'chunks': [compare(c, 'start') for c in f['chunks']]} for f in source['functions']]
    thunks = [compare(x, 'address') for x in source['dependency_thunks']]
    data = [compare(x, 'address') for x in source['data_ranges']]
    all_checks = [c for f in checks for c in f['chunks']] + thunks + data
    report = {'idb_input_sha256': source['database_input_sha256'], 'disk_exe_sha256': sha(exe),
              'method': '按 PE 节表核验所有导出函数 chunk、跳板与数据；未运行 EXE',
              'functions': checks, 'dependency_thunks': thunks, 'data_ranges': data,
              'all_equal': all(x['equal'] for x in all_checks)}
    save('持久化_当前磁盘核验.json', report)
    samples = []
    for filename in ['User.kpd', 'Private.kpd']:
        raw = (ROOT / 'Config' / filename).read_bytes()
        if len(raw) < 9:
            raise ValueError('容器头短于9字节')
        key = raw[0]
        rawlen, packedlen = struct.unpack('<II', bytes((v-key)&255 for v in raw[1:9]))
        if not 0 < rawlen <= 1024*1024 or not 0 < packedlen <= len(raw)-9:
            raise ValueError('容器声明长度越界或超出审计上限')
        content = lzokay.decompress(bytes((v-key)&255 for v in raw[9:9+packedlen]), rawlen)
        if len(content) != rawlen:
            raise ValueError('解压实际长度不符')
        item = {'source': 'Config/' + filename, 'source_size': len(raw), 'source_sha256': sha(raw),
                'raw_length': rawlen, 'packed_length': packedlen, 'tail_length': len(raw)-9-packedlen,
                'privacy': '不输出解包正文、账号、姓名或明文摘要'}
        if filename == 'User.kpd':
            nul = content.find(b'\0')
            item.update({'expected_fixed_length': 128, 'matches_expected_length': rawlen == 128,
                         'contains_nul': nul >= 0,
                         'bytes_after_first_nul_all_zero': all(v == 0 for v in content[nul+1:]) if nul >= 0 else None})
        else:
            # 只识别ASCII结构，不用猜测编码强行解释姓名。
            decodable = []
            for encoding in ('utf-8', 'gbk', 'cp950'):
                try:
                    content.decode(encoding, errors='strict')
                    decodable.append(encoding)
                except UnicodeDecodeError:
                    pass
            keys = []
            section = None
            for line in content.splitlines():
                line = line.strip()
                if line.startswith(b'[') and line.endswith(b']'):
                    section = line[1:-1]
                elif section == b'NAME' and b'=' in line and not line.startswith(b'//'):
                    keys.append(line.split(b'=', 1)[0].strip())
            item.update({'text_decode': '按ASCII字节识别节名和键，不解读姓名',
                         'strictly_decodable_candidates': decodable,
                         'name_section_key_count': len(keys),
                         'keys_are_contiguous_item_sequence': keys == [f'item{i}'.encode('ascii') for i in range(len(keys))]})
        samples.append(item)
    save('持久化样本_脱敏摘要.json', {'samples': samples})
    lines = ['// 持久化逐函数审阅清单', '// 完整导出不等于完整语义覆盖；局部审阅不得计为全函数完成。', '//']
    lines += ['// ' + f['address'] + '  ' + f['review_scope'] for f in source['functions']]
    (BASE.parent / '03_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    manifest = {'method': '完整和局部范围逐条明确；按VA跨专题去重；库代码不可混计游戏业务覆盖',
                'functions': [{'address': f['address'], 'review_status': 'partial' if f['review_scope'].startswith('局部') else 'full',
                               'status': '局部审阅' if f['review_scope'].startswith('局部') else ('库函数审阅' if '库代码' in f['review_scope'] else '已分析'),
                               'conclusion': f['review_scope'],
                               'unknown': '未覆盖的UI/网络行为见scope' if f['review_scope'].startswith('局部') else ('运行库环境读取，不计游戏业务覆盖' if '库代码' in f['review_scope'] else '仅静态分析，未做客户端动态回归'),
                               'scope': f['review_scope'], 'evidence': '证据/持久化_IDA原始导出.json',
                               'disk_match': all(c['equal'] for c in check['chunks'])}
                              for f, check in zip(source['functions'], checks)]}
    (BASE.parent / '函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'functions': len(checks), 'partial': sum(f['review_scope'].startswith('局部') for f in source['functions']),
                      'chunks': sum(len(f['chunks']) for f in checks), 'thunks': len(thunks), 'data': len(data),
                      'all_equal': report['all_equal'], 'samples': samples}, ensure_ascii=False))
    if not report['all_equal']:
        raise SystemExit('发现不一致区间，禁止宣称全部已匹配')

if __name__ == '__main__':
    main()
