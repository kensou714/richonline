"""只读当前 EXE，逐区间核验录像专题原证；仅在本专题写出审阅报告。"""
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
PARTIAL = {0x751770, 0x751E80, 0x752A00}
DEPENDENCY = {0x703F50, 0x79CB50}


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    exe = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', exe, 60)[0]
    count = struct.unpack_from('<H', exe, pe + 6)[0]
    optional_size = struct.unpack_from('<H', exe, pe + 20)[0]
    imagebase = struct.unpack_from('<I', exe, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', exe, pe + 24 + optional_size + 40*i + 8)
                for i in range(count)]

    def read_va(address, size):
        rva = address - imagebase
        for _, start, rawsize, offset in sections:
            if start <= rva and rva + size <= start + rawsize:
                return exe[offset + rva - start:offset + rva - start + size]
        raise ValueError(f'核验区间不在原始节内: {address:#x}')

    source = json.loads((BASE / '录像界面残留_IDA原证.json').read_text(encoding='utf-8'))

    def compare(item, key):
        original = bytes.fromhex(item['bytes_hex'])
        actual = read_va(int(item[key], 16), len(original))
        return {'address': item[key], 'size': len(original), 'equal': actual == original,
                'disk_sha256': sha(actual), 'idb_sha256': sha(original)}

    def check_functions(items):
        return [{'address': f['address'], 'scope': f['review_scope'],
                 'chunks': [compare(c, 'start') for c in f['chunks']]} for f in items]

    checks = check_functions(source['functions'])
    navigation = check_functions(source['dependency_functions'])
    thunks = [compare(x, 'address') for x in source['thunks']]
    data = [compare(x, 'address') for x in source['data_ranges']]
    intervals = [c for f in checks + navigation for c in f['chunks']] + thunks + data
    failures = [x for x in intervals if not x['equal']]
    report = {'idb_input_sha256': source['database_input_sha256'].upper(),
              'disk_exe_sha256': sha(exe),
              'method': '按 PE 节表逐 chunk、跳板及数据核验；不运行客户端，不改 IDB/EXE',
              'functions': checks, 'navigation_functions': navigation,
              'thunks': thunks, 'data_ranges': data, 'failures': failures,
              'all_equal': not failures}
    save(BASE / '录像界面残留_当前磁盘核验.json', report)

    def manifest_item(f, check, nav=False):
        address = int(f['address'], 16)
        status = ('仅导航' if nav else '局部审阅' if address in PARTIAL else
                  '依赖审阅' if address in DEPENDENCY else '已分析')
        unknown = ('I/O 排除导航，调用者及全部业务未恢复' if nav else
                   '非记录分支未完整审阅' if address in PARTIAL else
                   '仅覆盖本专题依赖范围，内部算法未完整展开' if address in DEPENDENCY else
                   '仅静态审阅；RCD 加载、写入和回放执行链未恢复')
        return {'address': f['address'], 'status': status,
                'review_status': 'full' if status == '已分析' else 'navigation' if nav else 'partial',
                'conclusion': f['review_scope'], 'scope': f['review_scope'],
                'unknown': unknown, 'evidence': '证据/录像界面残留_IDA原证.json',
                'disk_match': all(c['equal'] for c in check['chunks'])}

    entries = [manifest_item(f, check) for f, check in zip(source['functions'], checks)]
    nav_entries = [manifest_item(f, check, True)
                   for f, check in zip(source['dependency_functions'], navigation)]
    manifest = {'method': '完整原证不等于完整语义审阅；跨专题按 VA 去重',
                'functions': entries, 'navigation_functions': nav_entries,
                'counts': {status: sum(x['status'] == status for x in entries + nav_entries)
                           for status in ('已分析', '局部审阅', '依赖审阅', '仅导航')}}
    save(BASE.parent / '函数审阅清单.json', manifest)
    lines = ['// ============================================================================',
             '// 录像记录残留：逐函数审阅清单',
             '// ============================================================================',
             '// 所有函数保存完整伪代码、反汇编与 chunk 原证；以下单独限定语义审阅范围。',
             '// 532 字节仅证实为内存记录，不能推定为 RCD 磁盘记录。', '//']
    for item in entries + nav_entries:
        lines.extend(['// ' + item['address'] + '  ' + item['status'],
                      '//   结论：' + item['conclusion'],
                      '//   边界：' + item['unknown']])
    lines.extend(['//', '// 当前磁盘核验：证据/录像界面残留_当前磁盘核验.json',
                  '// 当前 EXE SHA256：' + sha(exe),
                  '// 数据库输入 SHA256：' + source['database_input_sha256'].upper(),
                  '// 整文件指纹不同；只有本专题逐区间核验结果可用于证明对应代码相同。'])
    (BASE.parent / '03_逐函数审阅清单.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({'functions': len(checks), 'navigation': len(navigation),
                      'chunks': sum(len(f['chunks']) for f in checks + navigation),
                      'thunks': len(thunks), 'data': len(data),
                      'counts': manifest['counts'], 'all_equal': report['all_equal']},
                     ensure_ascii=False))
    if failures:
        raise SystemExit('发现不一致区间，禁止声明本专题代码与当前磁盘全部相同')


if __name__ == '__main__':
    main()
