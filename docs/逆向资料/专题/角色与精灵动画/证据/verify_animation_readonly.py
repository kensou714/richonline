"""只读核验动画专题的 IDA 函数区间，并提取当前 Anim.kpd 样本统计。"""
from pathlib import Path
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]

def sha(value):
    return hashlib.sha256(value).hexdigest().upper()

def main():
    raw = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', raw, 60)[0]
    count = struct.unpack_from('<H', raw, pe + 6)[0]
    optsize = struct.unpack_from('<H', raw, pe + 20)[0]
    imagebase = struct.unpack_from('<I', raw, pe + 52)[0]
    sections = [struct.unpack_from('<IIII', raw, pe + 24 + optsize + 40*i + 8) for i in range(count)]
    def disk_bytes(address, size):
        rva = address - imagebase
        for virtualsize, start, rawsize, offset in sections:
            if start <= rva and rva + size <= start + rawsize:
                return raw[offset + rva - start:offset + rva - start + size]
        raise ValueError(f'区间不在磁盘原始节数据内: {address:#x}, {size}')
    source = json.loads((BASE / '动画管理与骰子_IDA原始导出.json').read_text(encoding='utf-8'))
    checks = []
    for function in source['functions']:
        chunks = []
        for chunk in function['chunks']:
            original = bytes.fromhex(chunk['bytes_hex'])
            start = int(chunk['start'], 16)
            actual = disk_bytes(start, len(original))
            chunks.append({'start': chunk['start'], 'size': len(original),
                           'equal': original == actual, 'disk_sha256': sha(actual),
                           'differences': [{'va': hex(start+i), 'idb': a, 'disk': b}
                                           for i, (a,b) in enumerate(zip(original, actual)) if a != b]})
        checks.append({'address': function['address'], 'chunks': chunks})
    data_checks = []
    for item in source['data_tables']:
        original = bytes.fromhex(item['bytes_hex'])
        actual = disk_bytes(int(item['address'], 16), len(original))
        data_checks.append({'address': item['address'], 'size': len(original), 'equal': original == actual})
    result = {'idb_input_sha256': source['idb_input_sha256'], 'disk_exe_sha256': sha(raw),
              'method': '按 PE 节表逐函数所有 chunk 和数据表区间比较；未运行客户端',
              'function_count': len(checks), 'reviewed_count': len(source['reviewed']),
              'functions': checks, 'data_tables': data_checks}
    (BASE / '动画函数_当前磁盘核验.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    packed = (ROOT / 'Data' / 'Anim.kpd').read_bytes()
    if len(packed) < 9:
        raise ValueError('Anim.kpd 外层头不完整')
    key = packed[0]
    decoded_size, packed_size = struct.unpack('<II', bytes((b-key)&255 for b in packed[1:9]))
    if not 0 < decoded_size <= 64*1024*1024 or not 0 < packed_size <= len(packed)-9:
        raise ValueError('Anim.kpd 长度不合法或超过只读审计上限')
    decoded = lzokay.decompress(bytes((b-key)&255 for b in packed[9:9+packed_size]), decoded_size)
    if len(decoded) != decoded_size:
        raise ValueError('Anim.kpd 解压长度不符')
    content = decoded.decode('gbk', errors='strict')
    entries, current, caption = [], None, ''
    for line in content.splitlines():
        value = line.strip()
        if value.startswith('//'):
            caption = value[2:].strip()
        elif value == '[ANIM]':
            current = {'name_from_sample_comment': caption, 'surf': []}
            entries.append(current)
        elif '=' in value and current is not None:
            k, v = [part.strip() for part in value.split('=', 1)]
            if k in ('indx','time'):
                current[k] = int(v)
            elif k == 'free':
                current[k] = v
            elif k.startswith('surf_'):
                current['surf'].append({'key': k, 'value': v})
    sample = {'source': 'Data/Anim.kpd', 'source_sha256': sha(packed), 'size': len(packed),
              'key': key, 'packed_size': packed_size, 'decoded_size': decoded_size,
              'tail_size': len(packed)-9-packed_size, 'decoded_sha256': sha(decoded),
              'text_decoder': 'Python gbk strict；仅说明此样本可解码，不替代客户端 CP_ACP 语义',
              'entries': entries}
    (BASE / 'Anim_kpd_样本审计.json').write_text(json.dumps(sample, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (BASE / 'Anim_kpd_只读转录.txt').write_text('// Data/Anim.kpd 解包只读转录；原资源未改动。\n'+''.join('// '+line+'\n' for line in content.splitlines()), encoding='utf-8')
    names = {e['indx']: e for e in entries}
    navigation = ['// 47类动画导航：配置名称与静态函数表', '// ============================================================================',
                  '// 名称来自当前Anim.kpd原注释；不是对所有动作语义的独立复原。',
                  '// 虚函数顺序：启动 / 结束 / 更新并返回完成。地址均为解跳板后的VA。',
                  '// 0号已有深入正文；其余46类目前仅工厂与构造导航，不计语义覆盖。', '//']
    for row in source['factory_navigation']:
        entry = names[row['id']]
        navigation.extend([f"// {row['id']:02d}  {entry['name_from_sample_comment']}",
                           f"//   time={entry['time']}ms；free={entry.get('free', 'false（缺省）')}；对象大小={row['size']}",
                           f"//   工厂={row['factory']}；构造={row['constructor']}；虚表={row['vtable']}",
                           '//   启动/结束/更新='+' / '.join(v['target'] for v in row['virtuals']),
                           '//   surf='+(', '.join(s['value'] for s in entry['surf']) or '无'), '//'])
    (BASE.parent / '04_47类动画导航.txt').write_text('\n'.join(navigation)+'\n', encoding='utf-8')
    bad = [f['address'] for f in checks if any(not c['equal'] for c in f['chunks'])]
    print(json.dumps({'functions': len(checks), 'reviewed': len(source['reviewed']), 'chunks': sum(len(f['chunks']) for f in checks), 'mismatch_functions': bad, 'data_tables': len(data_checks), 'mismatch_tables': [d for d in data_checks if not d['equal']], 'sample_entries': len(entries), 'sample_free_true': sum(e.get('free') == 'true' for e in entries)}, ensure_ascii=False))

if __name__ == '__main__':
    main()
