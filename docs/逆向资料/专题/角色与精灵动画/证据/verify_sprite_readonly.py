"""只读比较精灵补充批的全部函数chunk与当前磁盘EXE。"""
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]

def main():
    raw = (ROOT / 'RnClient.exe').read_bytes()
    pe = struct.unpack_from('<I', raw, 60)[0]
    n = struct.unpack_from('<H', raw, pe+6)[0]
    opt = struct.unpack_from('<H', raw, pe+20)[0]
    imagebase = struct.unpack_from('<I', raw, pe+52)[0]
    sections = [struct.unpack_from('<IIII', raw, pe+24+opt+40*i+8) for i in range(n)]
    result = {'disk_exe_sha256': hashlib.sha256(raw).hexdigest().upper(), 'sources': []}
    for name in ['角色精灵_IDA原始导出.json', '角色精灵_依赖原证.json']:
        source = json.loads((BASE / name).read_text(encoding='utf-8'))
        item = {'source': name, 'idb_input_sha256': source['idb_input_sha256'], 'functions': []}
        for function in source['functions']:
            chunks = []
            for chunk in function['chunks']:
                original = bytes.fromhex(chunk['bytes_hex'])
                rva = int(chunk['start'], 16)-imagebase
                found = [s for s in sections if s[1] <= rva and rva+len(original) <= s[1]+s[2]]
                if len(found) != 1:
                    raise ValueError('不能唯一映射区间'+chunk['start'])
                section = found[0]
                offset = section[3]+rva-section[1]
                actual = raw[offset:offset+len(original)]
                chunks.append({'start': chunk['start'], 'size': len(original), 'equal': actual == original,
                               'disk_sha256': hashlib.sha256(actual).hexdigest().upper()})
            item['functions'].append({'address': function['address'], 'chunks': chunks})
        result['sources'].append(item)
    (BASE / '角色精灵_当前磁盘核验.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    allchunks = [c for s in result['sources'] for f in s['functions'] for c in f['chunks']]
    print(json.dumps({'functions':sum(len(s['functions']) for s in result['sources']), 'chunks':len(allchunks), 'all_equal':all(c['equal'] for c in allchunks)},ensure_ascii=False))

if __name__ == '__main__':
    main()
