"""只读解包候选与分组配置，区分磁盘存在、配置分组和运行时索引。"""
from pathlib import Path
from collections import Counter
import configparser
import hashlib
import json
import struct
import lzokay

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]

def unpack(name):
    raw = (ROOT/'Data'/name).read_bytes()
    packed = bytes((x-raw[0]) & 255 for x in raw[1:])
    n, m = struct.unpack_from('<II', packed)
    assert m == len(packed)-8
    plain = lzokay.decompress(packed[8:], n)
    assert len(plain) == n
    (BASE/(name+'.decoded.bin')).write_bytes(plain)
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(plain.decode('ascii').rstrip('\0'))
    metadata = dict(path='Data/'+name, source_size=len(raw), source_sha256=hashlib.sha256(raw).hexdigest(),
                    decoded_size=n, compressed_size=m, decoded_sha256=hashlib.sha256(plain).hexdigest(), key=raw[0])
    return parser, metadata

def main():
    candidates, random_meta = unpack('RandomMap.kpd')
    index, index_meta = unpack('MapList.kpd')
    membership = {}
    for section in index.sections():
        for key, value in index.items(section):
            membership.setdefault(value, []).append(dict(section=section, key=key))
    groups = []
    offsets = [0x548+16*i for i in range(9)]
    names = ['CM_SMALL','CM_BIG','CM_ALL','PK_SMALL','PK_BIG','PK_ALL','KO_SMALL','KO_BIG','KO_ALL']
    for name, offset in zip(names, offsets):
        entries = []
        section = candidates[name]
        serial = 1
        while 'map%02d' % serial in section:
            key = 'map%02d' % serial
            value = section[key]
            path = ROOT/'Map'/value.replace('\\','/')
            raw = path.read_bytes() if path.is_file() else None
            summary = None
            if raw is not None:
                mode_at = 16+4+0x5AE4
                summary = dict(file_size=len(raw), version_at_16=struct.unpack_from('<I',raw,16)[0] if len(raw)>=20 else None,
                               mode_offset=mode_at, mode=struct.unpack_from('<I',raw,mode_at)[0] if len(raw)>=mode_at+4 else None,
                               caveat='只按既有摘要契约读取版本和模式，不验证完整EMP')
            entries.append(dict(key=key, value=value, disk_path='Map/'+value, value_size=len(value.encode('ascii')), disk_exists=raw is not None,
                                disk_sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None,
                                emp_summary=summary, maplist_membership=membership.get(value, [])))
            serial += 1
        groups.append(dict(section=name, object_offset=hex(offset), count=len(entries),
                           first_missing_key='map%02d' % serial, unconsumed_keys=sorted(set(section)-{e['key'] for e in entries}),
                           entries=entries))
    result = dict(resources=[random_meta,index_meta], groups=groups, total_records=sum(g['count'] for g in groups),
                  unique_candidates=len({e['value'] for g in groups for e in g['entries']}),
                  missing_disk=sorted({e['value'] for g in groups for e in g['entries'] if not e['disk_exists']}),
                  not_in_maplist=sorted({e['value'] for g in groups for e in g['entries'] if not e['maplist_membership']}),
                  caveat='磁盘检查仅核Map目录松散文件，不核容器包；MapList配置成员不是运行时276字节表，后者还受EMP摘要、模式和目录扫描过滤。')
    (BASE/'resources.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    text = ['// RandomMap.kpd 解包原文；仅换为注释式阅读副本，精确字节见 decoded.bin。']
    text.extend('// '+line for line in (BASE/'RandomMap.kpd.decoded.bin').read_bytes().decode('ascii').rstrip('\0').splitlines())
    (BASE.parent/'05_候选配置原文.txt').write_text('\n'.join(text)+'\n','utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='groups'},ensure_ascii=True))
    print([(g['section'],g['count']) for g in groups])

if __name__ == '__main__':
    main()
