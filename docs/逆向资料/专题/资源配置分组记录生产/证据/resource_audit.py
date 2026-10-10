"""只读当前Tex/other.dat；样本结构审计不替代客户端缺键或运行态契约。"""
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def inspect():
    data = (ROOT / 'Tex/other.dat').read_bytes()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    assert sha(data) == 'cce42c1439edfc1aa3e0a0c6ec7437b35628523dc2c70212a60bef68de0fe6e6'
    key = data[0]
    size, packed = struct.unpack('<II', bytes((x - key) & 255 for x in data[1:9]))
    assert packed + 9 == len(data) and size == 169979
    plain = lzokay.decompress(bytes((x - key) & 255 for x in data[9:]), size)
    assert sha(plain) == '84ebfcf29879012389c86aa9dcb14cbcc3d0a8bdd1bc3ba20d54732ac5ecde04'
    assert plain.decode('cp950').encode('cp950') == plain
    sections, section, offset = [], None, 0
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        raw = line.rstrip(b'\r\n')
        value = raw.strip()
        if value.startswith(b'[') and value.endswith(b']'):
            section = dict(name=value[1:-1].decode('ascii'), line=number, offset=offset, raw_hex=raw.hex(), entries=[])
            sections.append(section)
        elif value and not value.startswith(b'//'):
            assert section is not None and b'=' in raw
            k, v = raw.split(b'=', 1)
            section['entries'].append(dict(key=k.strip().decode('ascii'), value=v.strip().decode('cp950'), line=number, offset=offset, raw_hex=raw.hex()))
        offset += len(line)
    assert offset == size
    mapping = {s['name']: s for s in sections}
    assert len(mapping) == len(sections)
    groups = sorted(int(s['name'][6:]) for s in sections if re.fullmatch(r'OTHER_\d+', s['name']))
    assert groups == list(range(len(groups)))
    records = []
    for g in groups:
        items = []
        for i in range(100):
            name = 'O_%d_S_%d' % (g, i)
            if name not in mapping:
                break
            s = mapping[name]
            e = {r['key']: r for r in s['entries']}
            assert len(e) == len(s['entries']) and re.fullmatch(r'-?\d+', e['npid']['value'])
            items.append(dict(index=i, npid=int(e['npid']['value']), source_line=e['npid']['line'], source_offset=e['npid']['offset']))
        all_items = sorted(int(s['name'].rsplit('_', 1)[1]) for s in sections if re.fullmatch(r'O_' + str(g) + r'_S_\d+', s['name']))
        records.append(dict(group=g, loaded_prefix_count=len(items), configured_indices=all_items,
                            ignored_after_gap_or_limit=[i for i in all_items if i >= len(items)], items=items))
    return dict(status='PASS', source='Tex/other.dat', source_sha256=sha(data), file_bytes=len(data), key=key,
                packed_bytes=packed, plain_bytes=size, plain_sha256=sha(plain), encoding='CP950严格往返',
                group_count=len(groups), group_allocation_bytes=len(groups)*1200, sections=sections, groups=records,
                scope='样本按连续节及最多100项模型解析；不模拟客户端slot池初值、缺键残留、malloc失败或实际图像显示')


def main():
    result = inspect()
    (HERE / 'resource_audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('sections','groups')}, ensure_ascii=False))
    print('prefix_counts', [r['loaded_prefix_count'] for r in result['groups']])


if __name__ == '__main__':
    main()
