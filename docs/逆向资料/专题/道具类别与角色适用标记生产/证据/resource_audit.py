"""当前Prop包只读解包；保留重复段、键顺序与原始字节，不模拟完整解析器。"""
import collections
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    source = (ROOT/'Data/Prop.kpd').read_bytes()
    assert sha(source) == '1d9c90b96f051af3a77105dc9baf3672f45f25bd37c865050b81bf81182e91d4'
    key = source[0]
    size, packed = struct.unpack('<II', bytes((x-key)&255 for x in source[1:9]))
    assert packed+9 == len(source) and 0 < size < 64*1024*1024
    plain = lzokay.decompress(bytes((x-key)&255 for x in source[9:]), size)
    assert len(plain) == size and sha(plain) == 'ae57f27ead85451fdbd686883e815c10da6083bde431534a449722f62409d067'
    text = plain.decode('cp950')
    assert text.encode('cp950') == plain
    sections, section, offset = [], None, 0
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        raw = line.rstrip(b'\r\n')
        stripped = raw.strip()
        if stripped.startswith(b'[') and stripped.endswith(b']'):
            section = dict(name=stripped[1:-1].decode('ascii'), source_line=number,
                           source_offset=offset, raw_line_hex=raw.hex(), entries=[])
            sections.append(section)
        elif stripped and not stripped.startswith(b'//'):
            assert section is not None and b'=' in raw, number
            field, value = raw.split(b'=', 1)
            field_name = field.strip().decode('ascii')
            payload = value.lstrip(b' \t')
            if field_name in ('indx','part') or re.fullmatch(r'ROLE[0-9]+', field_name):
                section['entries'].append(dict(key=field_name,value=payload.decode('cp950'),
                                               value_hex=payload.hex(),raw_line_hex=raw.hex(),
                                               source_line=number,source_offset=offset))
        offset += len(line)
    assert offset == len(plain) and len(sections) == 1117 and all(x['name']=='PROP' for x in sections)
    parts, role_keys, role_values, ids = collections.Counter(), collections.Counter(), collections.Counter(), []
    missing_part, repeated_keys = [], []
    for index, section in enumerate(sections):
        fields = collections.defaultdict(list)
        for entry in section['entries']: fields[entry['key']].append(entry)
        assert len(fields['indx']) == 1
        value = fields['indx'][0]['value']
        assert re.fullmatch(r'[0-9]+', value)
        ids.append(int(value))
        for field, entries in fields.items():
            if len(entries)>1: repeated_keys.append(dict(section=index,key=field,count=len(entries)))
        if 'part' in fields:
            for entry in fields['part']: parts[entry['value']]+=1
        else: missing_part.append(index)
        for field, entries in fields.items():
            if field.startswith('ROLE'):
                role_keys[field]+=len(entries)
                for entry in entries: role_values[entry['value']]+=1
    duplicate_ids = {str(k):v for k,v in collections.Counter(ids).items() if v>1}
    result = dict(status='PASS', source='Data/Prop.kpd', source_sha256=sha(source), source_size=len(source),
                  header_key=key, packed_size=packed, plain_size=size, plain_sha256=sha(plain),
                  encoding='CP950严格往返；GB18030也可往返，不据此推断实际ACP',
                  scope='仅保留indx/part/ROLE键原行；非完整客户端解析器仿真，样本取值不等于全部程序允许值',
                  section_count=len(sections), indices=ids, index_min=min(ids),index_max=max(ids),
                  duplicate_indices=duplicate_ids, repeated_selected_keys=repeated_keys,
                  missing_part_sections=missing_part, part_histogram=dict(parts),role_key_histogram=dict(role_keys),
                  role_value_histogram=dict(role_values),sections=sections)
    (HERE/'resource_audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    lines = ['// ============================================================================',
             '// 当前Prop资源 / part与ROLE键离线快照',
             '// ============================================================================',
             '// 原包Data/Prop.kpd，仅当前客户端根；不读上级旧客户端或部署副本。',
             '// 原包SHA256：'+sha(source), '// 解包SHA256：'+sha(plain),
             '// '+str(len(sections))+'个PROP物理段；indx范围'+str(min(ids))+'..'+str(max(ids))+'。',
             '// 原包'+str(len(source))+'B，解包'+str(size)+'B；全部目标键原行与字节偏移见resource_audit.json。',
             '// 显示采用CP950严格往返，另可GB18030往返；不证明游戏实际代码页。', '//',
             '// part样本分布，缺键段数'+str(len(missing_part))+'；不等同程序映射表全集。']
    lines += ['// '+name+' = '+str(count) for name,count in sorted(parts.items())]
    lines += ['//', '// ROLE键样本分布；缺键的客户端默认行为须另核loader。']
    lines += ['// '+name+' = '+str(count) for name,count in sorted(role_keys.items(),key=lambda x:int(x[0][4:]))]
    lines += ['// 目标值分布：'+json.dumps(dict(role_values),ensure_ascii=False),
              '// 重复indx数量：'+str(len(duplicate_ids))+'；目标键重复条目：'+str(len(repeated_keys))+'。',
              '// 这是物理文件事实；不证明加载成功、每条资源有效或各类别完整行为。']
    (HERE.parent/'06_当前Prop资源快照.txt').write_text('\n'.join(lines)+'\n','utf-8')
    print(json.dumps({k:result[k] for k in ('status','section_count','index_min','index_max','part_histogram','role_key_histogram','role_value_histogram')},ensure_ascii=True))


if __name__ == '__main__':
    main()
