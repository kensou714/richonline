"""只读解包当前Help资源，保留重复节与字节定位；不改资源。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    data = (ROOT / 'Data/Help.kpd').read_bytes()
    assert sha(data) == '1145a25a22698581623bc587666f5847e9d9a11588f11a5cfc1fbdccd1b78b39'
    key = data[0]
    raw_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in data[1:9]))
    assert len(data) == packed_size + 9 and 0 < raw_size < 1048576
    compressed = bytes((b - key) & 255 for b in data[9:])
    plain = lzokay.decompress(compressed, raw_size)
    assert len(plain) == raw_size
    assert sha(plain) == 'ab61d7ddd6a796278ce6f93584177241c35a1712c116ca38881beca00f387d68'
    decoded = plain.decode('cp950')
    assert decoded.encode('cp950') == plain
    sections, section, offset = [], None, 0
    for number, line in enumerate(plain.splitlines(keepends=True), 1):
        value = line.rstrip(b'\r\n')
        stripped = value.strip()
        if stripped.startswith(b'[') and stripped.endswith(b']'):
            section = dict(name=stripped[1:-1].decode('ascii'), source_line=number,
                           source_offset=offset, raw_line_hex=value.hex(), entries=[])
            sections.append(section)
        elif stripped and not stripped.startswith(b'//'):
            assert section is not None and b'=' in value, number
            raw_key, raw_value = value.split(b'=', 1)
            key_name = raw_key.strip().decode('ascii')
            payload = raw_value.lstrip(b' \t')
            section['entries'].append(dict(key=key_name, value_hex=payload.hex(),
                                           value=payload.decode('cp950'), source_line=number,
                                           source_offset=offset, raw_line_hex=value.hex(),
                                           value_offset=offset + len(raw_key) + 1 + len(raw_value) - len(payload)))
        offset += len(line)
    assert offset == len(plain) and len(sections) == 125
    def entries(s):
        result = {}
        for e in s['entries']:
            assert e['key'] not in result
            result[e['key']] = e
        return result
    categories = []
    for category, prefix, expected in [('OP', 'item', 13), ('RULE', 'item', 5)]:
        s = next(s for s in sections if s['name'] == category)
        es = entries(s)
        count = int(es['num']['value'])
        assert count == expected and set(es) == {'num'} | {prefix + str(i) for i in range(count)}
        values = [es[prefix + str(i)] for i in range(count)]
        assert all(len(bytes.fromhex(e['value_hex'])) + 1 <= 512 for e in values)
        categories.append(dict(category=category, count=count, continuous=True, capacity=512,
                               max_raw_value_bytes=max(len(bytes.fromhex(e['value_hex'])) for e in values),
                               loader='0x69c930' if category == 'OP' else '0x69cbb0'))
    for category, prefix, expected in [('EVENT', 'event', 26), ('NPC', 'npc', 20)]:
        s = next(s for s in sections if s['name'] == category)
        count = int(entries(s)['num']['value'])
        assert count == expected
        rows = [s for s in sections if s['name'].startswith(prefix)]
        assert [s['name'] for s in rows] == [prefix + str(i) for i in range(count)]
        all_entries = [entries(s) for s in rows]
        assert all(set(e) == {'id', 'name', 'desc'} for e in all_entries)
        assert all(len(bytes.fromhex(e['name']['value_hex'])) + 1 <= 64 and
                   len(bytes.fromhex(e['desc']['value_hex'])) + 1 <= 512 for e in all_entries)
        categories.append(dict(category=category, count=count, continuous=True, stride=580,
                               ids=[int(e['id']['value']) for e in all_entries],
                               max_name_bytes=max(len(bytes.fromhex(e['name']['value_hex'])) for e in all_entries),
                               max_desc_bytes=max(len(bytes.fromhex(e['desc']['value_hex'])) for e in all_entries),
                               loader='0x69ce30' if category == 'EVENT' else '0x69d190'))
    props = [s for s in sections if s['name'] == 'prop']
    assert len(props) == 75
    prop_entries = [entries(s) for s in props]
    assert all(set(e) == {'id', 'name'} for e in prop_entries)
    categories.append(dict(category='prop', count=75, repeated_section=True, stride=12,
                           ids=[int(e['id']['value']) for e in prop_entries],
                           ignored_resource_keys=['name'], loader='0x69d510',
                           text_source='外部627C20属性表；本资源name不被该loader读取'))
    result = dict(status='PASS', source='Data/Help.kpd', source_sha256=sha(data),
                  file_bytes=len(data), header_bytes=9, key=key, raw_size=raw_size, packed_size=packed_size,
                  plain_sha256=sha(plain), encoding='CP950严格往返；不证明运行时代码页',
                  cr=plain.count(b'\r'), lf=plain.count(b'\n'), nul=plain.count(b'\0'),
                  sections=sections, categories=categories,
                  scope='只读当前资源和结构约束；不模拟完整客户端解析器，不证明资源引用id有效或UI显示')
    (HERE / 'resource_audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// ============================================================================',
             '// 当前Help资源 / 原始文本与字段对照',
             '// ============================================================================',
             '// 数据只读解包自Data/Help.kpd；以下为CP950转写，保留重复节，展示省略尾空白。',
             '// 原值、尾空白和原行完整字节保存在resource_audit.json，不从展示文本回写资源。',
             '// 行号及解包后字节偏移见resource_audit.json；展示不证明客户端最终字码转换结果。',
             '// prop的name只供资源对照，本loader不消费该字段。', '//']
    prop_number = 0
    for s in sections:
        name = s['name']
        if name == 'prop':
            name += ' / 顺序' + str(prop_number)
            prop_number += 1
        lines += ['// ----------------------------------------------------------------------------',
                  '// ' + name + ' / 源行' + str(s['source_line'])]
        for e in s['entries']:
            lines.append('// ' + e['key'] + ' = ' + e['value'].rstrip())
    (HERE.parent / '06_当前资源文本对照.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(status='PASS', sections=len(sections), raw_size=raw_size,
                         categories={c['category']: c['count'] for c in categories}), ensure_ascii=False))


if __name__ == '__main__':
    main()
