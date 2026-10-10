"""只读Role包；保留重复节和原字节，只模拟已存在键的文本输出。"""
import hashlib
import json
import struct
from pathlib import Path

import lzokay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TEXT_FIELDS = [('name', 4, 16)] + [(key, 0x98 + i * 128, 128) for i, key in enumerate(
    ['enName', 'xingZuo', 'birthday', 'bloodType', 'age', 'shengXiao', 'height',
     'weight', 'work', 'interest', 'pet', 'favor', 'dislike', 'idol', 'language', 'tag'])] + [
    ('trait', 0x898, 200), ('introduce', 0x960, 800)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def copied_bytes(data):
    # 8198E0按高位字节复制双字节，反引号+n转换为LF；此模型不覆盖缺键/EOF。
    output, i = bytearray(), 0
    while i < len(data):
        if data[i] >= 128:
            assert i + 1 < len(data)
            output.extend(data[i:i + 2])
            i += 2
        elif data[i:i + 2] == b'`n':
            output.append(10)
            i += 2
        else:
            output.append(data[i])
            i += 1
    return bytes(output)


def main():
    data = (ROOT / 'Data/Role.kpd').read_bytes()
    assert sha(data) == 'd40e2ba5eea1f6bd162fbbc33f5891a89031de787a587212b334a5dcb33b50d2'
    key = data[0]
    raw_size, packed_size = struct.unpack('<II', bytes((b - key) & 255 for b in data[1:9]))
    assert len(data) == packed_size + 9 and 0 < raw_size < 1048576
    plain = lzokay.decompress(bytes((b - key) & 255 for b in data[9:]), raw_size)
    assert len(plain) == raw_size == 6397
    assert sha(plain) == 'cfff4a6e8d8a03532152562a8b09a816e9fc797b751505edcf429e01b1158df7'
    assert plain.decode('cp950').encode('cp950') == plain
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
            payload = raw_value.lstrip(b' \t')
            section['entries'].append(dict(key=raw_key.strip().decode('ascii'), value_hex=payload.hex(),
                                           value=payload.decode('cp950'), source_line=number,
                                           source_offset=offset, raw_line_hex=value.hex(),
                                           value_offset=offset + len(raw_key) + 1 + len(raw_value) - len(payload)))
        offset += len(line)
    assert offset == len(plain) and len(sections) == 9
    assert all(s['name'] == 'ROLE' for s in sections)
    roles = []
    for s in sections:
        entries = {e['key']: e for e in s['entries']}
        assert len(entries) == len(s['entries'])
        required = {'indx', 'mood', 'sex', 'landFlag'} | {f[0] for f in TEXT_FIELDS}
        assert required <= set(entries)
        capacities = []
        for name, field_offset, capacity in TEXT_FIELDS:
            copied = copied_bytes(bytes.fromhex(entries[name]['value_hex']))
            assert len(copied) + 1 <= capacity
            capacities.append(dict(key=name, offset=hex(field_offset), capacity=capacity,
                                   copied_hex=copied.hex(), copied_bytes=len(copied), with_nul=len(copied) + 1))
        count = 0
        while 'suit' + str(count) in entries:
            count += 1
        all_suit = sorted(int(k[4:]) for k in entries if k.startswith('suit'))
        roles.append(dict(index=int(entries['indx']['value']), mood=int(entries['mood']['value']),
                          name=entries['name']['value'], sex=entries['sex']['value'],
                          land_flag=int(entries['landFlag']['value']),
                          consumed_suit_keys=['suit' + str(i) for i in range(count)],
                          suit_values=[int(entries['suit' + str(i)]['value']) for i in range(count)],
                          ignored_suit_keys=['suit' + str(i) for i in all_suit if i >= count],
                          text_capacities=capacities))
    indices = [r['index'] for r in roles]
    count = max([0] + indices) + 1
    assert indices == list(range(9)) and count == 9
    assert [len(r['consumed_suit_keys']) for r in roles] == [17, 17, 16, 18, 17, 13, 10, 5, 17]
    result = dict(status='PASS', source='Data/Role.kpd', source_sha256=sha(data), file_bytes=len(data),
                  header_bytes=9, key=key, raw_size=raw_size, packed_size=packed_size, plain_sha256=sha(plain),
                  encoding='CP950严格往返；不证明运行时代码页或名称转换结果',
                  cr=plain.count(b'\r'), lf=plain.count(b'\n'), nul=plain.count(b'\0'),
                  sections=sections, roles=roles, role_section_count=len(sections), array_count=count,
                  array_bytes=count * 3204, duplicate_indices=[], negative_indices=[], missing_indices=[],
                  count_formula='max(0, 全部ROLE的atoi(indx))+1；当前样本恰为连续9项',
                  scope='只读现有键与容量；不模拟完整解析器、缺键越界、编码转换、UI和损坏包')
    (HERE / 'resource_audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// ============================================================================',
             '// 当前Role资源 / 原始文本与字段对照',
             '// ============================================================================',
             '// 只读Data/Role.kpd，CP950严格转写；原值与尾空白完整保存在resource_audit.json。',
             '// 原资源中的ASCII问号保持原样；展示不用于回写，也不证明客户端最终文本。',
             '// 9个ROLE，indx为0..8；容量9，记录总字节28836。缺键/损坏配置不在样本验证内。',
             '// suit首次缺键即停止；索引7缺suit5，后续suit7..16不会消费。', '//']
    for s, r in zip(sections, roles):
        lines += ['// ----------------------------------------------------------------------------',
                  '// ROLE / indx=' + str(r['index']) + ' / 源行' + str(s['source_line'])]
        for e in s['entries']:
            note = '  （该loader未消费）' if e['key'] in r['ignored_suit_keys'] else ''
            lines.append('// ' + e['key'] + ' = ' + e['value'].rstrip() + note)
    (HERE.parent / '06_当前资源文本对照.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(status='PASS', role_sections=len(sections), array_count=count,
                         array_bytes=count * 3204), ensure_ascii=False))


if __name__ == '__main__':
    main()
