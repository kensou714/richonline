"""独立从当前 PE 原始区复算 Feast 原证字节、E9 桥和复用来源。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
BASE = Path(__file__).resolve().parent
SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def main():
    blob = (ROOT / 'RnClient.exe').read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError('磁盘 EXE 指纹变化')
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    base = struct.unpack_from('<I', blob, pe + 52)[0]
    optional = struct.unpack_from('<H', blob, pe + 20)[0]
    sections = []
    for index in range(struct.unpack_from('<H', blob, pe + 6)[0]):
        at = pe + 24 + optional + index * 40
        rva, size, offset = struct.unpack_from('<III', blob, at + 12)
        sections.append((base + rva, size, offset))

    def read(va, size):
        for start, count, offset in sections:
            relative = va - start
            if 0 <= relative and relative + size <= count:
                return blob[offset + relative:offset + relative + size]
        return None

    counts = dict(function_ranges=0, bridges=0, windows=0, source_hashes=0,
                  resource_rows=0)

    def identity(row):
        current = bytes.fromhex(row['idb_hex']) if row.get('idb_hex') is not None else None
        if current is not None and len(current) != row['size']:
            raise ValueError('原字节长度不符：' + row['va'])
        actual = read(int(row['va'], 16), row['size'])
        if actual is None:
            if row.get('disk_hex') is not None or row.get('matching') is not None:
                raise ValueError('非磁盘映射被当作已匹配：' + row['va'])
            return
        if current != actual or row.get('disk_hex') != actual.hex() or row.get('matching') is not True:
            raise ValueError('字节不符：' + row['va'])

    def record(row, require_chunks=True):
        for field in ('byte_ranges', 'chunk_byte_ranges'):
            if not row.get(field):
                if field == 'chunk_byte_ranges' and not require_chunks:
                    continue
                raise ValueError('函数缺少字节范围：' + row['va'])
            for item in row[field]:
                identity(item)
                counts['function_ranges'] += 1

    def bridges(rows):
        for row in rows:
            identity(row)
            raw = bytes.fromhex(row['idb_hex'])
            target = int(row['va'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            if len(raw) != 5 or raw[0] != 0xE9 or hex(target) != row['target']:
                raise ValueError('E9 桥不符：' + row['va'])
            counts['bridges'] += 1

    core = json.loads((BASE / 'core_raw.json').read_text('utf-8'))
    for row in core['functions']:
        record(row)
    bridges(core['thunks'])
    supplement = json.loads((BASE / 'supplemental_raw.json').read_text('utf-8'))
    for row in supplement['functions']:
        record(row)
    bridges(supplement['thunks'])
    context = json.loads((BASE / 'context_raw.json').read_text('utf-8'))
    for row in [context['switch_table']] + [item for block in context['contexts']
                                          for item in block['instructions']]:
        identity(row)
        counts['windows'] += 1
    table = bytes.fromhex(context['switch_table']['idb_hex'])
    if len(table) != 52:
        raise ValueError('13 槽 switch 表长度不符')
    dispatch = next(row for row in core['functions'] if row['va'] == '0x7d89d0')
    sites = {int(ins['va'], 16) for ins in dispatch['assembly']}
    if not set(struct.unpack('<13I', table)) <= sites:
        raise ValueError('switch 表入口不是已导出分派指令')
    reused = json.loads((BASE / 'reused_evidence.json').read_text('utf-8'))
    sources = {}
    for source, digest in reused['source_hashes'].items():
        source_blob = (ROOT / 'docs/逆向资料' / source).read_bytes()
        if hashlib.sha256(source_blob).hexdigest() != digest:
            raise ValueError('复用来源发生变化：' + source)
        sources[source] = json.loads(source_blob)
        counts['source_hashes'] += 1
    for row in reused['reused']:
        originals = {item['va']: item for item in sources[row['source']]['functions']}
        if originals.get(row['va']) != row['record']:
            raise ValueError('复用内容不符原来源：' + row['va'])
        record(row['record'], require_chunks=False)
    source_thunks = {row['va']: row for source in sources.values() for row in source['thunks']}
    for row in reused['thunks']:
        if source_thunks.get(row['va']) != row:
            raise ValueError('复用桥与原来源不符：' + row['va'])
    bridges(reused['thunks'])
    navigation = json.loads((BASE / 'navigation_raw.json').read_text('utf-8'))
    windows = navigation['windows'] + [ref['bytes'] for target in navigation['targets']
                                      for ref in target['references'] if ref['bytes']]
    for row in windows:
        identity(row)
        counts['windows'] += 1
    for group in navigation['targets']:
        for edge in group['references']:
            if not edge['bridge']:
                continue
            raw = read(int(edge['site'], 16), 5)
            if raw is None or raw[0] != 0xE9:
                raise ValueError('导航桥未映射或不是 E9：' + edge['site'])
            target = int(edge['site'], 16) + 5 + int.from_bytes(raw[1:], 'little', signed=True)
            if hex(target) != edge['target']:
                raise ValueError('导航桥目标不符：' + edge['site'])

    import lzokay

    resource = json.loads((BASE / 'resource_raw.json').read_text('utf-8'))
    package = (ROOT / resource['source']).read_bytes()
    if hashlib.sha256(package).hexdigest() != resource['source_sha256']:
        raise ValueError('Feast 包来源变化')
    key = package[0]
    size, packed = struct.unpack('<II', bytes((byte - key) & 255 for byte in package[1:9]))
    decoded = lzokay.decompress(bytes((byte - key) & 255 for byte in package[9:9 + packed]), size)
    expected = dict(source_size=len(package), key=key, packed_size=packed,
                    tail_size=len(package) - 9 - packed, decoded_size=len(decoded),
                    decoded_sha256=hashlib.sha256(decoded).hexdigest(), decoded_hex=decoded.hex())
    if len(decoded) != size or any(resource.get(field) != value for field, value in expected.items()):
        raise ValueError('Feast 解包元数据或原字节不符')
    if len(decoded) % 26 or resource['record_size'] != 26:
        raise ValueError('Feast 样本记录步长不符')
    rows = [dict(index=offset // 26, offset=offset, year_by_lookup=2004 + offset // 26,
                 raw_hex=decoded[offset:offset + 26].hex(),
                 pairs=[dict(slot=slot, month=decoded[offset + 2 * slot],
                             day=decoded[offset + 2 * slot + 1]) for slot in range(13)])
            for offset in range(0, len(decoded), 26)]
    if rows != resource['rows']:
        raise ValueError('Feast 精确记录字节或日期对转录不符')
    counts['resource_rows'] = len(rows)
    review = json.loads((BASE / 'function_review.json').read_text('utf-8'))
    expected_vas = {row['va'] for row in core['functions'] + supplement['functions']}
    expected_vas.update(row['va'] for row in reused['reused'])
    expected_vas.update(row['owner'] for row in context['contexts'])
    actual_vas = [row['va'] for row in review['functions']]
    if len(actual_vas) != len(set(actual_vas)) or set(actual_vas) != expected_vas:
        raise ValueError('审阅清单遗漏或重复原证入口')
    from collections import Counter

    if dict(Counter(row['status'] for row in review['functions'])) != review['counts']:
        raise ValueError('审阅清单状态计数不符')
    for row in review['functions']:
        if not row['conclusion'] or not row['unknown'] or row['full_dependency_closure']:
            raise ValueError('局部结论边界缺失：' + row['va'])
        for path in row['evidence']:
            if not (ROOT / 'docs/逆向资料' / path).is_file():
                raise ValueError('审阅证据路径缺失：' + path)
    counts['review_entries'] = len(actual_vas)
    output = dict(status='PASS', disk_sha256=SHA256, counts=counts,
                  boundary='只验证保留原证与当前磁盘及来源对应；旧复用未独立枚举声明尾块；不验证语义或实机行为')
    (BASE / 'validation.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(output, ensure_ascii=False))


if __name__ == '__main__':
    main()
