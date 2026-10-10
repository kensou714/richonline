"""6289C0专题独审：独立PE/资源检查及主IDA lease代跑的只读复读。"""
import hashlib
import json
import re
import struct
from pathlib import Path

import lzokay
import pefile

HERE = Path(__file__).resolve().parent.parent
ROOT = HERE.parents[3]
EVIDENCE = ('seed', 'lifetime', 'destructor', 'index', 'accessors')
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def doc(name):
    return json.loads((HERE / '证据' / (name + '.json')).read_text(encoding='utf-8'))


def functions():
    return [f for name in EVIDENCE for f in doc(name)['functions']]


def decode_kpd(path):
    raw = path.read_bytes()
    key = raw[0]
    header = bytes((byte - key) & 255 for byte in raw[1:9])
    size, packed = struct.unpack('<II', header)
    assert packed == len(raw) - 9 and 0 < size < 1024 * 1024
    plain = lzokay.decompress(bytes((byte - key) & 255 for byte in raw[9:]), size)
    assert len(plain) == size
    text = plain.decode('cp950', errors='strict')
    assert text.encode('cp950') == plain
    # 保留同名ITEM的文件顺序；普通字典解析器会吞掉重复段。
    sections = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('//') or line.startswith(';'):
            continue
        match = re.fullmatch(r'\[([^\]]+)\]', line)
        if match:
            sections.append((match.group(1), {}))
            continue
        assert sections and '=' in line
        key, value = (part.strip() for part in line.split('=', 1))
        assert key not in sections[-1][1]
        sections[-1][1][key] = value
    return raw, plain, sections


def offline():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    pe = pefile.PE(data=image, fast_load=True)
    assert pe.OPTIONAL_HEADER.Magic == 0x10B
    base = pe.OPTIONAL_HEADER.ImageBase

    def read(va, size):
        rva = va - base
        section = pe.get_section_by_rva(rva)
        assert section is not None
        delta = rva - section.VirtualAddress
        assert 0 <= delta and delta + size <= section.SizeOfRawData
        offset = section.PointerToRawData + delta
        return image[offset:offset + size]

    assert read(0xA766E8, 4) == bytes(4)
    functions_seen, chunks, tail_chunks, compared, thunks = set(), 0, 0, {}, set()
    for name in EVIDENCE:
        data = doc(name)
        assert data['disk_sha256'] == SHA
        for f in data['functions']:
            va = int(f['va'], 16)
            assert va not in functions_seen
            functions_seen.add(va)
            chunk_spans = {(int(c['start_va'], 16), int(c['end_va'], 16)) for c in f['declared_chunks']}
            assert len(chunk_spans) == len(f['declared_chunks'])
            chunks += len(chunk_spans)
            tail_chunks += sum(not c['is_main'] for c in f['declared_chunks'])
            for r in f['chunk_byte_ranges']:
                start = int(r['va'], 16)
                assert (start, start + r['size']) in chunk_spans
            for r in f['byte_ranges'] + f['chunk_byte_ranges']:
                va_r = int(r['va'], 16)
                raw = read(va_r, r['size'])
                assert raw.hex() == r['idb_hex'] == r['disk_hex']
                for i, byte in enumerate(raw):
                    old = compared.setdefault(va_r + i, byte)
                    assert old == byte
        for r in data.get('thunks', []):
            va_r = int(r['va'], 16)
            raw = read(va_r, r['size'])
            assert raw.hex() == r['idb_hex'] == r['disk_hex']
            assert r['size'] == 5 and raw[0] == 0xE9
            assert va_r + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(r['target'], 16)
            thunks.add(va_r)
            for i, byte in enumerate(raw):
                old = compared.setdefault(va_r + i, byte)
                assert old == byte
    assert (len(functions_seen), chunks, tail_chunks, len(compared), len(thunks)) == (12, 15, 3, 3146, 32)

    navigation = doc('navigation')
    assert navigation['disk_sha256'] == SHA
    assert navigation['global_va'] == '0xa766e8' and navigation['global_idb_hex'] == '00000000'
    calls = navigation['calls']
    assert len(calls) == 22
    for call in calls:
        site = int(call['site'], 16)
        raw = read(site, 5)
        assert raw[0] == 0xE8
        assert site + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(call['target'], 16)
    for r in navigation['observed_e9_navigation']:
        site = int(r['va'], 16)
        raw = read(site, 5)
        assert raw.hex() == r['idb_hex'] and raw[0] == 0xE9
        assert site + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(r['target'], 16)

    interfaces = doc('interface_navigation')
    assert interfaces['disk_sha256'] == SHA
    for window in interfaces['windows']:
        r = window['bytes']
        assert read(int(r['va'], 16), r['size']).hex() == r['idb_hex'] == r['disk_hex']

    resources = {}
    for filename, evidence in (('Level.kpd', 'resource'), ('VipLev.kpd', 'vip_resource')):
        raw, plain, sections = decode_kpd(ROOT / 'Data' / filename)
        saved = doc(evidence)
        assert len(raw) == saved['source_size'] and hashlib.sha256(raw).hexdigest() == saved['source_sha256']
        assert len(plain) == saved['decoded_size'] and hashlib.sha256(plain).hexdigest() == saved['decoded_sha256']
        assert [(s['name'], s['fields']) for s in saved['sections']] == sections
        resources[filename] = dict(source_size=len(raw), decoded_size=len(plain), sections=len(sections))
    levels = doc('resource')['sections']
    assert levels[0]['name'] == 'all' and int(levels[0]['fields']['num']) == 21
    assert [row['name'] for row in levels[1:]] == [f'level{i}' for i in range(21)]
    assert [int(row['fields']['exp']) for row in levels[1:]][-1] == 15000
    vips = doc('vip_resource')['sections']
    assert [row['name'] for row in vips] == ['ITEM'] * 4
    assert [int(row['fields']['level']) for row in vips] == list(range(4))
    assert vips[0]['fields']['icon'] == 'NULL'
    result = dict(status='PASS', exe_sha256=SHA, functions=len(functions_seen), chunks=chunks,
                  tail_chunks=tail_chunks, union_bytes=len(compared), thunks=len(thunks),
                  direct_calls=len(calls), interface_windows=len(interfaces['windows']),
                  global_initial_hex=read(0xA766E8, 4).hex(), resources=resources,
                  ida_live_result_present=(HERE / '证据' / 'independent_ida.json').exists(),
                  scope='独立PE32映射与资源解码；不执行客户端或推断异常路径')
    if result['ida_live_result_present']:
        live = doc('independent_ida')
        assert live['status'] == 'PASS' and not live['failures']
    (HERE / '证据' / 'independent_offline.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return result


def audit(db):
    import ida_bytes

    failures = []
    summary = []
    for f in functions():
        va = int(f['va'], 16)
        function = db.functions.get_at(va)
        live_chunks = list(db.functions.get_chunks(function))
        expected = [(int(c['start_va'], 16), int(c['end_va'], 16)) for c in f['declared_chunks']]
        actual = [(c.start_ea, c.end_ea) for c in live_chunks]
        if expected != actual:
            failures.append(f['va'] + ': 声明块不同')
        heads = {i.ea for c in live_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)
                 if ida_bytes.is_code(ida_bytes.get_full_flags(i.ea))}
        if heads != {int(i['va'], 16) for i in f['assembly']}:
            failures.append(f['va'] + ': 代码头不同')
        for r in f['byte_ranges'] + f['chunk_byte_ranges']:
            raw = db.bytes.get_bytes_at(int(r['va'], 16), r['size'])
            if raw.hex() != r['idb_hex']:
                failures.append(r['va'] + ': 原字节不同')
        summary.append(dict(va=f['va'], chunks=len(actual), code_heads=len(heads)))
    for name in EVIDENCE:
        for r in doc(name).get('thunks', []):
            if db.bytes.get_bytes_at(int(r['va'], 16), r['size']).hex() != r['idb_hex']:
                failures.append(r['va'] + ': E9不同')
    for window in doc('interface_navigation')['windows']:
        r = window['bytes']
        if db.bytes.get_bytes_at(int(r['va'], 16), r['size']).hex() != r['idb_hex']:
            failures.append(r['va'] + ': 导航窗口不同')
    if db.bytes.get_bytes_at(0xA766E8, 4).hex() != '00000000':
        failures.append('0xA766E8: 初值不同')
    result = dict(status='PASS' if not failures else 'FAIL', failures=failures, functions=summary,
                  execution_provenance='独审者编写只读脚本，主级审读并持主IDA lease代跑；独审者未独立连接',
                  scope='12函数15块代码头与原字节、E9和导航窗口实时复读；非完整业务分析')
    (HERE / '证据' / 'independent_ida.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status=result['status'], functions=len(summary), failures=failures)


if __name__ == '__main__':
    offline()
