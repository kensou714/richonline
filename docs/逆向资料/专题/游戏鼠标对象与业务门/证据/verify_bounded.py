"""离线检查鼠标对象原证、复用边界及机械适配；不连接IDA。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x6baac0, 0x6516e0, 0x651960, 0x653850}
REUSED = {0x6278f0, 0x6bad80, 0x691cc0}
REVIEWS = {
    0x6baac0: ('静态契约已审阅', '仅清this+0C长度190h并返回this；其余字节未写，底层清零实现未展开。'),
    0x6516e0: ('局部路径已核', '索引38、各门分支、门前650730副作用及8B提交字段已核；依赖业务含义和响应未闭合。'),
    0x651960: ('局部路径已核', '索引3、可改写目标、附加谓词、最终门和WORD目标已核；不推定领域名称。'),
    0x653850: ('局部路径已核', '索引18、槽25两分支及BYTE目标已核；已有槽分支绕过最终输入门。'),
    0x6278f0: ('静态契约已审阅', '复用完整主块与EH块：申请1AC、条件构造、全局发布和返回；不保证线程安全。'),
    0x6bad80: ('静态契约已审阅', '复用完整体：索引表选择、两缓存写入及SetCursor返回值分支；索引范围和初始化未闭合。'),
    0x691cc0: ('静态契约已审阅', '复用完整体：仅读首BYTE到AL，无写操作，高24位不代表布尔值。'),
    0x629890: ('静态契约已审阅', '完整声明块：先调用6BAB00，栈参数bit0决定delete；返回原this，ret4，不保证借用结束。'),
    0x6bab00: ('静态契约已审阅', '完整声明块：遍历100个DWORD槽，对非零值调用DeleteObject，忽略结果且不清槽；不保证句柄实际释放。'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class Image:
    def __init__(self):
        self.data = (ROOT / 'RnClient.exe').read_bytes()
        assert digest(self.data) == SHA
        self.nt = struct.unpack_from('<I', self.data, 60)[0]
        assert self.data[self.nt:self.nt + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', self.data, self.nt + 24)[0] == 0x10b
        self.base = struct.unpack_from('<I', self.data, self.nt + 52)[0]
        table = self.nt + 24 + struct.unpack_from('<H', self.data, self.nt + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.data, table + i * 40 + 8)
                         for i in range(struct.unpack_from('<H', self.data, self.nt + 6)[0])]

    def read(self, va, size):
        offsets = [offset + va - self.base - rva for _, rva, raw_size, offset in self.sections
                   if 0 <= va - self.base - rva and va - self.base - rva + size <= raw_size]
        assert len(offsets) == 1, hex(va)
        content = self.data[offsets[0]:offsets[0] + size]
        assert len(content) == size
        return content

    def check(self, row):
        start = row.get('start_va', row.get('va'))
        code = self.read(int(start, 16), row['size'])
        assert row['matching'] is True
        assert code.hex() == row['idb_hex'] == row['disk_hex'], start
        assert 'sha256' not in row or digest(code) == row['sha256']
        return dict(start_va=start, end_va=hex(int(start, 16) + len(code)),
                    size=len(code), sha256=digest(code))

    def string(self, va):
        data = bytearray()
        while (char := self.read(va + len(data), 1)) != b'\0':
            data += char
            assert len(data) < 1024
        return data.decode('ascii')

    def imports(self):
        imports = {}
        directory = self.base + struct.unpack_from('<I', self.data, self.nt + 24 + 104)[0]
        for index in range(1024):
            ilt, stamp, chain, name, iat = struct.unpack('<5I', self.read(directory + index * 20, 20))
            if not any((ilt, stamp, chain, name, iat)):
                return imports
            dll = self.string(self.base + name)
            for slot in range(65536):
                entry = struct.unpack('<I', self.read(self.base + (ilt or iat) + slot * 4, 4))[0]
                if entry == 0:
                    break
                symbol = f'ordinal:{entry & 0xffff}' if entry & 0x80000000 else self.string(self.base + entry + 2)
                imports[self.base + iat + slot * 4] = dll + '!' + symbol
        raise AssertionError('导入目录缺少终止符')


def adapt(raw, raw_sha):
    functions = []
    for index, f in enumerate(raw['functions']):
        ranges = [dict(row, va=row['start_va']) for row in f['chunk_byte_ranges']]
        functions.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'],
                              status='仅导出；审阅见分级清单',
                              assembly=[dict(row, va=row['site_va']) for row in f['assembly']],
                              pseudocode=f['pseudocode'], decompile_error=f['decompile_error'],
                              declared_chunks=[dict(start_va=r['start_va'],
                                                    end_va=hex(int(r['start_va'], 16) + r['size']),
                                                    is_main=r['start_va'] == f['seed_va']) for r in ranges],
                              byte_ranges=ranges, bytes_match_disk=True,
                              source='证据/bounded_raw.json', source_sha256=raw_sha,
                              json_pointer=f'/functions/{index}'))
    return dict(schema='richonline-formal-functions-1', disk_sha256=SHA,
                source_sha256=raw_sha, functions=functions,
                thunks=[dict(row, va=row['start_va'], target=row['target_va'])
                        for row in raw['verified_direct_bridges']],
                scope='纯机械适配；原始汇编、伪码及全部声明字节保留；不是语义认证')


def main():
    image = Image()
    raw_bytes = (HERE / 'bounded_raw.json').read_bytes()
    raw, raw_sha = json.loads(raw_bytes), digest(raw_bytes)
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert raw['disk_sha256'] == SHA and raw['topic'] == HERE.parent.name
    assert digest((DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == raw['exporter_sha256']
    assert {int(s['seed_va'], 16) for s in raw['seeds']} == FRESH | REUSED
    audits = {int(f['seed_va'], 16): [image.check(r) for r in f['chunk_byte_ranges']]
              for f in raw['current_chunk_audits']}
    assert set(audits) == FRESH | REUSED
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    assert {int(f['seed_va'], 16) for f in raw['reused_seeds']} == REUSED
    for f in raw['functions']:
        ranges = [image.check(r) for r in f['chunk_byte_ranges']]
        assert ranges == audits[int(f['seed_va'], 16)]
        sites = [int(row['site_va'], 16) for row in f['assembly']]
        assert sites and len(sites) == len(set(sites)) and f['pseudocode']
        assert all(any(int(r['start_va'], 16) <= site < int(r['end_va'], 16) for r in ranges) for site in sites)
    sources = []
    for s in raw['reuse_sources']:
        path = DOCS / s['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert digest(path.read_bytes()) == s['source_sha256']
        sources.append(dict(path=s['path'], sha256=s['source_sha256'], scope='只核来源完整性'))
    helper_path = DOCS / '专题/40B0系列事件/证据/request_helpers.json'
    helpers = json.loads(helper_path.read_bytes())
    reuse = []
    for index, f in enumerate(helpers['functions']):
        if int(f['va'], 16) not in REUSED:
            continue
        checked = [image.check(r) for r in f['byte_ranges']]
        assert checked == audits[int(f['va'], 16)]
        assert {(r['start_va'], r['end_va']) for r in checked} == {(r['start_va'], r['end_va']) for r in f['declared_chunks']}
        reuse.append(dict(seed_va=f['va'], source=str(helper_path.relative_to(DOCS)).replace('\\', '/'),
                          source_sha256=digest(helper_path.read_bytes()), json_pointer=f'/functions/{index}',
                          current_chunks=checked, scope='完整原文复用；当前全部声明块一致'))
    assert len(reuse) == 3
    bridges = {}
    for b in raw['verified_direct_bridges']:
        image.check(b)
        va = int(b['start_va'], 16)
        code = bytes.fromhex(b['idb_hex'])
        assert len(code) == 5 and code[0] == 0xe9
        target = va + 5 + struct.unpack_from('<i', code, 1)[0]
        assert target == int(b['target_va'], 16) and va not in bridges
        bridges[va] = target
    for c in raw['calls']:
        target = int(c['target_va'], 16)
        for b in c['bridges']:
            assert target == int(b, 16)
            target = bridges[target]
        assert target == int(c['implementation_va'], 16)
        site = int(c['site_va'], 16)
        if image.read(site, 1) == b'\xe8':
            assert site + 5 + struct.unpack('<i', image.read(site + 1, 4))[0] == int(c['target_va'], 16)
    windows = []
    candidates = list(raw['explicit_owner_windows'])
    for edges in raw['incoming'].values():
        candidates.extend(edge['owner_window'] for edge in edges if 'owner_window' in edge)
    for w in candidates:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        ranges = [image.check(row['bytes']) for row in w['assembly']]
        assert ranges and w['site_va'] in {r['start_va'] for r in ranges}
        assert all(ranges[i - 1]['end_va'] == ranges[i]['start_va'] for i in range(1, len(ranges)))
        windows.append(dict(owner_va=w['owner_va'], start=ranges[0]['start_va'], end=ranges[-1]['end_va'],
                            site=w['site_va'], window_status='仅有限窗口核验',
                            window_conclusion='字节与局部调用点已核；不代表owner完整语义'))
    for row in raw['data_windows']:
        image.check(row)
    assert image.read(0xa766c0, 4) == bytes(4)
    imported = image.imports()
    assert imported[0xad3f88].lower() == 'user32.dll!setcursor'
    assert image.read(0x6badd6, 6).hex() == 'ff15883fad00'
    input_path = DOCS / '专题/输入与快捷键/ida_input_raw.json'
    inputs = json.loads(input_path.read_bytes())
    input_checks = []
    for key, f in inputs['functions'].items():
        if int(f['ea'], 16) not in {0x7a47b0, 0x7a29e0}:
            continue
        for r in f['ranges']:
            code = bytes.fromhex(r['idb_bytes_hex'])
            assert image.read(int(r['start'], 16), len(code)) == code
        input_checks.append(dict(owner_va=f['ea'], source_sha256=digest(input_path.read_bytes()),
                                 json_pointer=f'/functions/{key}', scope='完整旧块字节一致；语义仅指定输入门路径'))
    assert len(input_checks) == 2
    shutdown_path = DOCS / '专题/事件文字记录器/证据/shutdown.json'
    shutdown = json.loads(shutdown_path.read_bytes())
    exit_f = next(f for f in shutdown['functions'] if f['va'] == '0x624080')
    exit_chunks = [image.check(r) for r in exit_f['chunk_byte_ranges']]
    supplemental = []
    supplemental_evidence = {}
    for name in ['exit_dependency_raw.json', 'destructor_raw.json']:
        content = (HERE / name).read_bytes()
        obj = json.loads(content)
        assert obj['disk_sha256'] == SHA
        for index, f in enumerate(obj['functions']):
            checked = [image.check(r) for r in f['chunk_byte_ranges']]
            assert {(r['start_va'], r['end_va']) for r in checked} == {(r['start_va'], r['end_va']) for r in f['declared_chunks']}
            supplemental_evidence[int(f['va'], 16)] = '证据/' + name
            supplemental.append(dict(seed_va=f['va'], source=name, source_sha256=digest(content),
                                     json_pointer=f'/functions/{index}', current_chunks=checked))
        for b in obj['thunks']:
            image.check(b)
            va = int(b['va'], 16)
            code = bytes.fromhex(b['idb_hex'])
            assert len(code) == 5 and code[0] == 0xe9
            assert va + 5 + struct.unpack_from('<i', code, 1)[0] == int(b['target'], 16)
    assert image.read(0x60def7, 5).hex() == 'e994b90100'
    assert imported[0xad3acc].lower() == 'gdi32.dll!deleteobject'
    assert image.read(0x6bab4a, 6).hex() == 'ff15cc3aad00'
    context_path = HERE / 'exit_owner_context.json'
    context = json.loads(context_path.read_bytes())
    assert context['disk_sha256'] == SHA
    exit_windows = []
    for w in context['windows']:
        image.check(w)
        for row in w['assembly']:
            image.check(dict(row['bytes'], start_va=row['site_va']))
        exit_windows.append(dict(owner_va=w['owner_va'], start=w['start_va'], end=w['end_va'],
                                 window_status='仅退出有限窗口', window_conclusion='两层前驱与释放实参已核，不计624080整函数覆盖'))
    semantic_sites = {
        0x6baace: '6890010000', 0x6baad8: '83c00c', 0x691cd1: '8a00',
        0x6bad9e: '3b448a0c', 0x6bada2: '743f', 0x6badb1: '89919c010000',
        0x6badc4: '8988a0010000', 0x7a47c4: '8808',
        0x651700: '6a26', 0x65197b: '6a03', 0x65388b: '6a12',
        0x651875: '668955f2', 0x651b5d: '668945e2',
        0x65398d: '8855ce', 0x653a24: '8845be',
        0x624a14: '6a01', 0x624a33: 'c705c066a70000000000',
        0x6298a9: '83e001', 0x6298ac: '740c', 0x6298ca: 'c20400',
        0x6bab2a: '837df864', 0x6bab2e: '7329', 0x6bab36: '837c8a0c00',
    }
    for va, code in semantic_sites.items():
        assert image.read(va, len(code) // 2).hex() == code, hex(va)
    formal = adapt(raw, raw_sha)
    save(HERE / 'formal_functions.json', formal)
    assert json.loads((HERE / 'formal_functions.json').read_bytes()) == adapt(raw, raw_sha)
    functions = [dict(va=hex(va), status=status, conclusion=conclusion,
                      evidence=('证据/formal_functions.json' if va in FRESH else
                                supplemental_evidence.get(va, '证据/reused_audit.json')),
                      scope='完整声明块内的限定静态契约或局部路径',
                      unknown='无实机；初始化写者、业务依赖和线程行为未闭合')
                 for va, (status, conclusion) in REVIEWS.items()]
    assert all({'va', 'status', 'conclusion'}.isdisjoint(w) for w in windows)
    save(HERE / 'reused_audit.json', dict(disk_sha256=SHA, reused_seeds=reuse,
                                        input_paths=input_checks, exit_owner_chunks=exit_chunks,
                                        exit_source_sha256=digest(shutdown_path.read_bytes()),
                                        supplemental=supplemental,
                                        exit_context_source_sha256=digest(context_path.read_bytes()),
                                        boundary='624080只核退出局部语义；不作为整函数审阅'))
    save(HERE.parent / '函数审阅清单.json', dict(disk_sha256=SHA, raw_source_sha256=raw_sha,
                                                functions=functions, windows=windows + exit_windows))
    result = dict(status='PASS', disk_sha256=SHA, raw_source_sha256=raw_sha,
                  fresh_functions=4, reused_seeds=3, current_chunks=sum(len(r) for r in audits.values()),
                  verified_e9_bridges=len(bridges), finite_windows=len(windows),
                  raw_window_records=len(candidates), ownerless_window_records=len(candidates) - len(windows),
                  supplemental_functions=2, supplemental_thunk_functions=1, exit_windows=len(exit_windows),
                  reuse_sources=sources, semantic_anchor_sites=[hex(v) for v in semantic_sites],
                  import_audit=[{'iat_va': '0xad3f88', 'symbol': imported[0xad3f88]},
                                {'iat_va': '0xad3acc', 'symbol': imported[0xad3acc]}],
                  review_levels={'静态契约已审阅': 6, '局部路径已核': 3},
                  formal_adapter_equivalent=True,
                  boundary='限定静态审阅；不证明实机触发、服务端响应或未知依赖行为')
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
    result['doc_format_passed'] = True
    save(HERE / 'bounded_audit.json', result)
    save(HERE.parent / '验证结果.json', {key: value for key, value in result.items() if key != 'reuse_sources'})
    print(json.dumps({key: result[key] for key in ['status', 'fresh_functions', 'reused_seeds', 'current_chunks', 'finite_windows']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
