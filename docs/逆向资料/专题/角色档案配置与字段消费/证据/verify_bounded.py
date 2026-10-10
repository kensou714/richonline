"""完整声明块、桥、窗口和资源重核；字节一致不提升整函数语义覆盖。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x7f2c20, 0x7f2c40, 0x7f2c90, 0x629750, 0x6a25a0, 0x7f35f0, 0x7f3630}
SEEDS = FRESH | {0x6276a0, 0x6b7930, 0x646590}
REUSE = {
    '专题/TeachMode对象与消费者/证据/teachmode_raw.json': {0x6276a0, 0x6b7930},
    '专题/Avatar配置与角色图片/证据/supplement_raw.json': {0x646590},
    '专题/MapView配置记录与预览消费/证据/functions_raw.json': {0x622d50},
    '专题/角色1416字段来源/证据/functions.json': {0x693680},
    '专题/KoNews记录与消费者/证据/closure_raw.json': {0x627760},
    '专题/业务提示与期限映射/证据/followups.json': {0x6dba40},
    '专题/事件文字记录器/证据/resource_parser.json':
        {0x8191d0, 0x819220, 0x819250, 0x819470, 0x819660, 0x8198e0, 0x81ad50, 0x81ad80, 0x81b7f0},
    '专题/文本过滤与字码转换/证据/functions_raw.json': {0x627160, 0x64f000, 0x8190b0, 0x81b4c0},
    '专题/全局数值配置/证据/functions.json': {0x627120, 0x627140, 0x81ad10},
    '专题/二进制读写游标/证据/cursor_extensions.json': {0x91bd80},
}
REVIEWS = {
    0x6276a0: ('静态契约已审阅', '八字节单例懒分配、条件构造和A766D0发布；没有同步。'),
    0x7f2c20: ('静态契约已审阅', '只清根+4数组指针，不初始化+0容量。'),
    0x7f2c40: ('静态契约已审阅', '非空数组交91F7E0后清根+4；不重置容量，不逐元素析构。'),
    0x629750: ('静态契约已审阅', '先清数组，再按参数bit0删除对象；返回原this，ret4。'),
    0x7f2be0: ('静态契约已审阅', '完整60B回调：memset整条C84字节，再置+C80为FF。'),
    0x7f2c90: ('局部路径已核', '两遍ROLE扫描、max(indx,0)+1容量、C84记录和字段消费；缺键/越界未防护。'),
    0x6b7930: ('静态契约已审阅', '取根+4的index*C84+C81，符号扩展BYTE，ret4；无索引检查。'),
    0x6a25a0: ('静态契约已审阅', '运行时对象+28角色号转至角色根的性别查询；未核上层索引合法性。'),
    0x646590: ('静态契约已审阅', '只返回DWORD[this]；本专题调用窗口对应角色数组容量。'),
    0x7f35f0: ('静态契约已审阅', '调用共享资源根6DBA40，参数为type8、角色号、selector9、-1；仅查询编号。'),
    0x7f3630: ('静态契约已审阅', '同一资源查询，selector10；不读取角色档案数组，不证明播放。'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class Image:
    def __init__(self):
        self.data = (ROOT / 'RnClient.exe').read_bytes()
        assert sha(self.data) == SHA
        nt = struct.unpack_from('<I', self.data, 60)[0]
        assert self.data[nt:nt + 4] == b'PE\0\0'
        self.base = struct.unpack_from('<I', self.data, nt + 52)[0]
        table = nt + 24 + struct.unpack_from('<H', self.data, nt + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.data, table + 40 * i + 8)
                         for i in range(struct.unpack_from('<H', self.data, nt + 6)[0])]

    def read(self, va, size):
        offsets = [offset + va - self.base - rva for _, rva, raw_size, offset in self.sections
                   if 0 <= va - self.base - rva and va - self.base - rva + size <= raw_size]
        assert len(offsets) == 1, hex(va)
        return self.data[offsets[0]:offsets[0] + size]

    def check(self, row):
        start = row.get('start_va', row.get('va'))
        data = self.read(int(start, 16), row['size'])
        assert row.get('matching', row.get('equal')) is True
        assert data.hex() == row.get('idb_hex', row.get('ida_hex')) == row['disk_hex'], start
        assert 'sha256' not in row or sha(data) == row['sha256']
        return dict(start_va=start, end_va=hex(int(start, 16) + len(data)), size=len(data), sha256=sha(data))


def adapt(raw, digest):
    functions = []
    for index, f in enumerate(raw['functions']):
        ranges = [dict(r, va=r['start_va']) for r in f['chunk_byte_ranges']]
        functions.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'],
                              status='仅导出；审阅另见分级清单',
                              assembly=[dict(r, va=r['site_va']) for r in f['assembly']],
                              pseudocode=f['pseudocode'], decompile_error=f['decompile_error'],
                              byte_ranges=ranges, bytes_match_disk=True,
                              declared_chunks=[dict(start_va=r['start_va'],
                                                    end_va=hex(int(r['start_va'], 16) + r['size']),
                                                    is_main=r['start_va'] == f['seed_va']) for r in ranges],
                              source='证据/bounded_raw.json', source_sha256=digest,
                              json_pointer=f'/functions/{index}'))
    return dict(schema='richonline-formal-functions-1', disk_sha256=SHA, source_sha256=digest,
                functions=functions, scope='机械适配保留全部汇编/原类型伪码/声明块；不自动认证语义',
                thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']])


def main():
    image = Image()
    content = (HERE / 'bounded_raw.json').read_bytes()
    raw, digest = json.loads(content), sha(content)
    assert raw['schema'] == 'richonline-bounded-preparation-1' and raw['disk_sha256'] == SHA
    assert raw['topic'] == HERE.parent.name
    assert sha((DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == raw['exporter_sha256']
    assert {int(f['seed_va'], 16) for f in raw['seeds']} == SEEDS
    audits = {int(f['seed_va'], 16): [image.check(r) for r in f['chunk_byte_ranges']]
              for f in raw['current_chunk_audits']}
    assert set(audits) == SEEDS and sum(map(len, audits.values())) == 12
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    for f in raw['functions']:
        checked = [image.check(r) for r in f['chunk_byte_ranges']]
        assert checked == audits[int(f['seed_va'], 16)]
        sites = [int(r['site_va'], 16) for r in f['assembly']]
        assert sites and len(sites) == len(set(sites)) and isinstance(f['pseudocode'], str) and f['pseudocode']
        assert all(any(int(r['start_va'], 16) <= s < int(r['end_va'], 16) for r in checked) for s in sites)
    for s in raw['reuse_sources']:
        path = DOCS / s['path']
        assert path.resolve().is_relative_to(DOCS.resolve()) and sha(path.read_bytes()) == s['source_sha256']
    bridges = {}
    def bridge(r, target_key):
        image.check(r)
        va = int(r.get('start_va', r.get('va')), 16)
        code = bytes.fromhex(r['idb_hex'])
        assert len(code) == 5 and code[0] == 0xe9
        target = va + 5 + struct.unpack_from('<i', code, 1)[0]
        assert target == int(r[target_key], 16)
        assert va not in bridges or bridges[va] == target
        bridges[va] = target
    for r in raw['verified_direct_bridges']:
        bridge(r, 'target_va')
    assert len(bridges) == 40
    for c in raw['calls']:
        target = int(c['target_va'], 16)
        for b in c['bridges']:
            assert target == int(b, 16)
            target = bridges[target]
        assert target == int(c['implementation_va'], 16)
        site = int(c['site_va'], 16)
        if image.read(site, 1) == b'\xe8':
            assert site + 5 + struct.unpack('<i', image.read(site + 1, 4))[0] == int(c['target_va'], 16)
    callback_bytes = (HERE / 'constructor_callback_raw.json').read_bytes()
    callback = json.loads(callback_bytes)
    assert callback['disk_sha256'] == SHA and len(callback['functions']) == 1
    f = callback['functions'][0]
    assert f['va'] == '0x7f2be0' and isinstance(f['pseudocode'], list)
    checked = [image.check(r) for r in f['chunk_byte_ranges']]
    assert sum(r['size'] for r in checked) == 60
    assert {(r['start_va'], r['end_va']) for r in checked} == {(r['start_va'], r['end_va']) for r in f['declared_chunks']}
    for r in callback['thunks']:
        bridge(r, 'target')
    # 6022CD为装载器传入的回调地址，原证保留实参及回调incoming；补核当前PE桥字节。
    callback_bridge_code = image.read(0x6022cd, 5)
    assert callback_bridge_code[0] == 0xe9
    bridges[0x6022cd] = 0x6022cd + 5 + struct.unpack_from('<i', callback_bridge_code, 1)[0]
    assert image.read(0x7f2e25, 5).hex() == '68cd226000'
    assert len(bridges) == 42 and bridges[0x6022cd] == 0x7f2be0 and bridges[0x60ffdb] == 0x920bf0
    reused = []
    for rel, selected in REUSE.items():
        payload = (DOCS / rel).read_bytes()
        obj, found = json.loads(payload), set()
        for i, f in enumerate(obj['functions']):
            va = int(f['va'], 16)
            if va not in selected:
                continue
            found.add(va)
            if 'instructions' in f:
                checked = [image.check(r) for r in f['chunks']]
                for r in f['instructions']:
                    assert image.read(int(r['va'], 16), r['size']).hex() == r['hex']
            else:
                checked = [image.check(r) for r in f.get('chunk_byte_ranges', f['byte_ranges'])]
                declared = f.get('declared_chunks', f.get('chunks'))
                assert {(r['start_va'], r['end_va']) for r in checked} == {(r['start_va'], r['end_va']) for r in declared}
            if va in SEEDS:
                assert checked == audits[va]
            reused.append(dict(owner_va=f['va'], source=rel, source_sha256=sha(payload),
                               json_pointer=f'/functions/{i}', chunks=checked,
                               scope='完整声明块当前字节重核；仅本专题路径/字段语义，不新增其他函数覆盖'))
        assert found == selected, (rel, selected - found)
    for rel, pointer in [
        ('专题/Grant全局配置与短消费/证据/grant_reused_raw.json', '/legacy_rechecked_functions/0'),
        ('专题/高扇入函数群筛选/证据/highfanout_raw.json', '/targets/0/function')]:
        payload = (DOCS / rel).read_bytes()
        f = json.loads(payload)
        for part in pointer.split('/')[1:]:
            f = f[int(part)] if isinstance(f, list) else f[part]
        checked = []
        for r in f.get('disk_ranges', f.get('chunks')):
            data = image.read(int(r['va'], 16), r['size'])
            assert data.hex() == r['disk_hex'] and sha(data) == r['sha256']
            if 'ida_hex' in r:
                assert r['equal'] is True and r['ida_hex'] == r['disk_hex']
            checked.append(dict(start_va=r['va'], end_va=hex(int(r['va'], 16) + r['size']), size=r['size'], sha256=sha(data)))
        for r in f['instructions']:
            assert image.read(int(r['va'], 16), r['size']).hex() == r['hex']
        reused.append(dict(owner_va=f['va'], source=rel, source_sha256=sha(payload), json_pointer=pointer,
                           chunks=checked, scope='旧完整块重核；仅游标重置/数组删除依赖'))
    candidates = list(raw['explicit_owner_windows'])
    for edges in raw['incoming'].values():
        candidates.extend(e['owner_window'] for e in edges if 'owner_window' in e)
    windows, seen, ownerless = [], set(), 0
    for w in candidates:
        if w['owner_va'] is None:
            assert not w['assembly']
            ownerless += 1
            continue
        checked = [image.check(r['bytes']) for r in w['assembly']]
        assert w['site_va'] in {r['start_va'] for r in checked}
        assert all(checked[i - 1]['end_va'] == checked[i]['start_va'] for i in range(1, len(checked)))
        key = (w['owner_va'], w['site_va'], checked[0]['start_va'], checked[-1]['end_va'])
        if key in seen:
            continue
        seen.add(key)
        windows.append(dict(owner_va=w['owner_va'], site=w['site_va'], start=checked[0]['start_va'],
                            end=checked[-1]['end_va'], window_status='仅有限窗口核验',
                            window_conclusion='仅参数/字段来源；不增加owner整函数覆盖'))
    strings = []
    for r in raw['data_windows']:
        image.check(r)
        if r['start_va'] in {'0xa766d0', '0xa69330'}:
            assert r['size'] == 4
            continue
        data = bytes.fromhex(r['idb_hex'])
        assert data[-1:] == b'\0' and b'\0' not in data[:-1]
        strings.append(dict(address=r['start_va'], text=data[:-1].decode('ascii'), size=r['size'], sha256=sha(data)))
    for r in raw['strings']:
        image.check(r['byte_audit'])
        assert r['unit_width'] == 1 and r['nul_hex'] == '00'
        assert r['byte_audit']['idb_hex'] == r['payload_hex'] + '00'
    path_rel = '专题/事件文字记录器/证据/data_audit.json'
    path_source = (DOCS / path_rel).read_bytes()
    path_row = json.loads(path_source)['records'][88]
    image.check(path_row)
    assert path_row['va'] == '0xa22164' and path_row['disk_hex'] == '446174615c526f6c652e6b706400'
    assert image.read(0x623bf2, 5).hex() == '686421a200'
    path_reference = dict(source=path_rel, source_sha256=sha(path_source), json_pointer='/records/88',
                          address='0xa22164', size=14, text='Data\\Role.kpd', caller_site='0x623bf2')
    resource_bytes = (HERE / 'resource_audit.json').read_bytes()
    resource = json.loads(resource_bytes)
    assert resource['status'] == 'PASS' and resource['source'] == 'Data/Role.kpd'
    assert sha((ROOT / resource['source']).read_bytes()) == resource['source_sha256']
    assert resource['role_section_count'] == resource['array_count'] == 9 and resource['array_bytes'] == 28836
    formal = adapt(raw, digest)
    save(HERE / 'formal_functions.json', formal)
    assert json.loads((HERE / 'formal_functions.json').read_bytes()) == adapt(raw, digest)
    save(HERE / 'reused_audit.json', dict(disk_sha256=SHA, references=reused, path=path_reference,
                                        callback=dict(source='constructor_callback_raw.json', source_sha256=sha(callback_bytes),
                                                      json_pointer='/functions/0', chunks=[image.check(r) for r in callback['functions'][0]['chunk_byte_ranges']],
                                                      argument_source_pointer='/data_references/7', argument_site='0x7f2e25',
                                                      bridge_current_pe=dict(va='0x6022cd', size=5, disk_hex=callback_bridge_code.hex(),
                                                                             sha256=sha(callback_bridge_code), target='0x7f2be0',
                                                                             scope='当前PE直接桥重核，不伪称独立IDA采集')),
                                        scope='复用来源/指针/完整块可定位；CRT与运行时行为未闭合'))
    functions = [dict(va=hex(va), status=status, conclusion=conclusion,
                      evidence='证据/formal_functions.json' if va in FRESH else
                               '证据/constructor_callback_raw.json' if va == 0x7f2be0 else '证据/reused_audit.json',
                      scope='完整声明块内的限定契约或局部路径',
                      unknown='实机、线程、损坏资源和其他消费者未验证；不提升为全面语义覆盖')
                 for va, (status, conclusion) in REVIEWS.items()]
    assert all({'va', 'status', 'conclusion'}.isdisjoint(w) for w in windows)
    save(HERE.parent / '函数审阅清单.json', dict(disk_sha256=SHA, raw_source_sha256=digest,
                                                functions=functions, windows=windows))
    for p in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in p.read_text(encoding='utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=SHA, raw_source_sha256=digest, fresh_functions=7, reused_seeds=3,
                  current_chunks=12, verified_e9_bridges=40, supplemental_functions=1, supplemental_chunks=1,
                  supplemental_e9_bridges=2, unique_e9_bridges=len(bridges), raw_window_records=len(candidates),
                  finite_windows=len(windows), ownerless_window_records=ownerless, strings=strings,
                  callback_source_sha256=sha(callback_bytes), dependency_functions=len(reused), path=path_reference,
                  resource_audit=dict(source=resource['source'], source_sha256=resource['source_sha256'],
                                      plain_sha256=resource['plain_sha256'], audit_sha256=sha(resource_bytes),
                                      script_sha256=sha((HERE / 'resource_audit.py').read_bytes())),
                  review_levels={'静态契约已审阅': 10, '局部路径已核': 1},
                  formal_adapter_equivalent=True, doc_format_passed=True,
                  boundary='字节身份不等于完整语义或运行时验收；缺键/越界/线程/CRT仍保留边界')
    save(HERE / 'bounded_audit.json', result)
    save(HERE.parent / '验证结果.json', {k: v for k, v in result.items() if k != 'strings'})
    print(json.dumps({k: result[k] for k in ['status', 'current_chunks', 'finite_windows', 'unique_e9_bridges']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
