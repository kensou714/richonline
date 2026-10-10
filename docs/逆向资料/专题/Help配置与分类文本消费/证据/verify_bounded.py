"""复核Help固定种子与必要旧依赖；字节一致不自动提升语义等级。"""
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
FRESH = {0x69c740, 0x69c790, 0x69c880, 0x69c930, 0x69cbb0, 0x69ce30, 0x69d190, 0x69d510, 0x629480}
SEEDS = FRESH | {0x628a80}
REUSE = {
    '专题/TeachMode对象与消费者/证据/teachmode_raw.json': {0x628a80, 0x627c20},
    '专题/40D0系列事件/证据/ui_helpers.json': {0x693370, 0x69dec0},
    '专题/事件文字记录器/证据/resource_parser.json':
        {0x8191d0, 0x819220, 0x819250, 0x819470, 0x819660, 0x8198e0, 0x81ad50, 0x81ad80, 0x81b7f0},
    '专题/文本过滤与字码转换/证据/functions_raw.json': {0x627160, 0x64f000, 0x8190b0, 0x81b4c0},
    '专题/全局数值配置/证据/functions.json': {0x627120, 0x627140, 0x81ad10},
    '专题/二进制读写游标/证据/cursor_extensions.json': {0x91bd80},
}
REVIEWS = {
    0x69c740: ('静态契约已审阅', '仅初始化+84/+90/+9C/+A8四个指针；不写第五指针+B4。'),
    0x69c790: ('静态契约已审阅', '四个非空指针依次交91F7E0并清零；不释放+B4，不重置计数或标志。'),
    0x69c880: ('静态契约已审阅', '仅复制固定路径、清五计数及五BYTE标志并返回1；不打开Help.kpd。'),
    0x629480: ('静态契约已审阅', '先调用69C790，再按参数bit0删除对象；ret4，返回原this不保证仍可解引用。'),
    0x628a80: ('静态契约已审阅', '复用完整主块/EH：BC分配、条件构造、A766F8发布与返回，未见同步。'),
    0x69c930: ('局部路径已核', 'OP/num与连续item键、512B槽、编码门及flag已核；没有index<count保护。'),
    0x69cbb0: ('局部路径已核', 'RULE/num与连续item键、512B槽和flag已核；缺键/解压安全性不外推。'),
    0x69ce30: ('局部路径已核', 'EVENT/num与eventN节、580B记录及资源引用/复制文本已核；依赖安全性未闭合。'),
    0x69d190: ('局部路径已核', 'NPC/num与npcN节、id=-1特例、580B记录及编码路径已核。'),
    0x69d510: ('局部路径已核', '重复prop两遍扫描、12B记录及外部名称/描述借用已核；第五数组所有权仍有缺口。'),
    0x69d8d0: ('静态契约已审阅', '完整短体：先触发OP装载，返回+84数组加index*512，无索引/空指针检查。'),
    0x69d910: ('静态契约已审阅', '完整短体：先触发RULE装载，返回+90数组加index*512，无索引/空指针检查。'),
    0x69d950: ('静态契约已审阅', '完整短体：先触发EVENT装载，返回+9C数组加index*580，无索引/空指针检查。'),
    0x69d990: ('静态契约已审阅', '完整短体：先触发NPC装载，返回+A8数组加index*580，无索引/空指针检查。'),
    0x69d9d0: ('静态契约已审阅', '完整短体：先触发prop装载，返回+B4数组加index*12，无索引/空指针检查。'),
}


def sha(content):
    return hashlib.sha256(content).hexdigest()


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
        data = self.data[offsets[0]:offsets[0] + size]
        assert len(data) == size
        return data

    def check(self, row):
        start = row.get('start_va', row.get('va'))
        data = self.read(int(start, 16), row['size'])
        assert row.get('matching', row.get('equal')) is True
        assert data.hex() == row['idb_hex'] == row['disk_hex'], start
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
                functions=functions, scope='机械字段适配；完整汇编、伪码和声明块保留；非自动语义认证',
                thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']])


def main():
    image = Image()
    content = (HERE / 'bounded_raw.json').read_bytes()
    raw, digest = json.loads(content), sha(content)
    assert raw['disk_sha256'] == SHA and raw['topic'] == HERE.parent.name
    assert raw['schema'] == 'richonline-bounded-preparation-1'
    assert sha((DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == raw['exporter_sha256']
    assert {int(f['seed_va'], 16) for f in raw['seeds']} == SEEDS
    audits = {int(f['seed_va'], 16): [image.check(r) for r in f['chunk_byte_ranges']]
              for f in raw['current_chunk_audits']}
    assert set(audits) == SEEDS
    assert {int(f['seed_va'], 16) for f in raw['functions']} == FRESH
    for f in raw['functions']:
        checked = [image.check(r) for r in f['chunk_byte_ranges']]
        assert checked == audits[int(f['seed_va'], 16)]
        sites = [int(r['site_va'], 16) for r in f['assembly']]
        assert len(sites) == len(set(sites)) and sites and f['pseudocode']
        assert all(any(int(r['start_va'], 16) <= site < int(r['end_va'], 16) for r in checked) for site in sites)
    sources = []
    for s in raw['reuse_sources']:
        path = DOCS / s['path']
        assert path.resolve().is_relative_to(DOCS.resolve())
        assert sha(path.read_bytes()) == s['source_sha256']
        sources.append(dict(path=s['path'], source_sha256=s['source_sha256']))
    bridges = {}
    for r in raw['verified_direct_bridges']:
        image.check(r)
        va, code = int(r['start_va'], 16), bytes.fromhex(r['idb_hex'])
        assert len(code) == 5 and code[0] == 0xe9
        target = va + 5 + struct.unpack_from('<i', code, 1)[0]
        assert target == int(r['target_va'], 16) and va not in bridges
        bridges[va] = target
    for call in raw['calls']:
        target = int(call['target_va'], 16)
        for b in call['bridges']:
            assert target == int(b, 16)
            target = bridges[target]
        assert target == int(call['implementation_va'], 16)
        site = int(call['site_va'], 16)
        if image.read(site, 1) == b'\xe8':
            assert site + 5 + struct.unpack('<i', image.read(site + 1, 4))[0] == int(call['target_va'], 16)
    candidates = list(raw['explicit_owner_windows'])
    for edges in raw['incoming'].values():
        candidates.extend(e['owner_window'] for e in edges if 'owner_window' in e)
    windows = []
    for w in candidates:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        checked = [image.check(r['bytes']) for r in w['assembly']]
        assert w['site_va'] in {r['start_va'] for r in checked}
        assert all(checked[i - 1]['end_va'] == checked[i]['start_va'] for i in range(1, len(checked)))
        windows.append(dict(owner_va=w['owner_va'], site=w['site_va'], start=checked[0]['start_va'],
                            end=checked[-1]['end_va'], window_status='仅有限窗口核验',
                            window_conclusion='参数和字段读取局部；不计owner整函数覆盖'))
    for r in raw['data_windows']:
        image.check(r)
    strings = []
    for r in raw['data_windows']:
        if r['start_va'] == '0xa766f8':
            assert r['size'] == 4
            continue
        data = bytes.fromhex(r['idb_hex'])
        assert data[-1:] == b'\0' and b'\0' not in data[:-1]
        strings.append(dict(address=r['start_va'], text=data[:-1].decode('ascii'), size=r['size'], sha256=sha(data)))
    for r in raw['strings']:
        image.check(r['byte_audit'])
        assert r['unit_width'] == 1 and r['nul_hex'] == '00'
        assert r['byte_audit']['idb_hex'] == r['payload_hex'] + '00'
    reused = []
    for rel, selected in REUSE.items():
        payload = (DOCS / rel).read_bytes()
        obj = json.loads(payload)
        found = set()
        for index, f in enumerate(obj['functions']):
            va = int(f['va'], 16)
            if va not in selected:
                continue
            found.add(va)
            if 'instructions' in f:
                checked = [image.check(r) for r in f['chunks']]
            else:
                checked = [image.check(r) for r in f.get('chunk_byte_ranges', f['byte_ranges'])]
                declared = f.get('declared_chunks', f.get('chunks'))
                assert {(r['start_va'], r['end_va']) for r in declared} == {(r['start_va'], r['end_va']) for r in checked}
            if va == 0x628a80:
                assert checked == audits[va]
            reused.append(dict(owner_va=f['va'], source=rel, source_sha256=sha(payload),
                               json_pointer=f'/functions/{index}', chunks=checked,
                               scope='当前完整声明块字节一致；语义仅本专题指定字段/路径'))
        assert found == selected, (rel, selected - found)
    special_specs = [
        ('专题/Grant全局配置与短消费/证据/grant_reused_raw.json', '/legacy_rechecked_functions/0'),
        ('专题/高扇入函数群筛选/证据/highfanout_raw.json', '/targets/0/function'),
    ]
    for rel, pointer in special_specs:
        payload = (DOCS / rel).read_bytes()
        f = json.loads(payload)
        for part in pointer.split('/')[1:]:
            f = f[int(part)] if isinstance(f, list) else f[part]
        checked = []
        for r in f.get('disk_ranges', f.get('chunks')):
            start, size = int(r['va'], 16), r['size']
            data = image.read(start, size)
            assert data.hex() == r['disk_hex'] and sha(data) == r['sha256']
            if 'ida_hex' in r:
                assert r['equal'] is True and r['ida_hex'] == r['disk_hex']
            checked.append(dict(start_va=r['va'], end_va=hex(start + size), size=size, sha256=sha(data)))
        for r in f['instructions']:
            assert image.read(int(r['va'], 16), r['size']).hex() == r['hex']
        reused.append(dict(owner_va=f['va'], source=rel, source_sha256=sha(payload), json_pointer=pointer,
                           chunks=checked, scope='完整旧字节重核；语义仅游标归零或分配清理转发'))
    supplement_bytes = (HERE / 'dependency_raw.json').read_bytes()
    supplement = json.loads(supplement_bytes)
    assert supplement['disk_sha256'] == SHA
    supplemental = []
    expected_extra = {0x69d8d0, 0x69d910, 0x69d950, 0x69d990, 0x69d9d0}
    assert {int(f['va'], 16) for f in supplement['functions']} == expected_extra
    for index, f in enumerate(supplement['functions']):
        checked = [image.check(r) for r in f['chunk_byte_ranges']]
        assert {(r['start_va'], r['end_va']) for r in checked} == {(r['start_va'], r['end_va']) for r in f['declared_chunks']}
        supplemental.append(dict(seed_va=f['va'], source='dependency_raw.json', source_sha256=sha(supplement_bytes),
                                 json_pointer=f'/functions/{index}', chunks=checked))
    for r in supplement['thunks']:
        image.check(r)
        start = int(r['va'], 16)
        code = bytes.fromhex(r['idb_hex'])
        assert code[0] == 0xe9 and len(code) == 5
        assert start + 5 + struct.unpack_from('<i', code, 1)[0] == int(r['target'], 16)
    anchors = {0x69c751: 'c7808400000000000000', 0x69c778: 'c780a800000000000000',
               0x69c8a2: 'c7818000000000000000', 0x69c90b: 'c681b800000000',
               0x69c912: 'b801000000', 0x69ca57: 'c1e209', 0x69cad0: 'e80d33f7ff',
               0x69cf57: '69d244020000', 0x69d2b7: '69d244020000',
               0x69d36c: '837dc8ff', 0x69d62b: '6bc90c',
               0x69d646: '8982b4000000', 0x69d708: '89440a04', 0x69d72b: '89440a08',
               0x629499: '83e001', 0x6294ba: 'c20400'}
    for va, code in anchors.items():
        assert image.read(va, len(code) // 2).hex() == code, hex(va)
    resource_bytes = (HERE / 'resource_audit.json').read_bytes()
    resource = json.loads(resource_bytes)
    resource_source = (ROOT / resource['source']).read_bytes()
    assert resource['source'] == 'Data/Help.kpd' and resource['status'] == 'PASS'
    assert sha(resource_source) == resource['source_sha256'] == '1145a25a22698581623bc587666f5847e9d9a11588f11a5cfc1fbdccd1b78b39'
    assert len(resource_source) == resource['file_bytes'] == 5301
    assert resource['plain_sha256'] == 'ab61d7ddd6a796278ce6f93584177241c35a1712c116ca38881beca00f387d68'
    assert {c['category']: c['count'] for c in resource['categories']} == {'OP': 13, 'RULE': 5, 'EVENT': 26, 'NPC': 20, 'prop': 75}
    assert len(resource['sections']) == 125
    resource_reference = dict(source=resource['source'], source_sha256=resource['source_sha256'],
                              audit_sha256=sha(resource_bytes), plain_sha256=resource['plain_sha256'],
                              script_sha256=sha((HERE / 'resource_audit.py').read_bytes()),
                              scope='引用已运行的只读资源审计；详细结构和原始值见resource_audit.json，不证明UI显示')
    formal = adapt(raw, digest)
    save(HERE / 'formal_functions.json', formal)
    assert json.loads((HERE / 'formal_functions.json').read_bytes()) == adapt(raw, digest)
    save(HERE / 'reused_audit.json', dict(disk_sha256=SHA, references=reused,
                                        supplemental=supplemental,
                                        scope='仅628A80按函数契约审阅；其他依赖不新增整函数覆盖'))
    functions = [dict(va=hex(va), status=status, conclusion=conclusion,
                      evidence=('证据/formal_functions.json' if va in FRESH else
                                '证据/dependency_raw.json' if va in expected_extra else '证据/reused_audit.json'),
                      scope='完整声明块内限定契约或局部路径',
                      unknown='未运行游戏；损坏资源、失败恢复、其他消费者和所有权接管仍有边界')
                 for va, (status, conclusion) in REVIEWS.items()]
    assert all({'va', 'status', 'conclusion'}.isdisjoint(w) for w in windows)
    save(HERE.parent / '函数审阅清单.json', dict(disk_sha256=SHA, raw_source_sha256=digest,
                                                functions=functions, windows=windows))
    for p in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in p.read_text(encoding='utf-8').splitlines())
    result = dict(status='PASS', disk_sha256=SHA, raw_source_sha256=digest, fresh_functions=9, reused_seeds=1,
                  current_chunks=sum(len(v) for v in audits.values()), verified_e9_bridges=len(bridges),
                  supplemental_functions=5, supplemental_chunks=5, supplemental_e9_bridges=len(supplement['thunks']),
                  raw_window_records=len(candidates), finite_windows=len(windows),
                  ownerless_window_records=len(candidates) - len(windows), strings=strings,
                  semantic_anchor_sites=[hex(v) for v in anchors], reuse_sources=sources,
                  resource_audit=resource_reference,
                  review_levels={'静态契约已审阅': 10, '局部路径已核': 5},
                  formal_adapter_equivalent=True, doc_format_passed=True,
                  boundary='限定静态审阅；不证明资源安全解析、全局清理或实机文本显示')
    save(HERE / 'bounded_audit.json', result)
    save(HERE.parent / '验证结果.json', {k: v for k, v in result.items() if k not in {'strings', 'reuse_sources'}})
    print(json.dumps({k: result[k] for k in ['status', 'current_chunks', 'finite_windows', 'verified_e9_bridges']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
