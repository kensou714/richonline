"""核对五主体、旧依赖、回调指针与有限窗口；不扩张运行时覆盖。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '12d260f584924374b55572c24d3301f232d425bfca853a49a7b5a3d02a4228e1'
SLOTS_SHA = '020fa6e36a83a35e7f784e316b3f8eef9044541988f62de52797691eb8935227'
SEEDS = {0x712980, 0x71f130, 0x71f230, 0x7cef00, 0x6a3a00}
REUSE = {
    '专题/TeachMode对象与消费者/证据/teachmode_raw.json':
        {0x7278e0, 0x628270, 0x629e60, 0x628900, 0x629c90, 0x8e2c10, 0x8e15b0, 0x91f6d0},
    '专题/主界面角色通知/证据/notify_mapping_audio.json': {0x8e1570},
    '专题/40EE系列事件/证据/direct_helpers.json': {0x694b30},
    '专题/40D0系列事件/证据/ui_helpers.json': {0x7f85c0},
}
REVIEWS = {
    0x712980: '输入对象+4取DWORD建筑索引，Build借用name传控件10虚表90；仅AL=1，ret4。',
    0x71f130: '输入对象参数槽0取DWORD索引，Build借用name传控件100虚表90；仅AL=1，ret4。',
    0x71f230: '槽0 DWORD传旧7BC3D0，提交体仅取低BYTE；忽略提交返回，AL=1，ret8且第二参数未读。',
    0x7cef00: '保存但不使用来路ECX，改取628270根交6A3A00；转发AL，自动void/MFC签名不代表实际契约。',
    0x6a3a00: '经629E60定位124字节记录，读取记录+4所指对象+20的1000h位，清位AL=1置位AL=0。',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class Image:
    def __init__(self):
        self.data = (ROOT / 'RnClient.exe').read_bytes()
        assert sha(self.data) == SHA
        nt = struct.unpack_from('<I', self.data, 60)[0]
        self.base = struct.unpack_from('<I', self.data, nt + 52)[0]
        table = nt + 24 + struct.unpack_from('<H', self.data, nt + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.data, table + 40 * i + 8)
                         for i in range(struct.unpack_from('<H', self.data, nt + 6)[0])]
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def read(self, va, size):
        positions = [off + va - self.base - rva for _, rva, count, off in self.sections
                     if 0 <= va - self.base - rva and va - self.base - rva + size <= count]
        assert len(positions) == 1
        return self.data[positions[0]:positions[0] + size]

    def check(self, r):
        va = r.get('start_va', r.get('va'))
        code = self.read(int(va, 16), r['size'])
        assert r.get('matching', r.get('equal')) is True
        assert code.hex() == r.get('idb_hex', r.get('ida_hex')) == r['disk_hex']
        assert 'sha256' not in r or sha(code) == r['sha256']
        return dict(start_va=va, end_va=hex(int(va, 16) + len(code)), size=len(code), sha256=sha(code))

    def decode(self, ranges):
        rows = []
        for r in ranges:
            va = int(r['start_va'], 16)
            instructions = list(self.decoder.disasm(self.read(va, r['size']), va))
            assert sum(i.size for i in instructions) == r['size']
            rows.extend(dict(va=hex(i.address), size=i.size, hex=i.bytes.hex(), text=i.mnemonic + ' ' + i.op_str)
                        for i in instructions)
        return rows


def main():
    image = Image()
    raw_bytes = (HERE / 'bounded_raw.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == SHA and raw['topic'] == HERE.parent.name
    assert raw['schema'] == 'richonline-bounded-preparation-1' and not raw['reused_seeds']
    assert sha((DOCS / '专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == raw['exporter_sha256']
    assert {int(f['seed_va'], 16) for f in raw['seeds']} == SEEDS
    audits = {f['seed_va']: [image.check(r) for r in f['chunk_byte_ranges']] for f in raw['current_chunk_audits']}
    assert len(audits) == 5 and sum(len(v) for v in audits.values()) == 5
    formal, reviews = [], []
    for index, f in enumerate(raw['functions']):
        chunks = [image.check(r) for r in f['chunk_byte_ranges']]
        assert chunks == audits[f['seed_va']]
        assembly = image.decode(chunks)
        assert [r['site_va'] for r in f['assembly']] == [r['va'] for r in assembly]
        assert isinstance(f['pseudocode'], str) and f['pseudocode'] and not f['decompile_error']
        declared = [dict(start_va=r['start_va'], end_va=r['end_va'], is_main=r['start_va'] == f['seed_va']) for r in chunks]
        formal.append(dict(va=f['seed_va'], end_va=f['end_va'], name=f['name'],
                           status='仅导出；分级另见审阅清单',
                           assembly=[dict(r, va=r['site_va']) for r in f['assembly']], pseudocode=f['pseudocode'],
                           decompile_error=f['decompile_error'], declared_chunks=declared,
                           byte_ranges=[dict(r, va=r['start_va']) for r in f['chunk_byte_ranges']], bytes_match_disk=True,
                           source='证据/bounded_raw.json', source_sha256=RAW_SHA, json_pointer=f'/functions/{index}'))
        reviews.append(dict(va=f['seed_va'], status='静态契约已审阅', conclusion=REVIEWS[int(f['seed_va'], 16)],
                            source_records=[dict(path='证据/bounded_raw.json', sha256=RAW_SHA, json_pointer=f'/functions/{index}')],
                            declared_chunks=declared, original_byte_ranges=f['chunk_byte_ranges'], assembly_anchors=assembly,
                            limitation='完整主体限定契约；不保证实际虚表目标/回调注册/发送成功/索引合法或线程安全'))
    assert {int(f['va'], 16) for f in formal} == SEEDS
    bridges = {}
    for r in raw['verified_direct_bridges']:
        image.check(r)
        va, code = int(r['start_va'], 16), bytes.fromhex(r['idb_hex'])
        assert code[0] == 0xe9 and len(code) == 5
        target = va + 5 + struct.unpack_from('<i', code, 1)[0]
        assert target == int(r['target_va'], 16) and va not in bridges
        bridges[va] = target
    assert len(bridges) == 15
    for c in raw['calls']:
        target = int(c['target_va'], 16)
        for b in c['bridges']:
            assert target == int(b, 16)
            target = bridges[target]
        assert target == int(c['implementation_va'], 16)
        site = int(c['site_va'], 16)
        code = image.read(site, 5)
        assert code[0] == 0xe8 and site + 5 + struct.unpack_from('<i', code, 1)[0] == int(c['target_va'], 16)
    sources = []
    for r in raw['reuse_sources']:
        source = DOCS / r['path']
        assert sha(source.read_bytes()) == r['source_sha256']
        sources.append(dict(path=r['path'], sha256=r['source_sha256']))
    reused = []
    for rel, selected in REUSE.items():
        payload = (DOCS / rel).read_bytes()
        obj, found = json.loads(payload), set()
        for index, f in enumerate(obj['functions']):
            va = int(f['va'], 16)
            if va not in selected:
                continue
            found.add(va)
            ranges = f['chunks'] if 'instructions' in f else f.get('chunk_byte_ranges', f['byte_ranges'])
            chunks = [image.check(r) for r in ranges]
            assembly = image.decode(chunks)
            if 'instructions' in f:
                assert [(r['va'], r['hex']) for r in f['instructions']] == [(r['va'], r['hex']) for r in assembly]
            else:
                declared = f.get('declared_chunks', f.get('chunks'))
                if declared is not None:
                    assert {(r['start_va'], r['end_va']) for r in declared} == {(r['start_va'], r['end_va']) for r in chunks}
                else:
                    # 8E1570历史源只有va/end和完整字节范围；核原范围，不补造IDA声明块。
                    assert va == 0x8e1570 and len(chunks) == 1
                    assert chunks[0]['start_va'] == f['va'] and chunks[0]['end_va'] == f['end_va']
                assert [r['va'] for r in f['assembly']] == [r['va'] for r in assembly]
            reused.append(dict(owner_va=f['va'], source=rel, source_sha256=sha(payload), json_pointer=f'/functions/{index}',
                               observed_ranges=chunks, instructions=assembly,
                               source_declares_chunks=('instructions' in f or f.get('declared_chunks', f.get('chunks')) is not None),
                               boundary='原来源完整范围重核；8E1570源无声明块不补造，其他声明块逐项相等；只用本专题路径不新增覆盖'))
        assert found == selected
    rel = '专题/Build配置与建筑资料消费/证据/bounded_raw.json'
    payload = (DOCS / rel).read_bytes()
    for index, f in enumerate(json.loads(payload)['functions']):
        if f['seed_va'] == '0x71ed30':
            chunks = [image.check(r) for r in f['chunk_byte_ranges']]
            reused.append(dict(owner_va=f['seed_va'], source=rel, source_sha256=sha(payload), json_pointer=f'/functions/{index}',
                               chunks=chunks, instructions=image.decode(chunks), boundary='完整旧字节重核，仅参数槽生产局部样本；事件注册未闭合'))
    rel = '专题/回合等待与自动选择/证据/pending_functions.json'
    payload = (DOCS / rel).read_bytes()
    old = json.loads(payload)['functions']
    legacy = []
    for va in ['0x7bc3d0', '0x7d60e0', '0x63e440', '0x63f760']:
        f = old[va]
        code = bytes.fromhex(f['bytes'])
        assert f['address'] == va and len(code) == int(f['end'], 16) - int(va, 16)
        assert image.read(int(va, 16), len(code)) == code
        span = dict(start_va=va, end_va=f['end'], size=len(code), sha256=sha(code))
        instructions = image.decode([span])
        assert [r[0] for r in f['assembly']] == [r['va'] for r in instructions]
        legacy.append(dict(owner_va=va, source=rel, source_sha256=sha(payload), json_pointer='/functions/' + va,
                           original_record=f, observed_range=span, current_pe_instructions=instructions,
                           boundary='历史address/end/bytes单范围重核；不补造声明块、不宣称当前IDA全部函数块，不新增覆盖'))
    slot_bytes = (HERE / 'callback_slots/bounded_raw.json').read_bytes()
    assert sha(slot_bytes) == SLOTS_SHA
    slots_raw = json.loads(slot_bytes)
    assert slots_raw['disk_sha256'] == SHA and not slots_raw['functions'] and not slots_raw['seeds']
    expected = {0xa24cf4: (0x60a71b, 0x712980), 0xa263b4: (0x60a96e, 0x71f130), 0xa263c8: (0x60ce17, 0x71f230)}
    slots = []
    for index, r in enumerate(slots_raw['data_windows']):
        image.check(r)
        address = int(r['start_va'], 16)
        bridge, target = expected[address]
        assert r['size'] == 4 and struct.unpack('<I', bytes.fromhex(r['idb_hex']))[0] == bridge
        assert bridges[bridge] == target
        slots.append(dict(address=r['start_va'], bridge=hex(bridge), implementation=hex(target), original_bytes=r,
                          source='callback_slots/bounded_raw.json', source_sha256=SLOTS_SHA, json_pointer=f'/data_windows/{index}',
                          boundary='只证实代码指针引用；事件号/注册/控件实例/可达性未证明'))
    assert len(slots) == 3
    candidates = list(raw['explicit_owner_windows'])
    for rows in raw['incoming'].values():
        candidates.extend(r['owner_window'] for r in rows if 'owner_window' in r)
    windows, seen = [], set()
    for w in candidates:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        chunks = [image.check(r['bytes']) for r in w['assembly']]
        assert w['site_va'] in {r['start_va'] for r in chunks}
        assert all(chunks[i - 1]['end_va'] == chunks[i]['start_va'] for i in range(1, len(chunks)))
        key = (w['owner_va'], w['site_va'], chunks[0]['start_va'], chunks[-1]['end_va'])
        if key in seen:
            continue
        seen.add(key)
        windows.append(dict(owner_va=w['owner_va'], site=w['site_va'], start=key[2], end=key[3],
                            window_status='仅有限窗口核验', window_conclusion='局部生产/调用/字段/返回观察；不计owner完整覆盖'))
    assert not raw['data_windows'] and not raw['strings']
    result = dict(status='PASS', disk_sha256=SHA, raw_source_sha256=RAW_SHA, fresh_functions=5, reused_seeds=0,
                  current_chunks=5, subject_bytes=sum(r['size'] for v in audits.values() for r in v),
                  verified_e9_bridges=15, dependency_functions=len(reused), legacy_range_records=len(legacy),
                  raw_window_records=len(candidates), finite_windows=len(windows), callback_slots=3,
                  callback_source_sha256=SLOTS_SHA, review_levels={'静态契约已审阅': 5},
                  formal_adapter_equivalent=True, doc_format_passed=True,
                  boundary='原证字节和限定静态契约；不证明实际虚表/注册/发送成功/服务端接受/线程或全依赖')
    formal_obj = dict(schema='richonline-formal-functions-1', disk_sha256=SHA, source_sha256=RAW_SHA,
                      functions=formal, thunks=[dict(r, va=r['start_va'], target=r['target_va']) for r in raw['verified_direct_bridges']],
                      scope='无损机械适配保留完整汇编、字符串型伪码、全部声明块；语义另见清单')
    save(HERE / 'formal_functions.json', formal_obj)
    assert json.loads((HERE / 'formal_functions.json').read_bytes()) == formal_obj
    save(HERE / 'reused_audit.json', dict(disk_sha256=SHA, references=reused, legacy_ranges=legacy,
                                        callback_slots=slots, raw_source_references=sources))
    save(HERE.parent / '函数审阅清单.json', dict(disk_sha256=SHA, functions=reviews, windows=windows))
    for p in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in p.read_text(encoding='utf-8').splitlines())
    save(HERE / 'bounded_audit.json', result)
    save(HERE.parent / '验证结果.json', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
