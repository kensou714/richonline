"""第二十四批中央独审修正版：精确定位六条地图辅助记录，保留首次失败来源。"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT.parent.parent
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
TOPICS = {
    '124字节共享记录内容写入': {'fresh': 5, 'reused': 3},
    '角色档案配置与字段消费': {'fresh': 7, 'reused': 3},
    '地图视图初始化平移与夹取': {'fresh': 4, 'reused': 3},
    '文本控件光标与行边界': {'fresh': 3, 'reused': 4},
}
FINAL_FILES = {
    '124字节共享记录内容写入': ('function_review.json', 'independent_validation.json'),
    '角色档案配置与字段消费': ('函数审阅清单.json', 'independent_validation.json'),
    '地图视图初始化平移与夹取': ('函数审阅清单.json', 'independent_review_validation.json'),
    '文本控件光标与行边界': ('函数审阅清单.json', 'independent_validation.json'),
}
REVIEWED_VAS = {
    '124字节共享记录内容写入': {'0x6a4dc0', '0x6a4e70', '0x6a51a0', '0x6ab280', '0x6a6e00',
                         '0x6aad70', '0x6adec0', '0x6a54f0'},
    '角色档案配置与字段消费': {'0x6276a0', '0x7f2c20', '0x7f2c40', '0x629750', '0x7f2be0',
                        '0x7f2c90', '0x6b7930', '0x6a25a0', '0x646590', '0x7f35f0', '0x7f3630'},
    '地图视图初始化平移与夹取': {'0x7b6c90', '0x7b6ef0', '0x638150', '0x650c10', '0x7b6d50',
                         '0x7e1600', '0x7b6f60', '0x6919f0', '0x691a20'},
    '文本控件光标与行边界': {'0x8fc6a0', '0x8fc830', '0x8fccd0', '0x90ce80', '0x90d120', '0x90d310', '0x8fae70',
                       '0x611e76', '0x6034cf', '0x606d46', '0x601742', '0x6069db', '0x60aa13', '0x60bb61',
                       '0x60257f', '0x60aea0', '0x611fbb', '0x610283', '0x6049e7', '0x60d088', '0x601012',
                       '0x601d1e', '0x60262e', '0x6013f5', '0x60516c', '0x607a3e'},
}
READY = True


def load(path):
    return json.loads(path.read_bytes().decode('utf-8-sig'))


def digest(path):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), path
    return len(raw), hashlib.sha256(raw).hexdigest()


def va(value):
    return value if isinstance(value, int) else int(value, 16)


def pointer(value, path):
    for part in path.split('/')[1:]:
        key = part.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def walk(value, path=''):
    if isinstance(value, dict):
        yield value, path or '/'
        for key, child in value.items():
            yield from walk(child, path + '/' + str(key).replace('~', '~0').replace('/', '~1'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, path + '/' + str(index))


class Image:
    def __init__(self):
        self.raw = (PROJECT / 'RnClient.exe').read_bytes()
        assert hashlib.sha256(self.raw).hexdigest() == PE_SHA
        pe = struct.unpack_from('<I', self.raw, 0x3c)[0]
        assert self.raw[:2] == b'MZ' and self.raw[pe:pe + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', self.raw, pe + 24)[0] == 0x10b
        self.base = struct.unpack_from('<I', self.raw, pe + 52)[0]
        self.import_rva = struct.unpack_from('<I', self.raw, pe + 24 + 104)[0]
        table = pe + 24 + struct.unpack_from('<H', self.raw, pe + 20)[0]
        self.sections = [struct.unpack_from('<4I', self.raw, table + i * 40 + 8)
                         for i in range(struct.unpack_from('<H', self.raw, pe + 6)[0])]

    def read(self, address, size):
        rva = va(address) - self.base
        offsets = [offset + rva - start for _, start, raw_size, offset in self.sections
                   if 0 <= rva - start and rva - start + size <= raw_size]
        assert len(offsets) == 1, (address, size)
        return self.raw[offsets[0]:offsets[0] + size]

    def check(self, row, address=None):
        address = address or row.get('start_va', row.get('va'))
        raw = bytes.fromhex(row['idb_hex'])
        assert len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        if row['disk_hex'] is None:
            assert row['matching'] is None and '虚拟' in row['pending_status']
            rva = va(address) - self.base
            assert any(raw_size <= rva - start and rva - start + row['size'] <= size
                       for size, start, raw_size, _ in self.sections)
            return 'virtual'
        assert row['matching'] is True
        assert raw == bytes.fromhex(row['disk_hex']) == self.read(address, row['size'])
        return 'disk'

    def imports(self):
        def string(rva):
            result = bytearray()
            for index in range(4096):
                value = self.read(self.base + rva + index, 1)[0]
                if value == 0:
                    return result.decode('ascii')
                result.append(value)
            raise AssertionError('导入字符串越界')

        rows = []
        for index in range(4096):
            descriptor = struct.unpack('<5I', self.read(self.base + self.import_rva + 20 * index, 20))
            if not any(descriptor):
                return rows
            original, _, _, name, first = descriptor
            module = string(name)
            for item in range(65536):
                value = struct.unpack('<I', self.read(self.base + (original or first) + 4 * item, 4))[0]
                if value == 0:
                    break
                rows.append(dict(va=hex(self.base + first + 4 * item), module=module,
                    name=None if value & 0x80000000 else string(value + 2),
                    ordinal=value & 0xffff if value & 0x80000000 else 0))
            else:
                raise AssertionError('导入数组越界')
        raise AssertionError('导入描述表越界')


def bounded_check(path, image):
    raw = load(path)
    assert raw['disk_sha256'] == PE_SHA
    assert len(raw['functions']) == TOPICS[path.parent.parent.name]['fresh']
    assert len(raw['reused_seeds']) == TOPICS[path.parent.parent.name]['reused']
    assert len(raw['current_chunk_audits']) == len(raw['seeds'])
    assert len({row['seed_va'] for row in raw['functions']}) == len(raw['functions'])
    assert {row['seed_va'] for row in raw['current_chunk_audits']} == {row['seed_va'] for row in raw['seeds']}
    for row in raw['functions'] + raw['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']:
            assert image.check(chunk) == 'disk'
    for row in raw['verified_direct_bridges']:
        assert image.check(row) == 'disk'
        bytecode = bytes.fromhex(row['idb_hex'])
        assert row['size'] == 5 and bytecode[0] == 0xe9
        assert va(row['target_va']) == va(row['start_va']) + 5 + struct.unpack_from('<i', bytecode, 1)[0]
    counts = Counter(image.check(row) for row in raw['data_windows'])
    owners = instructions = 0
    for node, _ in walk(raw):
        if 'owner_va' in node and isinstance(node.get('assembly'), list):
            assert not any(key in node for key in ('va', 'address', 'ea', '地址'))
            owners += 1
            for item in node['assembly']:
                assert image.check(item['bytes'], item['site_va']) == 'disk'
                instructions += 1
    return counts, owners, instructions


def import_slot_check(directory, image):
    path = directory / '证据/import_slot_audit.json'
    row = load(path)
    assert row['schema'] == 'richonline-distinct-import-slot-1' and row['disk_sha256'] == PE_SHA
    assert row['start_va'] == '0xad3cbc' and row['size'] == 4 and row['file_offset'] == 4693180
    assert row['disk_hex'] == '80436d00' and row['idb_hex'] == 'ffffffff' and row['matching'] is False
    assert image.read(row['start_va'], 4) == image.raw[row['file_offset']:row['file_offset'] + 4] == bytes.fromhex(row['disk_hex'])
    assert bytes.fromhex(row['disk_hex']) != bytes.fromhex(row['idb_hex'])
    assert row['idb_imports'] == [dict(va='0xad3cbc', name='GetTickCount', ordinal=0, module='KERNEL32')]
    imports = [item for item in image.imports() if item['va'] == '0xad3cbc']
    assert len(imports) == 1 and imports[0]['name'] == 'GetTickCount'
    assert imports[0]['module'].lower() == 'kernel32.dll' and imports[0]['ordinal'] == 0
    assert '不一致' in row['pending_status'] and '运行时' in row['pending_status']
    raw = load(directory / '证据/bounded_raw.json')
    assert not any(va(item['start_va']) <= 0xad3cbc < va(item['start_va']) + item['size']
                   for item in raw['data_windows'])
    return dict(va=row['start_va'], disk_hex=row['disk_hex'], idb_hex=row['idb_hex'], matching=False,
                import_identity='GetTickCount/KERNEL32.dll；双份静态快照不等同运行时槽值')


def byte_record_check(row, image):
    address = row.get('start_va', row.get('va', row.get('address')))
    raw = bytes.fromhex(row.get('idb_hex', row.get('ida_hex')))
    assert len(raw) == row['size'] and raw == bytes.fromhex(row['disk_hex'])
    assert raw == image.read(address, row['size'])
    assert row.get('matching', row.get('equal')) is True
    if 'sha256' in row:
        assert hashlib.sha256(raw).hexdigest() == row['sha256']


def complete_raw_check(path, image, addresses):
    data = load(path)
    assert data['disk_sha256'] == PE_SHA
    assert {row['va'] for row in data['functions']} == set(addresses)
    assert len(data['functions']) == len(addresses)
    sizes = {}
    for row in data['functions']:
        ranges = row['chunk_byte_ranges']
        assert row['byte_ranges'] == ranges and row['bytes_match_disk'] is True
        assert row['declared_chunks'] == [dict(start_va=chunk['va'],
            end_va=hex(va(chunk['va']) + chunk['size']), is_main=chunk['va'] == row['va'])
            for chunk in ranges]
        assert va(row['end_va']) == max(va(chunk['va']) + chunk['size'] for chunk in ranges)
        for chunk in ranges:
            byte_record_check(chunk, image)
        assert all(any(va(chunk['va']) <= va(item['va']) < va(chunk['va']) + chunk['size']
                       for chunk in ranges) for item in row['assembly'])
        sizes[row['va']] = sum(chunk['size'] for chunk in ranges)
    return sizes


def supplements_check(image):
    record = complete_raw_check(ROOT / '专题/124字节共享记录内容写入/证据/reused_6AAD70_current.json',
                                image, ['0x6aad70'])
    callback = complete_raw_check(ROOT / '专题/角色档案配置与字段消费/证据/constructor_callback_raw.json',
                                  image, ['0x7f2be0'])
    assert callback == {'0x7f2be0': 60}
    callback_raw = load(ROOT / '专题/角色档案配置与字段消费/证据/constructor_callback_raw.json')
    assert [(row['va'], row['target']) for row in callback_raw['thunks']] == [
        ('0x60ffdb', '0x920bf0'), ('0x60b576', '0x91f6d0')]
    for row in callback_raw['thunks']:
        byte_record_check(row, image)
        raw = bytes.fromhex(row['idb_hex'])
        assert row['size'] == 5 and raw[0] == 0xe9
        assert va(row['va']) + 5 + struct.unpack_from('<i', raw, 1)[0] == va(row['target'])
    dimensions = complete_raw_check(ROOT / '专题/地图视图初始化平移与夹取/证据/dimension_getters_raw.json',
                                    image, ['0x60b044', '0x60bf9e', '0x6919f0', '0x691a20'])
    assert dimensions['0x60b044'] == dimensions['0x60bf9e'] == 5
    for bridge, target in [('0x60b044', '0x6919f0'), ('0x60bf9e', '0x691a20')]:
        raw = image.read(bridge, 5)
        assert raw[0] == 0xe9 and va(bridge) + 5 + struct.unpack_from('<i', raw, 1)[0] == va(target)
    return dict(reused_current=record, callback=callback, dimensions=dimensions)


def map_formal_check(directory, image):
    raw_path = directory / '证据/bounded_raw.json'
    raw, formal = load(raw_path), load(directory / '证据/formal_functions.json')
    reused = load(directory / '证据/reused_functions.json')
    dependencies = load(directory / '证据/formal_dependencies.json')
    assert formal['disk_sha256'] == reused['disk_sha256'] == dependencies['disk_sha256'] == PE_SHA
    helper = ROOT / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
    assert reused['adapter_helper_sha256'] == digest(helper)[1]
    expected = [(raw_path.relative_to(ROOT).as_posix(), f'/functions/{i}', '本批新原证无损适配')
                for i in range(4)]
    expected += [('专题/地图视图初始化平移与夹取/证据/dimension_getters_raw.json', f'/functions/{i}',
                  '本批尺寸短桥' if i < 2 else '本批尺寸读取本体') for i in range(4)]
    specs = [('专题/断线与离席恢复/ida_disconnect_fields.json', ['0x7b6d50', '0x7e1600'], '历史本体本批深化审阅'),
             ('专题/断线与离席恢复/ida_disconnect_dependencies.json', ['0x7b6f60'], '历史本体本批深化审阅'),
             ('专题/TeachMode序号生产与根对象/证据/load_source_raw.json', ['0x64f2a0'], '初始化参数局部契约复用'),
             ('专题/TeachMode对象与消费者/证据/teachmode_raw.json', ['0x63e0e0'], '历史局部契约复用'),
             ('专题/40C1状态事件/证据/animation_fields.json', ['0x63e000', '0x81bd10'], '历史局部契约复用')]
    for name, addresses, scope in specs:
        source = load(ROOT / name)
        for address in addresses:
            found = [(row, ref) for row, ref in walk(source)
                     if row.get('va', row.get('address')) == address
                     and any(key in row for key in ('assembly', 'instructions'))]
            assert len(found) == 1
            expected.append((name, found[0][1], scope))
    rows = formal['functions'] + dependencies['functions'] + reused['functions']
    assert len(rows) == len(expected) == 15
    for new, (name, ref, scope) in zip(rows, expected):
        path = ROOT / name
        old = pointer(load(path), ref)
        address = old.get('seed_va', old.get('va', old.get('address')))
        chunks = old.get('chunk_byte_ranges', old.get('chunks', old.get('byte_ranges')))
        assembly = old.get('assembly', old.get('instructions'))
        normalized = [dict(start_va=chunk.get('start_va', chunk.get('va', chunk.get('address'))),
            **{key: value for key, value in chunk.items() if key not in ('start_va', 'va', 'address')})
            for chunk in chunks]
        wanted = dict(old, va=address, source_path=name, source_pointer=ref,
            source_sha256=digest(path)[1], source_field_pointers={key: ref + '/' + key for key in old},
            adaptation_scope=scope, normalized_chunks=normalized,
            normalized_assembly=[dict(site_va=item.get('site_va', item.get('va', item.get('address'))),
                text=item['text'], is_code=item.get('is_code', True), original=item) for item in assembly])
        wanted.setdefault('declared_chunks', [dict(start_va=chunk['start_va'],
            end_va=hex(va(chunk['start_va']) + chunk['size']), is_main=chunk['start_va'] == address)
            for chunk in normalized])
        wanted.setdefault('byte_ranges', chunks)
        assert new == wanted, (name, ref)
        for chunk in normalized:
            byte_record_check(chunk, image)
    return dict(fresh=4, dimension_bodies=2, dimension_bridges=2, historical=7)


def shared_formal_check(directory, image):
    payload = (directory / '证据/bounded_raw.json').read_bytes()
    sha = hashlib.sha256(payload).hexdigest()
    raw, formal = load(directory / '证据/bounded_raw.json'), load(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and formal['source_sha256'] == sha
    assert len(formal['functions']) == len(raw['functions']) == 5
    for index, (old, new) in enumerate(zip(raw['functions'], formal['functions'])):
        ranges = [dict(va=chunk['start_va'], **{key: value for key, value in chunk.items() if key != 'start_va'})
                  for chunk in old['chunk_byte_ranges']]
        wanted = dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'],
            status='机械适配；语义见function_review.json',
            assembly=[dict(va=item['site_va'], text=item['text'], is_code=item['is_code']) for item in old['assembly']],
            pseudocode=old['pseudocode'], decompile_error=old['decompile_error'],
            declared_chunks=[dict(start_va=chunk['va'], end_va=hex(va(chunk['va']) + chunk['size']),
                                  is_main=chunk['va'] == old['seed_va']) for chunk in ranges],
            chunk_byte_ranges=ranges, bytes_match_disk=all(chunk['matching'] for chunk in ranges),
            source=dict(path='证据/bounded_raw.json', sha256=sha, json_pointer='/functions/' + str(index)))
        assert new == wanted
        for chunk in ranges:
            byte_record_check(chunk, image)
    return len(formal['functions'])


def shared_reuse_check():
    path = ROOT / '专题/124字节共享记录内容写入/证据/reused_raw.json'
    rows = load(path)['records']
    specs = [
        ('0x6aad70', '登录与大厅状态/证据/ui_wait_transitions.json', '/6'),
        ('0x6adec0', '大厅玩家记录与装备字段/证据/record_lifecycle.json', '/functions/7'),
        ('0x63e1a0', '角色1416字段来源/证据/functions.json', '/functions/2'),
        ('0x693680', '角色1416字段来源/证据/functions.json', '/functions/12'),
        ('0x6a54f0', '角色1416字段来源/证据/functions.json', '/functions/18'),
        ('0x64f200', '随机地图候选与配置索引/证据/dependencies_raw.json', '/functions/1'),
        ('0x82b090', 'TeachMode状态与序号来源/证据/closure_raw.json', '/functions/3'),
        ('0x7ba0b0', 'Pawn四档配置与业务消费/证据/functions_raw.json', '/functions/1'),
        ('0x629e30', '大厅玩家记录与装备字段/证据/record_access.json', '/functions/0'),
        ('0x64f090', '大厅玩家记录与装备字段/证据/record_access.json', '/functions/1'),
        ('0x629ea0', '游戏分派桥接/证据/property_and_6021_handlers.json', '/functions/22'),
        ('0x64efd0', '游戏分派桥接/证据/property_and_6021_handlers.json', '/functions/23'),
        ('0x6b7dc0', '124字节共享记录与判断门/证据/formal_functions.json', '/functions/1'),
        ('0x628ef0', '文本过滤与字码转换/证据/functions_raw.json', '/functions/3'),
        ('0x64cdc0', '文本过滤与字码转换/证据/functions_raw.json', '/functions/11'),
        ('0x627450', '回合等待与自动选择/证据/pending_functions.json', '/functions/0x627450')]
    assert len(rows) == len(specs) == 16
    exceptions = []
    for index, (row, (address, name, ref)) in enumerate(zip(rows, specs)):
        source = ROOT / '专题' / name
        original = pointer(load(source), ref)
        assert row['va'] == address == original.get('va', original.get('address')) and row['original_record'] == original
        assert row['source'] == dict(path='../../' + name, sha256=digest(source)[1], pointer=ref)
        has_review = isinstance(original.get('status'), str) and isinstance(original.get('conclusion'), str)
        assert has_review == (index in (10, 11)), (index, address)
        if has_review:
            assert digest(source)[1] == '9861f1e478a0ccb56863d5b766b813c03cb641da93fd7e726c5a59220d971a50'
            exceptions.append(dict(va=address, source=path.relative_to(ROOT).as_posix(),
                json_pointer=f'/records/{index}/original_record', original=original,
                original_source=source.relative_to(ROOT).as_posix(), original_pointer=ref))
    return exceptions


def role_formal_check(directory, image):
    raw_path = directory / '证据/bounded_raw.json'
    raw, formal, sha = load(raw_path), load(directory / '证据/formal_functions.json'), digest(raw_path)[1]
    wanted_rows = []
    for index, old in enumerate(raw['functions']):
        ranges = [dict(chunk, va=chunk['start_va']) for chunk in old['chunk_byte_ranges']]
        wanted_rows.append(dict(va=old['seed_va'], end_va=old['end_va'], name=old['name'],
            status='仅导出；审阅另见分级清单', assembly=[dict(item, va=item['site_va']) for item in old['assembly']],
            pseudocode=old['pseudocode'], decompile_error=old['decompile_error'], byte_ranges=ranges,
            bytes_match_disk=True, declared_chunks=[dict(start_va=chunk['start_va'],
                end_va=hex(va(chunk['start_va']) + chunk['size']), is_main=chunk['start_va'] == old['seed_va'])
                for chunk in ranges], source='证据/bounded_raw.json', source_sha256=sha,
            json_pointer=f'/functions/{index}'))
    wanted = dict(schema='richonline-formal-functions-1', disk_sha256=PE_SHA, source_sha256=sha,
        functions=wanted_rows, scope='机械适配保留全部汇编/原类型伪码/声明块；不自动认证语义',
        thunks=[dict(row, va=row['start_va'], target=row['target_va']) for row in raw['verified_direct_bridges']])
    assert formal == wanted
    reuse = load(directory / '证据/reused_audit.json')
    assert reuse['disk_sha256'] == PE_SHA
    assert len(reuse['references']) == 26
    selected = {
        'TeachMode对象与消费者/证据/teachmode_raw.json': ['0x6276a0', '0x6b7930'],
        'Avatar配置与角色图片/证据/supplement_raw.json': ['0x646590'],
        'MapView配置记录与预览消费/证据/functions_raw.json': ['0x622d50'],
        '角色1416字段来源/证据/functions.json': ['0x693680'],
        'KoNews记录与消费者/证据/closure_raw.json': ['0x627760'],
        '业务提示与期限映射/证据/followups.json': ['0x6dba40'],
        '事件文字记录器/证据/resource_parser.json': ['0x8191d0', '0x819220', '0x819250', '0x819470',
            '0x819660', '0x8198e0', '0x81ad50', '0x81ad80', '0x81b7f0'],
        '文本过滤与字码转换/证据/functions_raw.json': ['0x627160', '0x64f000', '0x8190b0', '0x81b4c0'],
        '全局数值配置/证据/functions.json': ['0x627120', '0x627140', '0x81ad10'],
        '二进制读写游标/证据/cursor_extensions.json': ['0x91bd80'],
        'Grant全局配置与短消费/证据/grant_reused_raw.json': ['0x81a090'],
        '高扇入函数群筛选/证据/highfanout_raw.json': ['0x91f7e0']}
    assert {(row['source'], row['owner_va']) for row in reuse['references']} == {
        ('专题/' + name, address) for name, addresses in selected.items() for address in addresses}
    for row in reuse['references']:
        path = ROOT / row['source']
        assert digest(path)[1] == row['source_sha256']
        original = pointer(load(path), row['json_pointer'])
        assert original['va'] == row['owner_va'] and 'conclusion' not in row and 'status' not in row
        chunks = original.get('chunk_byte_ranges', original.get('byte_ranges', original.get('disk_ranges', original.get('chunks'))))
        wanted_chunks = []
        for chunk in chunks:
            start = chunk.get('start_va', chunk.get('va'))
            bytecode = image.read(start, chunk['size'])
            assert bytecode.hex() == chunk['disk_hex']
            if 'idb_hex' in chunk or 'ida_hex' in chunk:
                byte_record_check(chunk, image)
            if 'sha256' in chunk:
                assert hashlib.sha256(bytecode).hexdigest() == chunk['sha256']
            wanted_chunks.append(dict(start_va=start, end_va=hex(va(start) + chunk['size']),
                                      size=chunk['size'], sha256=hashlib.sha256(bytecode).hexdigest()))
        assert row['chunks'] == wanted_chunks
        for instruction in original.get('instructions', []):
            if 'hex' in instruction:
                assert image.read(instruction['va'], instruction['size']).hex() == instruction['hex']
    callback = reuse['callback']
    callback_path = directory / '证据' / callback['source']
    assert callback['source'] == 'constructor_callback_raw.json'
    assert callback['source_sha256'] == digest(callback_path)[1] and callback['json_pointer'] == '/functions/0'
    bridge = callback['bridge_current_pe']
    assert bridge['va'] == '0x6022cd' and bridge['size'] == 5 and bridge['target'] == '0x7f2be0'
    bytecode = image.read(bridge['va'], 5)
    assert bytecode.hex() == bridge['disk_hex'] and hashlib.sha256(bytecode).hexdigest() == bridge['sha256']
    assert bytecode[0] == 0xe9 and va(bridge['va']) + 5 + struct.unpack_from('<i', bytecode, 1)[0] == 0x7f2be0
    assert image.read(0x7f2e25, 5).hex() == '68cd226000'
    return dict(fresh=len(wanted_rows), historical_dependencies=len(reuse['references']), callback=1)


def text_formal_check(directory, image):
    raw_path = directory / '证据/bounded_raw.json'
    sha = digest(raw_path)[1]
    assert sha == '6a313dc34df5930635ad34d9b2aa90da72fa170288fcf09ecaacab1ff33b06d2'
    raw, formal = load(raw_path), load(directory / '证据/formal_functions.json')
    assert formal['disk_sha256'] == PE_SHA and formal['source_sha256'] == sha
    specs = [('topic', '证据/bounded_raw.json', f'/functions/{index}', None) for index in range(3)]
    specs += [('docs', '专题/文本宽度到字符位置/证据/width_position.json', '/functions/' + str(index), address)
              for address, index in [('0x90ce80', 0), ('0x90d120', 6), ('0x90d310', 7)]]
    specs += [('docs', '专题/727F控件状态接口/证据/text_dependencies.json', '/functions/1', '0x8fae70')]
    assert len(formal['functions']) == len(specs) == 7
    for new, (base, name, ref, reused_va) in zip(formal['functions'], specs):
        path = (directory if base == 'topic' else ROOT) / name
        original = pointer(load(path), ref)
        source = dict(base=base, path=name, sha256=digest(path)[1], json_pointer=ref)
        ranges = original['chunk_byte_ranges'] if reused_va is None else next(
            item['chunk_byte_ranges'] for item in raw['current_chunk_audits'] if item['seed_va'] == reused_va)
        chunks = [dict(va=chunk.get('start_va', chunk.get('va')), size=chunk['size'],
            idb_hex=chunk.get('idb_hex', chunk.get('ida_hex')), disk_hex=chunk['disk_hex'],
            matching=chunk.get('matching', chunk.get('equal')),
            sha256=hashlib.sha256(bytes.fromhex(chunk.get('idb_hex', chunk.get('ida_hex')))).hexdigest()) for chunk in ranges]
        address = original.get('va', original.get('seed_va'))
        wanted = dict(va=address, name=original['name'], end_va=original.get('end_va',
            hex(max(va(chunk['va']) + chunk['size'] for chunk in chunks))),
            assembly=[dict(va=item.get('va', item.get('site_va')), text=item['text'], is_code=item.get('is_code', True))
                      for item in original.get('assembly', original.get('instructions'))],
            pseudocode=original['pseudocode'], decompile_error=original.get('decompile_error', original.get('pseudocode_error')),
            error_field_present='decompile_error' in original or 'pseudocode_error' in original,
            chunk_byte_ranges=chunks, source=source, source_record=original,
            coverage_origin='本批新增完整主体' if reused_va is None else '指定旧主体完整静态复核；不计新增',
            declared_chunks=[dict(start_va=chunk['va'], end_va=hex(va(chunk['va']) + chunk['size']),
                                  is_main=chunk['va'] == address) for chunk in chunks],
            bytes_match_disk=all(chunk['matching'] is True for chunk in chunks),
            status='原证无损适配；语义分级见函数审阅清单.json')
        if reused_va is not None:
            index = next(index for index, row in enumerate(raw['current_chunk_audits']) if row['seed_va'] == reused_va)
            wanted['current_audit_source'] = dict(base='topic', path='证据/bounded_raw.json', sha256=sha,
                                                  json_pointer=f'/current_chunk_audits/{index}')
            wanted['current_audit_record'] = raw['current_chunk_audits'][index]
        assert new == wanted, (name, ref)
        for chunk in chunks:
            byte_record_check(chunk, image)
    dependencies = [
        ('0x8f4b10', '专题/列表控件行记录与布局/证据/list_functions.json', 16, '可见宽度带关联对象扣减；有符号结果无非负钳制'),
        ('0x8f4ba0', '专题/列表控件行记录与布局/证据/list_functions.json', 18, '可见行容量有符号除法；零分母与溢出未设门'),
        ('0x8f4c20', '专题/列表控件行记录与布局/证据/list_functions.json', 19, '仅index<C门，回收描述及A0h行搬移，负index未拒绝'),
        ('0x8f39d0', '专题/列表控件行记录与布局/证据/list_dependencies.json', 5, '行创建/移位受配置和数量上限限制，可能不创建'),
        ('0x8eb410', '专题/控件回调与事件表/证据/注册与生命周期.json', 9, '范围约束位置后同步虚表通知；动态目标与重入未知')]
    assert len(formal['dependencies']) == len(dependencies) == 5
    for new, (address, name, index, contract) in zip(formal['dependencies'], dependencies):
        path, ref = ROOT / name, f'/functions/{index}'
        original = pointer(load(path), ref)
        assert original['va'] == address
        assert new == dict(va=address, source=dict(base='docs', path=name, sha256=digest(path)[1], json_pointer=ref),
            source_record=original, contract=contract, scope='仅指定旧依赖调用契约；不计本批完整主体或新增成果')
        for row, _ in walk(original):
            if ('idb_hex' in row or 'ida_hex' in row) and 'disk_hex' in row:
                byte_record_check(row, image)
    return dict(fresh=3, historical_bodies=4, historical_dependencies=5, direct_bridges=19)


def check_bindings(directory, validation, manifest_name):
    assert validation['status'] == 'PASS', directory.name
    checked = set()
    for key in ('sources', 'source_sha256', 'reviewed_final_sha256', 'author_text_sha256',
                'manifest_reference_sha256', 'bound_files', 'final_text_sha256', 'documents',
                'reference_sha256', 'document_sha256', 'source_files', 'final_binding_sha256'):
        value = validation.get(key)
        pairs = value.items() if isinstance(value, dict) else (
            ((row['path'], row.get('sha256', row.get('source_sha256'))) for row in value)
            if isinstance(value, list) else [])
        for name, sha in pairs:
            name = name.replace('\\', '/')
            base = PROJECT if name.startswith('docs/') else ROOT if name.startswith('专题/') else directory
            path = base / name
            if not path.is_file():
                path = directory / '证据' / name
            assert path.is_file() and digest(path)[1] == sha.lower(), path
            checked.add(path.resolve())
    for key, name in {'manifest_sha256': manifest_name, 'review_sha256': manifest_name,
        'formal_sha256': '证据/formal_functions.json', 'formal_source_sha256': '证据/formal_functions.json',
        'raw_source_sha256': '证据/bounded_raw.json'}.items():
        if key in validation:
            path = directory / name
            assert digest(path)[1] == validation[key]
            checked.add(path.resolve())
    required = {directory / manifest_name, directory / '证据/formal_functions.json', directory / '证据/bounded_raw.json'}
    required.update(directory.glob('*.txt'))
    assert {path.resolve() for path in required} <= checked, directory.name
    return len(checked)


def topic_check(topic, directory, image, central, records, evidence):
    manifest_name, validation_name = FINAL_FILES[topic]
    manifest_path = directory / manifest_name
    manifest, validation = load(manifest_path), load(directory / '证据' / validation_name)
    assert manifest['disk_sha256'] == PE_SHA
    bindings = check_bindings(directory, validation, manifest_name)
    if topic == '124字节共享记录内容写入':
        adapted = shared_formal_check(directory, image)
    elif topic == '角色档案配置与字段消费':
        adapted = role_formal_check(directory, image)
    elif topic == '地图视图初始化平移与夹取':
        adapted = map_formal_check(directory, image)
        auxiliary_refs = ['/direct_bridges/0', '/direct_bridges/1',
                          '/historical_contracts/0', '/historical_contracts/1',
                          '/historical_contracts/2', '/historical_contracts/3']
        related = [pointer(manifest, ref) for ref in auxiliary_refs]
        assert [row['va'] for row in related] == [
            '0x60b044', '0x60bf9e', '0x64f2a0', '0x63e0e0', '0x63e000', '0x81bd10']
        assert all(isinstance(row.get('status'), str) and 'conclusion' not in row for row in related)
    else:
        adapted = text_formal_check(directory, image)
    source = manifest_path.relative_to(ROOT).as_posix()
    expected = [(row, ref) for row, ref in walk(manifest)
                if isinstance(row.get('status'), str) and isinstance(row.get('conclusion'), str)
                and any(key in row for key in ('va', 'address', 'ea', '地址'))]
    addresses = [hex(va(row.get('va', row.get('address', row.get('ea', row.get('地址')))))) for row, _ in expected]
    assert len(addresses) == len(set(addresses)) and set(addresses) == REVIEWED_VAS[topic]
    for (row, ref), address in zip(expected, addresses):
        found = [item for item in central[address] if item['source'] == source and item['json_pointer'] == ref]
        assert len(found) == 1 and all(found[0][key] == row[key] for key in ('status', 'conclusion'))
    assert {item['json_pointer'] for item in records if item['source'] == source} == {ref for _, ref in expected}
    allowed = {(source, ref) for _, ref in expected}
    historical = shared_reuse_check() if topic == '124字节共享记录内容写入' else []
    for copied in historical:
        entries = central[copied['va']]
        matches = [row for row in entries if (row['source'], row['json_pointer']) ==
                   (copied['source'], copied['json_pointer'])]
        originals = [row for row in entries if (row['source'], row['json_pointer']) ==
                     (copied['original_source'], copied['original_pointer'])]
        assert len(matches) == len(originals) == 1
        assert all(matches[0][key] == originals[0][key] == copied['original'][key] for key in ('status', 'conclusion'))
        exported = next(row for row in evidence['functions'] if row['va'] == copied['va'])
        assert copied['source'] in exported['evidence'] and copied['original_source'] in exported['evidence']
        allowed.add((copied['source'], copied['json_pointer']))
    prefix = directory.relative_to(ROOT).as_posix() + '/'
    assert {(item['source'], item['json_pointer']) for item in records if item['source'].startswith(prefix)} == allowed
    bounded = directory / '证据/bounded_raw.json'
    data, owners, instructions = bounded_check(bounded, image)
    forbidden = bounded.relative_to(ROOT).as_posix()
    assert not any(row['source'] == forbidden for row in records)
    assert not any(forbidden in row['evidence'] for row in evidence['functions'] + evidence['unrecognized_code_ranges'])
    result = dict(manifest_reviews=len(expected), exact_historical_review_copies=len(historical),
                  bound_files=bindings, adaptations=adapted, data_ranges=dict(data),
                  finite_owner_windows=owners, finite_owner_instructions=instructions)
    if topic == '文本控件光标与行边界':
        result['import_slot_exception'] = import_slot_check(directory, image)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', nargs='?', default='第二十四批复核快照.json')
    args = parser.parse_args()
    assert READY, '准备阶段；原证与终稿校验尚未实现，禁止正式中央检查'
    assert Path(args.snapshot).name == args.snapshot
    snapshot, prior = load(HERE / args.snapshot), load(HERE / '第二十三批推进快照.json')
    sources = {}
    for row in snapshot['source_fingerprints']:
        path = HERE / row['path']
        assert digest(path) == (row['bytes'], row['sha256']), path
        sources[path.name] = load(path)
    assert set(sources) == {'evidence_coverage.json', 'review_coverage.json', 'followup_queue.json',
                            '结构覆盖口径.json', 'archive_validation.json'}
    original_snapshot = load(HERE / '第二十四批推进快照.json')
    original_archive_path = HERE / '第二十四批初次归档.json'
    original_archive_refs = [row for row in original_snapshot['source_fingerprints']
                             if row['path'] == 'archive_validation.json']
    assert len(original_archive_refs) == 1
    original_archive_ref = original_archive_refs[0]
    assert digest(original_archive_path) == (original_archive_ref['bytes'], original_archive_ref['sha256'])
    assert original_archive_ref['sha256'] == '38d3e997625037f2bfc18981563a841f2086d7a4fca229eec61a77816386a675'
    assert digest(HERE / 'independent_snapshot_audit24.py')[1] == 'b9817f7d3dc1d26ddc499a90a70aaab02fb23f0d1b104fe15780fb46f40538a0'
    original_archive = load(original_archive_path)
    assert original_snapshot['format_check']['counts'] == original_archive['counts']
    assert original_snapshot['format_check']['checked_at'] == original_archive['checked_at']
    assert not original_snapshot['format_check']['errors'] and not original_archive['error_files']
    unchanged_keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count',
                      'raw_status_counts', 'structural_groups', 'instruction_observation_count',
                      'unrecognized_code_ranges', 'navigation_windows')
    assert all(snapshot[key] == original_snapshot[key] for key in unchanged_keys)
    evidence, review, archive = (sources[name] for name in ('evidence_coverage.json', 'review_coverage.json', 'archive_validation.json'))
    assert not snapshot['invalid_records'] and not review['invalid_records']
    assert not snapshot['format_check']['errors'] and not archive['error_files']
    assert snapshot['format_check']['counts'] == archive['counts']
    assert snapshot['format_check']['checked_at'] == archive['checked_at']
    assert len(evidence['functions']) == snapshot['unique_exported_functions'] == evidence['unique_exported_functions']
    assert len(review['functions']) == snapshot['unique_explicit_review_functions'] == review['unique_functions_with_explicit_reviews']
    assert len({row['va'] for row in evidence['functions']}) == len(evidence['functions'])
    assert len({row['va'] for row in review['functions']}) == len(review['functions'])
    central = {row['va']: row['reviews'] for row in review['functions']}
    records = [dict(item, function_va=row['va']) for row in review['functions'] for item in row['reviews']]
    states = Counter(item['status'] for item in records)
    assert sum(states.values()) == review['review_record_count'] == snapshot['review_record_count']
    assert dict(states) == review['raw_status_counts'] == snapshot['raw_status_counts']
    assert snapshot['structural_groups'] == sources['结构覆盖口径.json']['groups']
    assert snapshot['instruction_observation_count'] == evidence['instruction_observation_count'] == prior['instruction_observation_count']
    assert snapshot['unrecognized_code_ranges'] == evidence['unrecognized_code_ranges'] == prior['unrecognized_code_ranges']
    assert snapshot['navigation_windows'] == evidence['navigation_windows']
    navigation = {(va(row['start_va']), va(row['end_va'])) for row in snapshot['navigation_windows']}
    assert len(navigation) == len(snapshot['navigation_windows']) == evidence['navigation_window_count']
    assert {(va(row['start_va']), va(row['end_va'])) for row in prior['navigation_windows']} <= navigation
    image = Image()
    supplements = supplements_check(image)
    topic_results = {topic: topic_check(topic, ROOT / '专题' / topic, image, central, records, evidence)
                     for topic in TOPICS}
    captured = set()
    for row in archive['files']:
        assert not row['errors'] and digest(ROOT / row['path']) == (row['bytes'], row['sha256'])
        assert row['path'] not in captured
        captured.add(row['path'])
    assert dict(Counter(Path(name).suffix for name in captured)) == archive['counts']
    assert '全量分析/independent_snapshot_audit24.py' in captured
    assert '全量分析/independent_snapshot_audit24_v2.py' in captured
    assert '全量分析/第二十四批初次归档.json' in captured
    keys = ('unique_exported_functions', 'unique_explicit_review_functions', 'review_record_count')
    changes = {key: snapshot[key] - prior[key] for key in keys}
    prefixes = tuple('专题/' + name + '/' for name in TOPICS)
    exclusive_exports = [row for row in evidence['functions'] if all(source.startswith(prefixes) for source in row['evidence'])]
    exclusive_reviews = [row for row in review['functions'] if all(item['source'].startswith(prefixes) for item in row['reviews'])]
    new_records = [item for item in records if item['source'].startswith(prefixes)]
    derived = dict(zip(keys, (len(exclusive_exports), len(exclusive_reviews), len(new_records))))
    assert changes == derived, (changes, derived)
    print(json.dumps(dict(status='PASS', snapshot=args.snapshot, counts={key: snapshot[key] for key in keys},
        changes=changes, source_fingerprints=len(sources), captured_archive_files=len(captured),
        original_failed_snapshot='第二十四批推进快照.json',
        original_archive_sha256=original_archive_ref['sha256'],
        topics=topic_results, supplements=supplements, navigation_windows=len(navigation),
        scope='冻结时点中央独审；不表示全程序语义完成或实机验证'), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
