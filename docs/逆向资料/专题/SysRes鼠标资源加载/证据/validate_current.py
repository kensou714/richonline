"""离线逐块核当前PE、原字段来源、桥/调用/字符串/窗口和资源；不执行客户端。"""
import hashlib
import json
import runpy
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'daf27638a4dab260e7e3c119247001fa9d5a767428b7241d2d4b6e8f09d123ff'


def pointer(value, path):
    for key in path.strip('/').split('/'):
        key = key.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def main():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA
    pe = struct.unpack_from('<I', image, 60)[0]
    base = struct.unpack_from('<I', image, pe + 52)[0]
    table = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<4I', image, table + 40 * i + 8) for i in range(struct.unpack_from('<H', image, pe + 6)[0])]
    counts = dict(byte_records=0, owner_items=0, data_items=0)
    sources, hashes, decoded, text = {}, {}, {}, []
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    def disk(va, size):
        matches = [(r, o) for _, r, n, o in sections if base + r <= va and va + size <= base + r + n]
        assert len(matches) == 1
        r, o = matches[0]
        return image[o + va - base - r:o + va - base - r + size]
    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        raw = disk(va, row['size'])
        assert raw.hex() == row['disk_hex'].lower()
        for key in ('idb_hex', 'ida_hex'):
            if key in row:
                assert raw.hex() == row[key].lower()
        if 'sha256' in row:
            assert hashlib.sha256(raw).hexdigest() == row['sha256']
        assert row.get('matching', row.get('equal', True)) is True
        counts['byte_records'] += 1
        return raw
    def load(name):
        raw = (HERE / name).read_bytes()
        sources[name] = json.loads(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
        return sources[name]
    bounded = load('bounded_raw.json')
    assert hashes['bounded_raw.json'] == RAW_SHA and bounded['disk_sha256'] == SHA
    seeds = ['0x6bab70', '0x6db9d0']
    assert [x['seed_va'] for x in bounded['seeds']] == seeds
    assert [x['seed_va'] for x in bounded['functions']] == seeds and not bounded['reused_seeds']
    assert [x['seed_va'] for x in bounded['current_chunk_audits']] == seeds
    for name in ('formal_functions.json', 'reused_functions.json'):
        for row in load(name)['functions']:
            source_bytes = (DOCS / row['source_path']).read_bytes()
            assert hashlib.sha256(source_bytes).hexdigest() == row['source_sha256']
            original_doc = json.loads(source_bytes)
            original = pointer(original_doc, row['source_pointer'])
            assert row['source_field_pointers'] == {key:row['source_pointer'] + '/' + key for key in original}
            for key, value in original.items():
                assert row[key] == value == pointer(original_doc, row['source_field_pointers'][key])
            chunks = original.get('chunk_byte_ranges', original.get('chunks', original.get('byte_ranges')))
            assert row['normalized_chunks'] == [dict(start_va=x.get('start_va', x.get('va', x.get('address'))), **{k:v for k,v in x.items() if k not in ('start_va','va','address')}) for x in chunks]
            assembly = original.get('assembly', original.get('instructions'))
            assert len(assembly) == len(row['normalized_assembly'])
            for orig, norm in zip(assembly, row['normalized_assembly']):
                assert norm['original'] == orig and norm['text'] == orig['text']
                assert norm['site_va'] == orig.get('site_va', orig.get('va', orig.get('address')))
                assert norm['is_code'] == orig.get('is_code', True)
                kind = 'data' if orig['text'].lstrip().split()[0].lower() in ('db','dw','dd','dq') else 'code'
                assert norm.get('normalized_item_kind', kind) == kind
            va = int(row['va'], 16)
            decoded[va] = {}
            text.append('// ' + row['va'] + ' / ' + row['adaptation_scope'])
            assert len(row['declared_chunks']) == len(row['normalized_chunks'])
            for declared, chunk in zip(row['declared_chunks'], row['normalized_chunks']):
                begin = int(chunk['start_va'], 16)
                end = begin + chunk['size']
                audit(chunk)
                assert int(declared['start_va'],16) == begin and int(declared['end_va'],16) == end
                items = [x for x in row['normalized_assembly'] if begin <= int(x['site_va'],16) < end]
                assert items and int(items[0]['site_va'],16) == begin
                for i,item in enumerate(items):
                    site = int(item['site_va'],16)
                    stop = int(items[i+1]['site_va'],16) if i+1 < len(items) else end
                    raw = disk(site, stop-site)
                    if item.get('normalized_item_kind') == 'data' or not item['is_code']:
                        instruction = '声明块内原始数据 ' + raw.hex()
                        counts['data_items'] += 1
                    else:
                        result = list(decoder.disasm(raw, site))
                        assert len(result) == 1 and result[0].size == len(raw), (hex(site), raw.hex())
                        instruction = result[0].mnemonic + ' ' + result[0].op_str
                        decoded[va][site] = instruction
                    text.append('// ' + hex(site) + ' ' + instruction)
    assert [r['va'] for r in sources['formal_functions.json']['functions']] == seeds
    # 旧本体中的直接调用与桥按原记录核验，目标依赖不因此升级为完整语义。
    for row in sources['reused_functions.json']['functions']:
        for call in row.get('calls', []):
            site = int(call.get('site_va', call.get('site')), 16)
            target = int(call.get('target_va', call.get('target')), 16)
            raw = disk(site, 6)
            if raw[:2] == b'\xff\x15':
                assert struct.unpack_from('<I', raw, 2)[0] == target
            else:
                assert raw[0] in (0xe8, 0xe9) and site + 5 + struct.unpack_from('<i', raw, 1)[0] == target
            for bridge in call.get('bridges', call.get('thunks', [])):
                assert target == int(bridge, 16)
                raw = disk(target, 5)
                assert raw[0] == 0xe9
                target += 5 + struct.unpack_from('<i', raw, 1)[0]
            assert target == int(call.get('implementation_va', call.get('implementation')), 16)
    helper = DOCS / '专题/地图选择字段与列表消费/证据/adapt_sources.py'
    assert sources['formal_functions.json']['adapter_helper_sha256'] == hashlib.sha256(helper.read_bytes()).hexdigest()
    bridges = {}
    for row in bounded['verified_direct_bridges']:
        raw = audit(row)
        va = int(row['start_va'],16)
        assert len(raw) == 5 and raw[0] == 0xE9
        target = va + 5 + struct.unpack_from('<i',raw,1)[0]
        assert target == int(row['target_va'],16)
        bridges[va] = target
    for row in bounded['calls']:
        site,target = int(row['site_va'],16),int(row['target_va'],16)
        ins = next(decoder.disasm(disk(site,16),site,count=1))
        if ins.bytes[:2] == b'\xff\x15':
            assert struct.unpack_from('<I',ins.bytes,2)[0] == target
        else:
            assert ins.bytes[0] in (0xE8,0xE9) and site+5+struct.unpack_from('<i',ins.bytes,1)[0] == target
        for bridge in row['bridges']:
            assert target == int(bridge,16)
            target = bridges[target]
        assert target == int(row['implementation_va'],16)
    for row in bounded['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']:
            audit(chunk)
    windows = bounded['explicit_owner_windows'] + [x['owner_window'] for edges in bounded['incoming'].values() for x in edges if 'owner_window' in x]
    for window in windows:
        last = None
        text.append('// 窗口 ' + str(window['owner_va']) + ' @' + window['site_va'])
        for item in window['assembly']:
            site = int(item['site_va'],16)
            raw = audit(item['bytes'])
            assert last is None or last == site
            last = site + len(raw)
            ins = list(decoder.disasm(raw,site))
            assert item['is_code'] and len(ins) == 1 and ins[0].size == len(raw)
            text.append('// ' + hex(site) + ' ' + ins[0].mnemonic + ' ' + ins[0].op_str)
            counts['owner_items'] += 1
    for string in bounded['strings']:
        raw = audit(string['byte_audit'])
        width = string['unit_width']
        payload = bytes.fromhex(string['payload_hex'])
        assert width in (1,2) and len(raw)%width == 0 and raw == payload + bytes(width)
        assert bytes.fromhex(string['nul_hex']) == bytes(width)
        assert all(payload[i:i+width] != bytes(width) for i in range(0,len(payload),width))
    assert not bounded['data_windows']
    rtc = load('rtc_buffer_raw.json')
    assert hashes['rtc_buffer_raw.json'] == 'bb785578339a37508b3bd8b4de00af2e5e8dff47e826fb1ba6f9877bcf133051'
    assert rtc['disk_sha256'] == SHA
    frame = audit(rtc['frame_descriptor'])
    variable = audit(rtc['variable_descriptor'])
    name = audit(rtc['variable_name'])
    assert struct.unpack('<2I', frame) == (1, 0x6BAD0B)
    assert struct.unpack('<iII', variable) == (-148, 128, 0x6BAD17)
    assert name == b'szTmp\0' and b'\0' not in name[:-1]
    assert (rtc['declared_variable_count'],rtc['ebp_relative_offset'],rtc['declared_buffer_size']) == (1,-148,128)
    for source in bounded['reuse_sources']:
        assert hashlib.sha256((DOCS/source['path']).read_bytes()).hexdigest() == source['source_sha256']
    # 启动取根桥不在本批seed直接calls内，精确复用旧启动call记录并单独核磁盘。
    startup_path = DOCS / '专题/股票与交易流程/证据/stock_core.json'
    startup = json.loads(startup_path.read_bytes())['functions'][0]
    selected = [x for x in startup['calls'] if x.get('site_va',x.get('site')) == '0x623ce6']
    assert len(selected) == 1
    call = selected[0]
    target = int(call.get('target_va',call.get('target')),16)
    raw = disk(0x623CE6,5)
    assert raw[0] == 0xE8 and 0x623CEB + struct.unpack_from('<i',raw,1)[0] == target
    for bridge in call.get('bridges',call.get('thunks',[])):
        assert int(bridge,16) == target
        raw = disk(target,5)
        assert raw[0] == 0xE9
        target += 5 + struct.unpack_from('<i',raw,1)[0]
    assert target == 0x6278F0
    resource = load('resource_audit.json')
    assert resource == runpy.run_path(str(HERE/'audit_resources.py'))['inspect_resources']()
    assert resource['resource_count'] == 39
    assert [r['filename_index'] for r in resource['resources']] == list(range(39))
    (HERE/'review_assembly.txt').write_text('\n'.join(text)+'\n','utf-8')
    anchors = 0
    status = 'EVIDENCE_ONLY'
    ledger_path = HERE.parent/'函数审阅清单.json'
    if ledger_path.exists():
        ledger = json.loads(ledger_path.read_bytes())
        assert ledger['disk_sha256'] == SHA
        assert [r['va'] for r in ledger['functions']] == seeds
        for row in ledger['functions'] + ledger['historical_contracts']:
            ref = row['evidence_ref']
            original = pointer(sources[ref['file']],ref['pointer'])
            assert original['va'] == row['va'] and row['source_sha256'] == original['source_sha256']
            assert row['declared_chunks'] == original['declared_chunks']
            assert row['mechanical_instructions'] == len(decoded[int(row['va'],16)])
            assert row['status'] and row['conclusion'] and row['unknown']
            for anchor in row['semantic_anchors']:
                ins = decoded[int(row['va'],16)][int(anchor['va'],16)]
                assert all(token in ins for token in anchor['tokens']), (anchor,ins)
                anchors += 1
        assert ledger['summary']['new_bodies'] == 2
        assert ledger['summary']['new_instructions'] == sum(len(decoded[int(s,16)]) for s in seeds) == 150
        assert ledger['summary']['historical_records'] == 10
        assert len(ledger['historical_contracts']) == len(sources['reused_functions.json']['functions']) == 10
        assert ledger['summary']['historical_mechanical_instructions'] == sum(r['mechanical_instructions'] for r in ledger['historical_contracts'])
        assert ledger['summary']['explicit_owner_windows'] == 1 and ledger['summary']['direct_bridges'] == len(bridges) == 8
        assert len(ledger['owner_windows']) == len(bounded['explicit_owner_windows']) == 1
        window = ledger['owner_windows'][0]
        original = pointer(sources[window['evidence_ref']['file']],window['evidence_ref']['pointer'])
        assert window['owner_va'] == original['owner_va'] == '0x623cb0'
        assert window['site_va'] == original['site_va'] == '0x623ced'
        assert window['status'] == '局部窗口分析' and window['conclusion'] and window['unknown']
        assert len(bounded['calls']) == 15 and len(bounded['strings']) == 2
        status = 'PASS'
    for path in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in path.read_text('utf-8').splitlines())
    result = dict(status=status,disk_sha256=SHA,source_sha256=hashes,**counts,adapted_records=len(decoded),
                  mechanical_instructions=sum(len(x) for x in decoded.values()),semantic_anchors=anchors,
                  resource_files=39,imports=5,boundary='本体局部/历史窄契约/窗口/资源结构分开；未实机验证句柄、失败或外观。')
    (HERE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='source_sha256'}))


if __name__ == '__main__':
    main()
