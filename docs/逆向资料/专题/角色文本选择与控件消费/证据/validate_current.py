"""离线复核来源、当前PE、声明块、指令边界、桥与分级清单。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT/'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'


def pointer(value, path):
    for key in path.strip('/').split('/'):
        key = key.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def main():
    blob = (ROOT/'RnClient.exe').read_bytes()
    assert hashlib.sha256(blob).hexdigest() == SHA
    pe = struct.unpack_from('<I', blob, 60)[0]
    base = struct.unpack_from('<I', blob, pe+52)[0]
    at = pe+24+struct.unpack_from('<H', blob, pe+20)[0]
    sections = [struct.unpack_from('<4I', blob, at+40*i+8) for i in range(struct.unpack_from('<H', blob, pe+6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    sources, hashes, maps, transcript = {}, {}, {}, []
    counts = dict(byte_records=0, owner_items=0)
    def disk(va, size):
        matches = [(rva, off) for _, rva, length, off in sections if base+rva <= va and va+size <= base+rva+length]
        assert len(matches) == 1, (hex(va), size)
        rva, off = matches[0]
        return blob[off+va-base-rva:off+va-base-rva+size]
    def audit(row, va=None):
        va = int(row.get('start_va', row.get('va')), 16) if va is None else va
        raw = disk(va, row['size'])
        assert raw.hex() == row['disk_hex'].lower()
        for key in ('idb_hex', 'ida_hex'):
            if key in row: assert raw.hex() == row[key].lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row: assert hashlib.sha256(raw).hexdigest() == row['sha256'].lower()
        counts['byte_records'] += 1
        return raw
    def load(name):
        raw = (HERE/name).read_bytes()
        hashes[name] = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        assert data['disk_sha256'].lower() == SHA
        sources[name] = data
        return data
    bounded = load('bounded_raw.json')
    assert hashes['bounded_raw.json'] == 'd3f6cc36649f163aab76931e1fa8b62573be4027e6f57f7a5cdc06764df053a6'
    seeds = ['0x6f4db0', '0x7014a0', '0x756460', '0x762e10']
    assert [x['seed_va'] for x in bounded['seeds']] == seeds
    assert [x['seed_va'] for x in bounded['functions']] == seeds[:2]
    assert [x['seed_va'] for x in bounded['reused_seeds']] == seeds[2:]
    assert [x['seed_va'] for x in bounded['current_chunk_audits']] == seeds
    for name in ('formal_functions.json', 'reused_functions.json'):
        for row in load(name)['functions']:
            raw = (DOCS/row['source_path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == row['source_sha256']
            document = json.loads(raw)
            original = pointer(document, row['source_pointer'])
            for key, value in original.items():
                assert row[key] == value and pointer(document, row['source_field_pointers'][key]) == value
            chunks = original.get('chunk_byte_ranges', original.get('chunks', original.get('byte_ranges')))
            expected = [dict(start_va=x.get('start_va', x.get('va', x.get('address'))), **{k:v for k,v in x.items() if k not in ('start_va','va','address')}) for x in chunks]
            assert row['normalized_chunks'] == expected
            expected = [dict(site_va=x.get('site_va', x.get('va', x.get('address'))), text=x['text'], is_code=x.get('is_code', True), original=x) for x in original.get('assembly', original.get('instructions'))]
            assert row['normalized_assembly'] == expected
            decoded = {}
            transcript.append('// '+row['va']+' / '+row['adaptation_scope'])
            assert len(row['declared_chunks']) == len(row['normalized_chunks'])
            for declared, chunk in zip(row['declared_chunks'], row['normalized_chunks']):
                start = int(chunk['start_va'], 16)
                end = start+chunk['size']
                audit(chunk)
                assert declared['start_va'] == chunk['start_va'] and int(declared['end_va'], 16) == end
                items = [x for x in row['normalized_assembly'] if start <= int(x['site_va'], 16) < end]
                assert items and int(items[0]['site_va'], 16) == start
                for i, item in enumerate(items):
                    va = int(item['site_va'], 16)
                    stop = int(items[i+1]['site_va'], 16) if i+1 < len(items) else end
                    payload = disk(va, stop-va)
                    if item['is_code']:
                        ins = list(decoder.disasm(payload, va))
                        assert len(ins) == 1 and ins[0].size == len(payload), (row['va'], hex(va))
                        text = ins[0].mnemonic+' '+ins[0].op_str
                        decoded[va] = text
                    else: text = '静态数据 '+payload.hex()
                    transcript.append('// '+hex(va)+' '+text)
            maps[int(row['va'], 16)] = decoded
    assert [x['va'] for x in sources['formal_functions.json']['functions']] == seeds[:2]
    helper = DOCS/'专题/地图选择字段与列表消费/证据/adapt_sources.py'
    assert sources['formal_functions.json']['adapter_helper_sha256'] == hashlib.sha256(helper.read_bytes()).hexdigest()
    bridges = {}
    for row in bounded['verified_direct_bridges']:
        raw = audit(row)
        va = int(row['start_va'], 16)
        assert len(raw) == 5 and raw[0] == 0xe9
        target = va+5+struct.unpack_from('<i', raw, 1)[0]
        assert target == int(row['target_va'], 16)
        bridges[va] = target
    def callcheck(row):
        site = int(row.get('site_va', row.get('site')), 16)
        target = int(row.get('target_va', row.get('target')), 16)
        raw = disk(site, 6)
        if raw[:2] == b'\xff\x15': assert struct.unpack_from('<I', raw, 2)[0] == target
        else: assert raw[0] in (0xe8, 0xe9) and site+5+struct.unpack_from('<i', raw, 1)[0] == target
        for bridge in row.get('bridges', row.get('thunks', row.get('chain', []))):
            assert target == int(bridge, 16)
            raw = disk(target, 5)
            assert raw[0] == 0xe9
            target += 5+struct.unpack_from('<i', raw, 1)[0]
        assert target == int(row.get('implementation_va', row.get('implementation')), 16)
    for row in bounded['calls']: callcheck(row)
    for row in sources['reused_functions.json']['functions']:
        for call in row.get('calls', []): callcheck(call)
    bridge_path = DOCS/'专题/TeachMode对象与消费者/证据/bridge_raw.json'
    bridge_raw = bridge_path.read_bytes()
    assert hashlib.sha256(bridge_raw).hexdigest() == '2eb16206077a4ab8a8bda6a156eb258340b3a0e2dde8bc353e8b0fd8fa2134c2'
    historical_bridges = {row['va']:row for row in json.loads(bridge_raw)['bridges']}
    audited_historical = set()
    for row in sources['reused_functions.json']['functions']:
        for call in row.get('outgoing', []):
            if not call.get('iscode'): continue
            callcheck(call)
            for address in call['chain']:
                if address in audited_historical: continue
                bridge = historical_bridges[address]
                payload = audit(bridge)
                assert payload[0] == 0xe9 and len(payload) == 5
                assert int(address,16)+5+struct.unpack_from('<i',payload,1)[0] == int(bridge['target'],16)
                audited_historical.add(address)
    assert '0x60da8d' in audited_historical
    hashes['historical_bridge_raw.json'] = hashlib.sha256(bridge_raw).hexdigest()
    for row in bounded['current_chunk_audits']:
        for chunk in row['chunk_byte_ranges']: audit(chunk)
    windows = bounded['explicit_owner_windows']+[edge['owner_window'] for rows in bounded['incoming'].values() for edge in rows if 'owner_window' in edge]
    for row in windows:
        if row['owner_va'] is None:
            assert not row['assembly']
            continue
        previous = None
        transcript.append('// 窗口owner='+row['owner_va']+' site='+row['site_va'])
        for item in row['assembly']:
            va = int(item['site_va'], 16)
            raw = audit(item['bytes'], va)
            assert previous is None or previous == va
            previous = va+len(raw)
            if item['is_code']:
                ins = list(decoder.disasm(raw, va))
                assert len(ins) == 1 and ins[0].size == len(raw)
                text = ins[0].mnemonic+' '+ins[0].op_str
            else: text = '静态数据 '+raw.hex()
            transcript.append('// '+hex(va)+' '+text)
            counts['owner_items'] += 1
    for row in bounded['strings']:
        raw = audit(row['byte_audit'])
        width = row['unit_width']
        payload = bytes.fromhex(row['payload_hex'])
        assert width in (1, 2) and raw == payload+bytes(width) and bytes.fromhex(row['nul_hex']) == bytes(width)
        assert all(payload[i:i+width] != bytes(width) for i in range(0, len(payload), width))
    for row in bounded['data_windows']: audit(row)
    for row in bounded['reuse_sources']:
        assert hashlib.sha256((DOCS/row['path']).read_bytes()).hexdigest() == row['source_sha256']
    switch_path = HERE/'switch_table/bounded_raw.json'
    switch_raw = switch_path.read_bytes()
    assert hashlib.sha256(switch_raw).hexdigest() == '25276eb641a8410d9e838037e24da54dfd5ab813254261625f221924b059bfcc'
    switch = json.loads(switch_raw)
    assert switch['disk_sha256'] == SHA
    assert len(switch['data_windows']) == 1
    table = audit(switch['data_windows'][0])
    assert int(switch['data_windows'][0]['start_va'], 16) == 0x6dbdb4 and len(table) == 48
    assert struct.unpack_from('<I', table, 40)[0] == 0x6dbabd
    hashes['switch_table/bounded_raw.json'] = hashlib.sha256(switch_raw).hexdigest()
    (HERE/'review_assembly.txt').write_text('\n'.join(line.rstrip() for line in transcript)+'\n', 'utf-8')
    status, anchors = 'EVIDENCE_ONLY', 0
    ledger_path = HERE.parent/'函数审阅清单.json'
    if ledger_path.exists():
        ledger = json.loads(ledger_path.read_text('utf-8'))
        assert ledger['disk_sha256'] == SHA
        assert [x['va'] for x in ledger['functions']] == seeds
        for row in ledger['functions']+ledger['historical_contracts']:
            assert row['status'] and row['conclusion'] and row['unknown']
            ref = row['evidence_ref']
            source = pointer(sources[ref['file']], ref['pointer'])
            assert row['va'] == source['va'] and row['source_sha256'] == source['source_sha256']
            assert row['declared_chunks'] == source['declared_chunks']
            assert row['instruction_count'] == sum(x['is_code'] for x in source['normalized_assembly'])
            for anchor in row['semantic_anchors']:
                text = maps[int(row['va'], 16)][int(anchor['va'], 16)]
                assert all(token in text for token in anchor['tokens']), (row['va'], anchor, text)
                anchors += 1
        assert len(ledger['owner_windows']) == len(bounded['explicit_owner_windows']) == 2
        for row in ledger['owner_windows']:
            source = pointer(bounded, row['evidence_ref']['pointer'])
            items = source['assembly']
            assert row['owner_va'] == source['owner_va'] and row['site_va'] == source['site_va']
            assert row['start_va'] == items[0]['site_va']
            assert int(row['end_va'], 16) == int(items[-1]['site_va'], 16)+items[-1]['bytes']['size']
            assert row['status'] == '局部窗口分析' and row['unknown']
        summary = ledger['summary']
        assert summary['reviewed_functions'] == 4 and summary['complete'] == 2 and summary['partial'] == 2
        assert summary['reviewed_instructions'] == sum(x['instruction_count'] for x in ledger['functions']) == 527
        assert summary['historical_contracts'] == len(ledger['historical_contracts']) == 8
        assert summary['historical_contract_instructions'] == sum(x['instruction_count'] for x in ledger['historical_contracts'])
        assert summary['direct_bridges'] == len(bounded['verified_direct_bridges']) == 32
        status = 'PASS'
    for path in HERE.parent.rglob('*.txt'):
        assert all((not line.strip() or line.startswith('//')) and '\t' not in line and line == line.rstrip() for line in path.read_text('utf-8').splitlines())
    result = dict(status=status, disk_sha256=SHA, source_sha256=hashes, **counts, functions=len(maps), decoded_instructions=sum(len(x) for x in maps.values()), semantic_anchors=anchors, boundary='块与指令机械核验不扩大语义认领；旧主体仅部分业务路径，helper与窗口另列。')
    (HERE/'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps({k:v for k,v in result.items() if k != 'source_sha256'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
