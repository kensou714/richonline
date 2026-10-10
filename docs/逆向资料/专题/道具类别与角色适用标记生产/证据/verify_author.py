"""第二十七批作者证据复核；只读当前PE、原证、适配件和资源快照。"""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'f60d2bae64a7da9ba09aa55f6ab4689473cd4d14bc8fc34ae50d7ad1c76a7b61'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PE:
    def __init__(self):
        self.data = (ROOT/'RnClient.exe').read_bytes()
        assert digest(self.data) == SHA
        nt = struct.unpack_from('<I', self.data, 60)[0]
        assert self.data[nt:nt+4] == b'PE\0\0'
        self.base = struct.unpack_from('<I', self.data, nt+52)[0]
        table = nt+24+struct.unpack_from('<H', self.data, nt+20)[0]
        self.sections = [struct.unpack_from('<4I', self.data, table+40*i+8)
                         for i in range(struct.unpack_from('<H', self.data, nt+6)[0])]
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def read(self, va, size):
        rows = [(rva, off) for _name,rva,length,off in self.sections
                if 0 <= va-self.base-rva and va-self.base-rva+size <= length]
        assert len(rows) == 1, (hex(va), size)
        rva, off = rows[0]
        return self.data[off+va-self.base-rva:off+va-self.base-rva+size]

    def check_range(self, row):
        va = int(row.get('start_va', row.get('va')), 16)
        raw = self.read(va, row['size'])
        assert raw.hex() == row['idb_hex'].lower() == row['disk_hex'].lower()
        assert row.get('matching', row.get('equal', True)) is True
        if 'sha256' in row:
            assert digest(raw) == row['sha256'].lower()
        return raw

    def decode(self, row):
        va = int(row.get('start_va', row.get('va')), 16)
        raw = self.check_range(row)
        decoded = list(self.cs.disasm(raw, va))
        assert sum(ins.size for ins in decoded) == len(raw)
        return decoded


def source(path, expected=None):
    blob = (HERE/path).read_bytes()
    if expected:
        assert digest(blob) == expected
    return json.loads(blob), digest(blob)


def pointer(document, path):
    for token in path.strip('/').split('/'):
        token = token.replace('~1','/').replace('~0','~')
        document = document[int(token)] if isinstance(document,list) else document[token]
    return document


def main():
    pe = PE()
    bounded, raw_digest = source(Path('bounded_raw.json'), RAW_SHA)
    assert bounded['disk_sha256'] == SHA
    assert [r['seed_va'] for r in bounded['seeds']] == ['0x7fe7d0','0x7fe9e0','0x7ff1d0','0x7ff240']
    assert [r['seed_va'] for r in bounded['functions']] == ['0x7fe7d0','0x7fe9e0','0x7ff1d0','0x7ff240']
    assert [sum(r['size'] for r in f['chunk_byte_ranges']) for f in bounded['functions']] == [514,77,100,5818]
    assert sum(len(f['assembly']) for f in bounded['functions']) == 1658
    decoded_map, transcript, range_count = {}, [], 0
    for f in bounded['functions']:
        # 逐块按声明起点解码；不连续异常尾块不能按主块末地址推定。
        for chunk in f['chunk_byte_ranges']:
            va = int(chunk['start_va'],16)
            sites = [r for r in f['assembly'] if va <= int(r['site_va'],16) < va+chunk['size']]
            decoded = list(pe.cs.disasm(pe.check_range(chunk), va))
            assert len(sites) == len(decoded)
            assert [int(r['site_va'],16) for r in sites] == [i.address for i in decoded]
            assert sum(i.size for i in decoded) == chunk['size'] and all(r['is_code'] for r in sites)
            decoded_map.update({i.address:i for i in decoded})
            transcript.extend('// '+hex(i.address)+' '+i.bytes.hex()+' '+i.mnemonic+' '+i.op_str for i in decoded)
            range_count += 1
    for f,audit in zip(bounded['functions'],bounded['current_chunk_audits']):
        assert f['seed_va'] == audit['seed_va'] and f['chunk_byte_ranges'] == audit['chunk_byte_ranges']
    for row in bounded['data_windows']:
        pe.check_range(row)
    assert len(bounded['verified_direct_bridges']) == 37
    bridges = {}
    for row in bounded['verified_direct_bridges']:
        raw = pe.check_range(row)
        va = int(row['start_va'],16)
        assert len(raw) == 5 and raw[0] == 0xE9
        assert va+5+struct.unpack_from('<i',raw,1)[0] == int(row['target_va'],16)
        bridges[va] = int(row['target_va'],16)
    assert len(bounded['calls']) == 195
    for row in bounded['calls']:
        va = int(row['site_va'],16)
        target = int(row['target_va'],16)
        raw = pe.read(va,5)
        assert raw[0] == 0xe8 and va+5+struct.unpack_from('<i',raw,1)[0] == target
        for bridge in row['bridges']:
            assert target == int(bridge,16)
            target = bridges[target]
        assert target == int(row['implementation_va'],16)
    dep, dep_sha = source(Path('dependency_data/bounded_raw.json'), '091e32beca3d1cab382b0dde998ced568c85a1c6e965f4ee0a6e75a9bf84a522')
    assert dep['disk_sha256'] == SHA and len(dep['data_windows']) == 4
    for row in dep['data_windows']: pe.check_range(row)
    for va,target in [(0x5ff6ea,0x8052a0),(0x606a5d,0x7fe7d0),(0x60bda5,0x7fe9e0)]:
        raw = pe.read(va,5)
        assert raw[0] == 0xe9 and va+5+struct.unpack_from('<i',raw,1)[0] == target
    assert pe.read(0xa2b480,8) == bytes(8)
    assert digest((DOCS/'专题/四类型辅助请求与队列/证据/export_preparation_core.py').read_bytes()) == bounded['exporter_sha256'] == dep['exporter_sha256']
    for row in bounded['reuse_sources']:
        assert digest((DOCS/row['path']).read_bytes()) == row['source_sha256']
    for row in bounded['strings']:
        raw = pe.check_range(row['byte_audit'])
        width = row['unit_width']
        payload = bytes.fromhex(row['payload_hex'])
        assert width in (1,2) and raw == payload+bytes(width) and bytes.fromhex(row['nul_hex']) == bytes(width)
        assert all(payload[i:i+width] != bytes(width) for i in range(0,len(payload),width))
    windows = bounded['explicit_owner_windows'] + [edge['owner_window'] for rows in bounded['incoming'].values() for edge in rows if 'owner_window' in edge]
    window_items = 0
    for window in windows:
        for item in window['assembly']:
            va = int(item['site_va'],16)
            row = dict(item['bytes'], start_va=item['site_va'])
            raw = pe.check_range(row)
            if item['is_code']:
                ins = list(pe.cs.disasm(raw,va))
                assert len(ins) == 1 and ins[0].size == len(raw)
            window_items += 1
    formal = json.loads((HERE/'formal_functions.json').read_text('utf-8'))
    assert formal['disk_sha256'] == SHA and len(formal['functions']) == 4
    assert formal['adapter_helper_sha256'] == digest((DOCS/'专题/地图选择字段与列表消费/证据/adapt_sources.py').read_bytes())
    for row in formal['functions']:
        assert row['source_sha256'] == raw_digest and row['normalized_chunks']
    reused = json.loads((HERE/'reused_functions.json').read_text('utf-8'))
    assert reused['disk_sha256'] == SHA and len(reused['functions']) == 9
    for row in formal['functions']+reused['functions']:
        source_bytes = (DOCS/row['source_path']).read_bytes()
        assert digest(source_bytes) == row['source_sha256']
        original = pointer(json.loads(source_bytes),row['source_pointer'])
        for key,value in original.items():
            assert row[key] == value
            assert pointer(json.loads(source_bytes),row['source_field_pointers'][key]) == value
        ranges = original.get('chunk_byte_ranges',original.get('chunks',original.get('byte_ranges')))
        assert row['normalized_chunks'] == [dict(start_va=r.get('start_va',r.get('va',r.get('address'))),
                 **{k:v for k,v in r.items() if k not in ('start_va','va','address')}) for r in ranges]
        old_instructions = original.get('assembly',original.get('instructions'))
        assert row['normalized_assembly'] == [dict(site_va=r.get('site_va',r.get('va',r.get('address'))),
                 text=r['text'],is_code=r.get('is_code',True),original=r) for r in old_instructions]
        for chunk in row['normalized_chunks']:
            raw = pe.check_range(chunk)
            start = int(chunk['start_va'],16)
            items = [r for r in row['normalized_assembly'] if start <= int(r['site_va'],16) < start+len(raw)]
            assert items and int(items[0]['site_va'],16) == start
            for i,item in enumerate(items):
                va = int(item['site_va'],16)
                end = int(items[i+1]['site_va'],16) if i+1<len(items) else start+len(raw)
                if item['is_code']:
                    ins = list(pe.cs.disasm(pe.read(va,end-va),va))
                    assert len(ins) == 1 and ins[0].size == end-va
    ledger = json.loads((HERE.parent/'函数审阅清单.json').read_text('utf-8'))
    assert ledger['disk_sha256'] == SHA and ledger['raw_source_sha256'] == raw_digest
    assert [r['va'] for r in ledger['functions']] == ['0x7fe7d0','0x7fe9e0','0x7ff1d0','0x7ff240']
    assert all(r['status'] and r['conclusion'] and r['unknown'] and r['semantic_anchors'] for r in ledger['functions'])
    anchor_count = 0
    for row,body in zip(ledger['functions'],formal['functions']):
        assert row['declared_chunks'] == body['declared_chunks']
        assert row['instruction_count'] == len(body['normalized_assembly'])
        instructions = {r['site_va']:r['text'] for r in body['normalized_assembly']}
        for anchor in row['semantic_anchors']:
            assert instructions[anchor['site_va']] == anchor['ida_text']
            assert int(anchor['site_va'],16) in decoded_map
            anchor_count += 1
    semantic_tokens = {
        0x7fe801:['mov','0xc','0xffffffff'],0x7fe815:['mov','0x14','0'],
        0x7fe9fa:['cmp','0x14','0'],0x7fea18:['mov','0x14','0'],
        0x7ff1f9:['cmp','0x1f'],0x7ff1fd:['jae'],0x7ff202:['0xa675c0','*4'],
        0x7ff21a:['mov','eax'],0x7ff221:['or','eax','0xffffffff'],
        0x7ff36d:['jle'],0x7ff380:['add','eax','1'],0x7ff3aa:['imul','0x468'],
        0x7ff436:['mov','[edx], eax'],0x7ff492:['imul','0x468'],
        0x7ff664:['je','0x7ff69e'],0x7ff69a:['mov','0xc','eax'],
        0x7ff710:['mov','0x14','edx'],0x7ff72c:['jge','0x7ff7c6'],
        0x7ff747:['mov','byte ptr','1'],0x7ff777:['je','0x7ff7c1'],
        0x7ff7a4:['neg','eax'],0x7ff7a6:['sbb','eax, eax'],0x7ff7a8:['inc','eax'],
        0x7ff7be:['mov','byte ptr','al'],0x8008cc:['ret','4']}
    for va,tokens in semantic_tokens.items():
        ins = decoded_map[va]
        text = ins.mnemonic+' '+ins.op_str
        assert all(token in text for token in tokens),(hex(va),text,tokens)
    # 31项表：当前PE中每个窗口均为目标字符串+NUL，首项按表序可复核。
    table = next(r for r in bounded['data_windows'] if int(r['start_va'],16) == 0xa675c0)
    assert table['size'] == 124
    pointers = struct.unpack('<31I', pe.check_range(table))
    assert pointers[0] == 0xa2de90 and pointers[-1] == 0xa2dd98
    names = ['PET','VEHICLE','LAND','DENG','DICE','MOVE','BACK','SUIT','GLASS','COVER','MASK','KITBAG',
             'GOWITH','POCKET','ROLE_PLANE','HOUSE_PLANE','5_ROLE','6_ROLE','7_ROLE','8_ROLE','9_ROLE',
             '1_BOSS','2_BOSS','3_BOSS','4_BOSS','5_BOSS','6_BOSS','7_BOSS','8_BOSS','9_BOSS','10_BOSS']
    data_windows = {int(r['start_va'],16):r for r in bounded['data_windows']}
    for target,name in zip(pointers,names):
        assert pe.check_range(data_windows[target]) == name.encode('ascii')+b'\0'
    resource = json.loads((HERE/'resource_audit.json').read_text('utf-8'))
    packed = (ROOT/resource['source']).read_bytes()
    assert digest(packed) == resource['source_sha256'] and len(packed) == resource['source_size']
    assert resource['section_count'] == 1117 and resource['index_max'] == 3070
    assert len(resource['missing_part_sections']) == 122 and not resource['duplicate_indices']
    assert set(resource['part_histogram']) <= set(names) and resource['role_value_histogram'] == {'true':8271,'false':2899}
    assert 3071*1128 == 3464088
    for doc in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in doc.read_text('utf-8').splitlines()),str(doc)
    result = dict(status='PASS', raw_sha256=raw_digest, dependency_sha256=dep_sha,
                          functions=4, reused_functions=9, bytes=6509, instructions=1658,
                          part_table_entries=31, bridges=37,calls=195, windows=len(windows),window_items=window_items,
                          semantic_anchors=anchor_count,explicit_semantic_checks=len(semantic_tokens),
                          bounds='仅限本文明确生产/释放/消费路径；不代表全部loader、CRT或实机行为已验证')
    (HERE/'author_assembly.txt').write_text('\n'.join(transcript)+'\n','utf-8')
    (HERE/'author_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
