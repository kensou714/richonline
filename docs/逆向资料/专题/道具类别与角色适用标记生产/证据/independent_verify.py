"""第二十七批独立复核；只读当前PE、Prop原包及冻结原证。"""
import collections
import hashlib
import json
import re
import struct
from pathlib import Path
import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
PE_SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'f60d2bae64a7da9ba09aa55f6ab4689473cd4d14bc8fc34ae50d7ad1c76a7b61'
SEEDS = {0x7fe7d0, 0x7fe9e0, 0x7ff1d0, 0x7ff240}
FINAL_SHA = {
    '00_有限采证实施计划.txt': '8570c62135390efde21ccf205321bbddc264cbd8721f420424198e0513ec7e54',
    '01_阅读入口与对象身份.txt': '300d316a4c37fb31076fc82370e444b94120a7e8a62b8513e1d3f478c4972505',
    '02_记录初值与释放.txt': '80d04878aabd819abb827cdcab3b43b433991174d6c08bdb75bcde10f75fad1f',
    '03_两遍装载与角色标记.txt': '338d8fdc378a0116673dce1322f593d5350f3591efb1055b67a8a2cef6cce0f0',
    '04_类别映射与消费闭环.txt': '15e6ab54772fb4a3ee3972f9ab8d99824e298badf23a817ee1737bb673cdce3b',
    '05_证据范围与协作边界.txt': '8fdfdd652b02814fa0d688129fea777a338274ad8d1924dbf5ae6d75263e2c5b',
    '06_当前Prop资源快照.txt': '3f2ef9f8b0b9b8ec983a5879c30d91420449a37d866ff161ee8f8bd6d7929db2',
    '07_独立审阅报告.txt': '6e8e64f5d5fd5a2ff8217f42cee7062ad3f401d45b5bbc909e9b7648b4e67f6b',
    '函数审阅清单.json': 'b79cc93e620c8d4cc0dcf1e82f1068d63855d4bc8e86af31f699005f36a8d2b4',
    '证据/adapt_author.py': '0b8f912269f7e29c2a242fa54b5bbf13152ed026e979c9128d7805ffd04e53ee',
    '证据/author_assembly.txt': '2a9eb9e996f4a505e43bbcdc8d7fde31d40fbef38d3c20610ea4a9fe013f71f8',
    '证据/author_validation.json': '807c03ac92231ecbcb46d89e389d48f20e73e3ab8a5048fa2a68bfc2c8f60ff5',
    '证据/bounded_raw.json': 'f60d2bae64a7da9ba09aa55f6ab4689473cd4d14bc8fc34ae50d7ad1c76a7b61',
    '证据/dependency_data/bounded_raw.json': '091e32beca3d1cab382b0dde998ced568c85a1c6e965f4ee0a6e75a9bf84a522',
    '证据/export_bounded.py': '43ea0b5c401cc2224e972f50cbbabd16975ef64c1180d6dee02cd6a40edce3cf',
    '证据/export_dependency_data.py': '22a1236b5771882321d443f97bb800d07ec133c8a805cd7c1f727e15519b3ab4',
    '证据/formal_functions.json': '20453cd9fb98b649cca6c74685875c37d7e4e4b70268d38f63851e09944cc53f',
    '证据/resource_audit.json': '2a94215fa0eb3f1596770b3dce34ec46f8824ad62385f735392d96209822461f',
    '证据/resource_audit.py': '932a7aca3c4ed2a94d57a39ba674fe98f280106c2ecae2c7a136339e6da29413',
    '证据/reused_functions.json': 'c4d0b4561b9d461bc14971fb3b449338ad2f7e34fe35ff39856258df50f46ec2',
    '证据/verify_author.py': '674df6315da019f3b3d0b3cff3be1edd7b4f3a331be30abd72fb8db6170fc4fb',
}
DEPENDENCY_SHA = '091e32beca3d1cab382b0dde998ced568c85a1c6e965f4ee0a6e75a9bf84a522'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify():
    image = (ROOT / 'RnClient.exe').read_bytes()
    assert sha(image) == PE_SHA
    nt = struct.unpack_from('<I', image, 60)[0]
    assert image[:2] == b'MZ' and image[nt:nt+4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, nt+24)[0] == 0x10b
    base = struct.unpack_from('<I', image, nt+52)[0]
    at = nt+24+struct.unpack_from('<H', image, nt+20)[0]
    sections = [struct.unpack_from('<4I', image, at+40*i+8)
                for i in range(struct.unpack_from('<H', image, nt+6)[0])]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    ranges, instructions, sources, transcript = set(), {}, {}, []

    def read(va, size):
        offsets = [off+va-base-rva for _, rva, length, off in sections
                   if rva <= va-base and va-base+size <= rva+length]
        assert len(offsets) == 1
        return image[offsets[0]:offsets[0]+size]

    def audit(row):
        va = int(row.get('start_va', row.get('va')), 16)
        payload = read(va, row['size'])
        assert payload.hex() == row['disk_hex'] == row.get('idb_hex', row.get('ida_hex'))
        assert row.get('matching', row.get('equal')) is True
        if 'sha256' in row:
            assert sha(payload) == row['sha256']
        ranges.add((va, len(payload)))
        return va, payload

    def decode(row):
        va, payload = audit(row)
        result = list(decoder.disasm(payload, va))
        assert sum(i.size for i in result) == len(payload)
        for ins in result:
            assert instructions.setdefault(ins.address, ins).bytes == ins.bytes
        return result

    def scan(value):
        if isinstance(value, dict):
            if value.get('disk_hex') is not None and 'size' in value:
                audit(value)
            for child in value.values():
                scan(child)
        elif isinstance(value, list):
            for child in value:
                scan(child)

    payload = (HERE/'bounded_raw.json').read_bytes()
    assert sha(payload) == RAW_SHA
    raw = json.loads(payload)
    assert raw['disk_sha256'] == PE_SHA and raw['schema'] == 'richonline-bounded-preparation-1'
    assert {int(f['seed_va'], 16) for f in raw['functions']} == SEEDS
    assert raw['reused_seeds'] == []
    scan(raw)
    for ref in raw['reuse_sources']:
        path = DOCS / ref['path']
        assert sha(path.read_bytes()) == ref['source_sha256']
        sources[ref['path']] = ref['source_sha256']
    bridges, rows = {}, []
    for f in raw['functions']:
        body = [i for c in f['chunk_byte_ranges'] for i in decode(c)]
        assert len(body) == len(f['assembly'])
        assert {i.address for i in body} == {int(a['site_va'], 16) for a in f['assembly']}
        calls = {i.address: int(i.op_str, 16) for i in body if i.mnemonic == 'call' and i.op_str.startswith('0x')}
        reported = [c for c in raw['calls'] if c['seed_va'] == f['seed_va']]
        assert set(calls) == {int(c['site_va'], 16) for c in reported}
        for c in reported:
            target = calls[int(c['site_va'], 16)]
            assert target == int(c['target_va'], 16)
            for address in c['bridges']:
                assert target == int(address, 16)
                b = read(target, 5)
                assert b[0] == 0xe9
                destination = target+5+struct.unpack_from('<i', b, 1)[0]
                bridges[target] = destination
                target = destination
            assert target == int(c['implementation_va'], 16)
        rows.append(dict(seed_va=f['seed_va'], byte_count=sum(i.size for i in body),
            instruction_count=len(body), chunk_count=len(f['chunk_byte_ranges']), direct_calls=len(calls)))
        transcript += ['// 主体 '+f['seed_va']] + ['// '+hex(i.address)+' '+i.bytes.hex()+' '+i.mnemonic+' '+i.op_str for i in body]
    for row in raw['verified_direct_bridges']:
        body = decode(row)
        assert len(body) == 1 and body[0].mnemonic == 'jmp'
        assert bridges.setdefault(body[0].address, int(body[0].op_str, 16)) == int(body[0].op_str, 16) == int(row['target_va'], 16)
    assert len(bridges) == len(raw['verified_direct_bridges'])
    windows = raw['explicit_owner_windows'] + [e['owner_window'] for edges in raw['incoming'].values() for e in edges if 'owner_window' in e]
    unique_windows = set()
    for w in windows:
        if w['owner_va'] is None:
            assert not w['assembly']
            continue
        body = []
        for row in w['assembly']:
            ins = decode(row['bytes'])
            assert len(ins) == 1 and ins[0].address == int(row['site_va'], 16)
            body.extend(ins)
        assert int(w['site_va'], 16) in {i.address for i in body}
        assert all(a.address+a.size == b.address for a,b in zip(body,body[1:]))
        unique_windows.add((w['owner_va'], w['site_va'], body[0].address, body[-1].address+body[-1].size))
        transcript += ['// 窗口 '+w['site_va']] + ['// '+hex(i.address)+' '+i.bytes.hex()+' '+i.mnemonic+' '+i.op_str for i in body]
    for row in raw['strings']:
        va, payload = audit(row['byte_audit'])
        width = row['unit_width']
        content = bytes.fromhex(row['payload_hex'])
        assert width in (1,2) and int(row['target_va'],16) == va
        assert payload == content + bytes(width) and bytes.fromhex(row['nul_hex']) == bytes(width)
        assert len(content) % width == 0 and all(content[i:i+width] != bytes(width) for i in range(0,len(content),width))
    table_va, table = audit(raw['data_windows'][0])
    assert table_va == 0xa675c0 and len(table) == 124 and len(raw['data_windows']) == 32
    categories = []
    for index, (target, row) in enumerate(zip(struct.unpack('<31I', table), raw['data_windows'][1:])):
        va, payload = audit(row)
        assert va == target and payload[-1] == 0 and b'\0' not in payload[:-1]
        categories.append(dict(index=index, string_va=hex(va), value=payload[:-1].decode('ascii'), payload_hex=payload.hex()))
    # 补证仅为三个回调桥与double零常量，不登记新函数。
    dep_bytes = (HERE/'dependency_data/bounded_raw.json').read_bytes()
    assert sha(dep_bytes) == DEPENDENCY_SHA
    dependency = json.loads(dep_bytes)
    assert not dependency['functions'] and not dependency['seeds']
    scan(dependency)
    assert [(int(x['start_va'],16),x['size']) for x in dependency['data_windows']] == [
        (0x5ff6ea,5),(0x606a5d,5),(0x60bda5,5),(0xa2b480,8)]
    for va, target in [(0x5ff6ea,0x8052a0),(0x606a5d,0x7fe7d0),(0x60bda5,0x7fe9e0)]:
        block = read(va,5)
        assert block[0] == 0xe9 and va+5+struct.unpack_from('<i',block,1)[0] == target
    assert read(0xa2b480,8) == bytes(8)

    # 旧契约直接解码原始字节；不调用作者验证器，也不只相信旧PASS。
    selected = [
        ('专题/NewProps与CombCard配置/证据/reused_raw.json',[1,3,9,14,15]),
        ('专题/NewProps与CombCard配置/证据/supplement_raw.json',[2]),
        ('专题/TeachMode对象与消费者/证据/teachmode_raw.json',[18,56]),
        ('专题/Avatar配置与角色图片/证据/supplement_raw.json',[2]),
        ('专题/角色文本选择与控件消费/证据/formal_functions.json',[0,1]),
        ('专题/名称查找与等待消费者/证据/supplement_formal.json',[2]),
    ]
    sources['专题/NewProps与CombCard配置/证据/supplement_raw.json'] = '3c8e7f35a732a969387f50cefe33cd73f8b8c59add42f7a364ebc77b182cc6e1'
    reused = []
    for source, indices in selected:
        path = DOCS/source
        assert sha(path.read_bytes()) == sources[source]
        content = json.loads(path.read_bytes())
        for index in indices:
            f = content['functions'][index]
            chunks = f.get('chunk_byte_ranges',f.get('chunks'))
            assert chunks
            body = [i for c in chunks for i in decode(c)]
            old_asm = f.get('assembly',f.get('instructions'))
            assert {i.address for i in body} == {int(x.get('site_va',x.get('va')),16) for x in old_asm}
            reused.append(dict(source=source,pointer='/functions/'+str(index),va=f['va'],
                instruction_count=len(body),byte_count=sum(i.size for i in body)))
    release_bridge = read(0x60ca48,5)
    assert release_bridge[0] == 0xe9 and 0x60ca4d+struct.unpack_from('<i',release_bridge,1)[0]==0x8052e0

    anchors = {}
    def anchor(va, mnemonic, operand):
        i = instructions[va]
        assert (i.mnemonic,i.op_str) == (mnemonic,operand), (hex(va),i.mnemonic,i.op_str)
        anchors[hex(va)] = dict(hex=i.bytes.hex(),mnemonic=mnemonic,operand=operand)
    for row in [
        (0x7fe7ea,'add','eax, 0xa4'),(0x7fe7e3,'push','8'),(0x7fe7e5,'push','0xc'),
        (0x7fe7f8,'mov','dword ptr [ecx], 0xffffffff'),
        (0x7fe801,'mov','dword ptr [edx + 0xc], 0xffffffff'),
        (0x7fe815,'mov','dword ptr [ecx + 0x14], 0'),
        (0x7fe841,'fstp','qword ptr [eax + 0x1c]'),(0x7fe84d,'fstp','qword ptr [ecx + 0x24]'),
        (0x7fe859,'fstp','qword ptr [edx + 0x2c]'),(0x7fe865,'fstp','qword ptr [eax + 0x34]'),
        (0x7fe9fa,'cmp','dword ptr [eax + 0x14], 0'),(0x7fe9fe,'je','0x7fea1f'),
        (0x7fea0d,'call','0x601cd3'),(0x7fea18,'mov','dword ptr [ecx + 0x14], 0'),
        (0x7ff09d,'cmp','dword ptr [eax], 0'),(0x7ff0a0,'je','0x7ff0d5'),
        (0x7ff0b6,'push','3'),(0x7ff0bb,'call','0x60ca48'),
        (0x7ff0cf,'mov','dword ptr [ecx], 0'),
        (0x7ff1f9,'cmp','dword ptr [ebp - 8], 0x1f'),(0x7ff1fd,'jae','0x7ff221'),
        (0x7ff202,'mov','edx, dword ptr [ecx*4 + 0xa675c0]'),(0x7ff20e,'call','0x61038c'),
        (0x7ff218,'jne','0x7ff21f'),(0x7ff21a,'mov','eax, dword ptr [ebp - 8]'),
        (0x7ff221,'or','eax, 0xffffffff'),(0x7ff231,'ret','4'),
        (0x7ff2d1,'call','0x60e29e'),(0x7ff2d6,'mov','dword ptr [ebp - 0x3c], eax'),
        (0x7ff30c,'mov','dword ptr [ecx + 4], 0'),(0x7ff36d,'jle','0x7ff378'),
        (0x7ff380,'add','eax, 1'),(0x7ff3aa,'imul','ecx, ecx, 0x468'),
        (0x7ff3b0,'add','ecx, 4'),(0x7ff3cd,'je','0x7ff413'),
        (0x7ff3e2,'push','0x606a5d'),(0x7ff3dd,'push','0x60bda5'),
        (0x7ff436,'mov','dword ptr [edx], eax'),(0x7ff492,'imul','eax, eax, 0x468'),
        (0x7ff664,'je','0x7ff69e'),(0x7ff687,'call','0x603781'),
        (0x7ff69a,'mov','dword ptr [ecx + edx + 0xc], eax'),
        (0x7ff6ea,'mov','eax, dword ptr [ebp - 0x3c]'),(0x7ff6ee,'call','0x609997'),
        (0x7ff710,'mov','dword ptr [eax + ecx + 0x14], edx'),
        (0x7ff72c,'jge','0x7ff7c6'),(0x7ff747,'mov','byte ptr [edx + eax], 1'),
        (0x7ff74f,'push','0xa2deec'),(0x7ff770,'call','0x609528'),
        (0x7ff777,'je','0x7ff7c1'),(0x7ff790,'push','0xa2def4'),
        (0x7ff79c,'call','0x61038c'),(0x7ff7a4,'neg','eax'),
        (0x7ff7a6,'sbb','eax, eax'),(0x7ff7a8,'inc','eax'),
        (0x7ff7be,'mov','byte ptr [ecx + edx], al'),(0x7ff7c1,'jmp','0x7ff71d'),
        (0x6465a1,'mov','eax, dword ptr [eax]'),(0x646621,'imul','eax, eax, 0x468'),
        (0x64662c,'mov','eax, dword ptr [edx + eax + 0x14]'),(0x646633,'mov','al, byte ptr [eax + ecx]'),
        (0x7014b1,'imul','eax, eax, 0x468'),(0x7014bc,'mov','eax, dword ptr [edx + eax + 0xc]'),
        (0x6f4ddf,'cmp','eax, 2'),(0x6f4df0,'cmp','eax, 7'),
        (0x6f4e2e,'movzx','eax, al'),(0x6f4e33,'jne','0x6f4e37'),
        (0x6f4e3c,'add','ecx, 0x28'),(0x6f4e40,'push','0x2f'),
        (0x6f4e42,'push','0xa'),(0x6f4e50,'jmp','0x6f4e55'),
    ]: anchor(*row)

    # 独立按物理段边界切包，并与作者每个目标键的原行/偏移比对。
    packed_file = (ROOT/'Data/Prop.kpd').read_bytes()
    assert sha(packed_file) == '1d9c90b96f051af3a77105dc9baf3672f45f25bd37c865050b81bf81182e91d4'
    decoded = bytes((b-packed_file[0])&255 for b in packed_file[1:])
    plain_len, packed_len = struct.unpack_from('<II',decoded)
    assert packed_len == len(decoded)-8
    plain = lzokay.decompress(decoded[8:],plain_len)
    assert sha(plain) == 'ae57f27ead85451fdbd686883e815c10da6083bde431534a449722f62409d067'
    assert len(plain) == plain_len == 546487
    for codec in ('cp950','gb18030'): assert plain.decode(codec).encode(codec) == plain
    marks = list(re.finditer(rb'(?m)^\[PROP\]\r?$',plain))
    assert len(marks) == 1117
    author_resource = json.loads((HERE/'resource_audit.json').read_bytes())
    parts, roles, values, ids, missing = collections.Counter(),collections.Counter(),collections.Counter(),[],[]
    checked_lines = 0
    for index,start in enumerate(marks):
        end = marks[index+1].start() if index+1<len(marks) else len(plain)
        block = plain[start.end():end]
        fields = list(re.finditer(rb'(?m)^(indx|part|ROLE[0-9]+)[ \t]*=[ \t]*([^\r\n]*)\r?$',block))
        observed = []
        for m in fields:
            offset = start.end()+m.start()
            line_end = plain.find(b'\n',offset)
            rawline = plain[offset:line_end if line_end>=0 else len(plain)].rstrip(b'\r')
            key,value = m.group(1).decode('ascii'),m.group(2).decode('cp950')
            observed.append(dict(key=key,value=value,value_hex=m.group(2).hex(),raw_line_hex=rawline.hex(),
                source_line=plain.count(b'\n',0,offset)+1,source_offset=offset))
            if key=='indx': ids.append(int(value))
            elif key=='part': parts[value]+=1
            else: roles[key]+=1; values[value]+=1
        section = author_resource['sections'][index]
        assert section['entries'] == observed
        assert section['source_offset'] == start.start()
        if not any(x['key']=='part' for x in observed): missing.append(index)
        checked_lines += len(observed)
    assert len(ids)==len(set(ids))==1117 and min(ids)==1 and max(ids)==3070
    assert author_resource['part_histogram']==dict(parts) and author_resource['missing_part_sections']==missing
    assert author_resource['role_key_histogram']==dict(roles) and author_resource['role_value_histogram']==dict(values)
    assert len(missing)==122 and roles=={f'ROLE{i}':1117 for i in range(10)}
    assert values=={'true':8271,'false':2899}
    assert set(parts)<=set(x['value'] for x in categories)
    assert categories[2]['value']=='LAND' and categories[7]['value']=='SUIT'
    assert read(0xa2dedc,5)==b'part\0' and read(0xa2deec,7)==b'ROLE%d\0' and read(0xa2def4,5)==b'true\0'

    # 有限契约模型仅复核分支/算术；不冒充执行整份loader或CRT。
    cases = []
    for value,expected in [(None,1),('true',1),('false',0),('TRUE',0),('',0),('true ',0),('truex',0)]:
        result = 1 if value is None else int(value=='true')
        assert result==expected
        cases.append(dict(kind='ROLE缺键及比较',input=value,expected=expected))
    for result in [0,1,0xffffffff,0x80000000,0x7fffffff]:
        carry = int(result!=0)  # NEG非零置CF；SBB eax,eax随后INC。
        normalized = ((-carry)&0xffffffff)+1
        normalized &= 0xffffffff
        assert normalized==int(result==0)
        cases.append(dict(kind='NEG_SBB_INC',input=hex(result),expected=normalized))
    for value in [x['value'] for x in categories]+['suit','unknown','']:
        found = next((i for i,x in enumerate(categories) if x['value']==value),-1)
        assert (found>=0)==(value in [x['value'] for x in categories])
        cases.append(dict(kind='part有序全等',input=value,expected=found))
    for n in [0,1,10,-1,-2147483648]:
        cases.append(dict(kind='角色计数有符号门',input=n,allocation_argument=n&0xffffffff,
            iterations=max(n,0),scope='只算有符号循环；不调用分配器'))
    resource_result = dict(source_sha256=sha(packed_file),plain_sha256=sha(plain),section_count=len(marks),
        checked_selected_lines=checked_lines,part_histogram=dict(parts),role_values=dict(values),missing_part=len(missing))
    formal = json.loads((HERE/'formal_functions.json').read_bytes())
    old_formal = json.loads((HERE/'reused_functions.json').read_bytes())
    assert [int(f['va'],16) for f in formal['functions']] == sorted(SEEDS)
    assert len(old_formal['functions']) == 9
    adapted_count = 0
    for adapted in formal['functions']+old_formal['functions']:
        original_bytes = (DOCS/adapted['source_path']).read_bytes()
        assert sha(original_bytes) == adapted['source_sha256']
        original = json.loads(original_bytes)
        for token in adapted['source_pointer'].strip('/').split('/'):
            original = original[int(token)] if isinstance(original,list) else original[token]
        assert all(adapted[key]==value for key,value in original.items())
        chunks = original.get('chunk_byte_ranges',original.get('chunks',original.get('byte_ranges')))
        assert len(chunks)==len(adapted['normalized_chunks'])
        for chunk,normalized in zip(chunks,adapted['normalized_chunks']):
            assert int(normalized['start_va'],16)==int(chunk.get('start_va',chunk.get('va')),16)
            assert normalized['size']==chunk['size']
            audit(chunk)
        source_asm = original.get('assembly',original.get('instructions'))
        assert [x['original'] for x in adapted['normalized_assembly']] == source_asm
        assert [int(x['site_va'],16) for x in adapted['normalized_assembly']] == [
            int(x.get('site_va',x.get('va')),16) for x in source_asm]
        adapted_count += 1
    ledger = json.loads((HERE.parent/'函数审阅清单.json').read_bytes())
    assert ledger['raw_source_sha256']==RAW_SHA and ledger['disk_sha256']==PE_SHA
    assert [int(f['va'],16) for f in ledger['functions']]==sorted(SEEDS)
    assert [f['status'] for f in ledger['functions']]==['静态契约已审阅']*3+['局部路径已核']
    for f,body in zip(ledger['functions'],formal['functions']):
        assert f['declared_chunks']==body['declared_chunks']
        assert f['instruction_count']==len(body['assembly'])
        texts = {x['site_va']:x['text'] for x in body['assembly']}
        for a in f['semantic_anchors']:
            assert texts[a['site_va']]==a['ida_text'] and int(a['site_va'],16) in instructions
    for doc in HERE.parent.glob('*.txt'):
        assert all(not line.strip() or line.startswith('//') for line in doc.read_text('utf8').splitlines())
    final = {}
    for name, expected in FINAL_SHA.items():
        actual = sha((HERE.parent/name).read_bytes())
        assert actual == expected
        final[name] = actual
    result = dict(status='PASS' if FINAL_SHA else '原证预核通过；语义与终稿待核', pe_sha256=PE_SHA,
        raw_sha256=RAW_SHA, functions=rows, unique_bridges=len(bridges), original_window_count=len(windows),
        unique_window_count=len(unique_windows), unique_byte_ranges=len(ranges), strings=len(raw['strings']),
        categories=categories, sources=sources, dependency_sha256=DEPENDENCY_SHA,reused_contracts=reused,
        old_release_bridge_current_pe=dict(va='0x60ca48',hex=release_bridge.hex(),target='0x8052e0',
            scope='旧调用元数据的离线PE复核，不新增IDA桥条目'),
        semantic_anchors=anchors,finite_contract_cases=cases,independent_resource=resource_result,
        lossless_adapted_records=adapted_count,explicit_review_records=len(ledger['functions']),
        reviewed_final_sha256=final)
    (HERE/'independent_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
    (HERE/'independent_assembly.txt').write_text('\n'.join(line.rstrip() for line in transcript)+'\n','utf-8')
    print(result['status'], rows)
    return result


if __name__ == '__main__':
    verify()
