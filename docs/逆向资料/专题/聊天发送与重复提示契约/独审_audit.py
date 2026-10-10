"""独审只读复核当前IDA块/指令/原证；只写独审文件，不改作者证据与数据库。"""
import hashlib
import itertools
import json
import struct
from pathlib import Path

HERE = Path('F:/大富翁online/Richonline/docs/逆向资料/专题/聊天发送与重复提示契约')
EXE = Path('F:/大富翁online/Richonline/RnClient.exe')


def audit(db):
    import ida_bytes
    data = json.loads((HERE / '证据/chat_contract_discovery.json').read_text(encoding='utf-8'))
    errors, summaries, noncode_heads = [], [], []
    for row in data['functions']:
        va = int(row['va'], 16)
        function = db.functions.get_at(va)
        chunks = list(db.functions.get_chunks(function))
        saved = [(int(r['va'], 16), int(r['end'], 16)) for r in row['chunks']]
        actual = [(c.start_ea, c.end_ea) for c in chunks]
        if saved != actual:
            errors.append(row['va'] + ': 声明块不同')
        for original in row['chunks']:
            if db.bytes.get_bytes_at(int(original['va'], 16), original['size']).hex() != original['ida_hex']:
                errors.append(original['va'] + ': 声明块字节不同')
        all_items = [i for c in chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)]
        heads = {}
        for item in all_items:
            if ida_bytes.is_code(ida_bytes.get_full_flags(item.ea)):
                heads[item.ea] = item.size
            else:
                noncode_heads.append(dict(owner=row['va'], va=hex(item.ea), size=item.size,
                                          ida_hex=db.bytes.get_bytes_at(item.ea,item.size).hex(),
                                          text=db.instructions.get_disassembly(item),
                                          reason='native IDA flags非代码；仍由完整声明块保存并核验'))
        expected = {int(i['va'], 16): i['size'] for i in row['instructions']}
        if heads != expected:
            errors.append(row['va'] + ': 指令声明不同')
        for original in row['instructions']:
            if db.bytes.get_bytes_at(int(original['va'], 16), original['size']).hex() != original['hex']:
                errors.append(original['va'] + ': 指令字节不同')
        summaries.append(dict(va=row['va'], chunks=len(chunks), instructions=len(heads)))
    records = data['thunks'] + data['static_data'] + data['route_tables']
    records += [row['snapshot'] for row in data['globals']]
    for row in records:
        if db.bytes.get_bytes_at(int(row['va'], 16), row['size']).hex() != row['ida_hex']:
            errors.append(row['va'] + ': 数据或跳板不同')
    supplemental = []
    for va, size, purpose in [(0xA33F85, 1, '百分号字符类别'), (0xA33FC4, 1, 'd字符类别'),
                              (0x933C88, 32, 'output八项状态跳表'),
                              (0x933D71, 1, 'd的类型路由索引'),
                              (0x933D14, 60, 'output类型跳表')]:
        supplemental.append(dict(va=hex(va), size=size, ida_hex=db.bytes.get_bytes_at(va, size).hex(), purpose=purpose))
    # 状态索引由上述字符低四位和当前状态共同决定，保存实际消费的两个状态字节。
    for byte_va, prior in [(0xA33F85, 0), (0xA33FC4, 1)]:
        category = db.bytes.get_bytes_at(byte_va, 1)[0] & 15
        va = 0xA33F80 + category * 8 + prior
        supplemental.append(dict(va=hex(va), size=1, ida_hex=db.bytes.get_bytes_at(va, 1).hex(), purpose='实际%d状态转移'))
    getter = db.functions.get_at(0x9342B0)
    getter_chunks = list(db.functions.get_chunks(getter))
    getter_record = dict(va=hex(getter.start_ea),
                         chunks=[dict(va=hex(c.start_ea), size=c.end_ea-c.start_ea,
                                      ida_hex=db.bytes.get_bytes_at(c.start_ea, c.end_ea-c.start_ea).hex()) for c in getter_chunks],
                         instructions=[dict(va=hex(i.ea), size=i.size, text=db.instructions.get_disassembly(i))
                                       for c in getter_chunks for i in db.instructions.get_between(c.start_ea, c.end_ea)])
    result = dict(status='PASS' if not errors else 'FAIL', functions=summaries,
                  errors=errors, supplemental=supplemental, get_int_arg=getter_record,
                  noncode_heads=noncode_heads,
                  head_policy='与作者idautils.Heads + is_code一致；非代码项单列，完整块仍逐字节比对',
                  execution_provenance='独审者编写只读核验，主级审读后使用主级IDA租约代理执行；非独审者独立IDA连接',
                  scope='当前IDA独立复读；完整性不等于业务全函数审阅，补充只限%d状态路径')
    (HERE / '独审_IDA复读.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return dict(status=result['status'], functions=len(summaries), errors=errors, supplemental=len(supplemental))


def offline():
    data = json.loads((HERE / '证据/chat_contract_discovery.json').read_text(encoding='utf-8'))
    image = EXE.read_bytes()
    pe = struct.unpack_from('<I', image, 0x3C)[0]
    assert image[:2] == b'MZ' and image[pe:pe+4] == b'PE\0\0'
    optional = pe + 24
    assert struct.unpack_from('<H', image, optional)[0] == 0x10B
    base = struct.unpack_from('<I', image, optional + 28)[0]
    table = optional + struct.unpack_from('<H', image, pe + 20)[0]
    sections = [struct.unpack_from('<IIII', image, table + 40*i + 8)
                for i in range(struct.unpack_from('<H', image, pe+6)[0])]

    def disk(va, size):
        for _, rva, raw_size, raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw_size:
                return image[raw+delta:raw+delta+size]
        return None

    digest = hashlib.sha256(image).hexdigest()
    assert digest == data['disk_sha256'] == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
    assert data['idb_input_sha256'] != digest
    counters = dict(functions=0, chunks=0, chunk_bytes=0, instructions=0, instruction_bytes=0, e9=0, unmapped_globals=0)
    for f in data['functions']:
        counters['functions'] += 1
        for c in f['chunks']:
            va = int(c['va'], 16)
            assert disk(va, c['size']).hex() == c['ida_hex'] == c['disk_hex']
            counters['chunks'] += 1
            counters['chunk_bytes'] += c['size']
        for i in f['instructions']:
            assert disk(int(i['va'], 16), i['size']).hex() == i['hex']
            counters['instructions'] += 1
            counters['instruction_bytes'] += i['size']
    for r in data['thunks']:
        va = int(r['va'], 16)
        raw = disk(va, 5)
        assert raw.hex() == r['ida_hex'] == r['disk_hex'] and raw[0] == 0xE9
        assert va + 5 + struct.unpack_from('<i', raw, 1)[0] == int(r['target'], 16)
        counters['e9'] += 1
    for r in data['static_data'] + data['route_tables']:
        assert disk(int(r['va'], 16), r['size']).hex() == r['ida_hex'] == r['disk_hex']
    for g in data['globals']:
        r = g['snapshot']
        current = disk(int(r['va'], 16), r['size'])
        if current is None:
            assert r['disk_hex'] is None and r['disk_mapped'] is False and r['equal'] is None
            counters['unmapped_globals'] += 1
        else:
            assert current.hex() == r['ida_hex']
    assert struct.unpack('<4I', disk(0x64A807, 16)) == (0x64A663,0x64A688,0x64A6A7,0x64A688)
    assert struct.unpack('<7I', disk(0x82A3BD, 28)) == (0x829C74,0x829CB8,0x829D5F,0x829D5F,0x829D5F,0x829CFC,0x829D2F)
    noninstruction=[]
    for f in data['functions']:
        covered={address for i in f['instructions'] for address in range(int(i['va'],16),int(i['va'],16)+i['size'])}
        for c in f['chunks']:
            for address in range(int(c['va'],16),int(c['end'],16)):
                if address not in covered:
                    noninstruction.append(dict(owner=f['va'],va=hex(address),disk_hex=disk(address,1).hex()))
    assert noninstruction == [dict(owner='0x922830',va='0x922873',disk_hex='90')]
    supplemental = []
    for character, prior, target in [(ord('%'),0,0x933145),(ord('d'),1,0x9333A5)]:
        category = disk(0xA33F60+character,1)[0] & 15
        signed = struct.unpack('<b',disk(0xA33F80+category*8+prior,1))[0]
        state = signed >> 4
        actual = struct.unpack('<I',disk(0x933C88+state*4,4))[0]
        assert actual == target
        supplemental.append(dict(character=chr(character), prior=prior, category=category, state=state, target=hex(actual)))
    index = disk(0x933D50+ord('d')-ord('C'),1)[0]
    assert struct.unpack('<I',disk(0x933D14+index*4,4))[0] == 0x9337C5
    models = independent_models()
    namespace = {'__name__':'independent_read_only_model', '__file__':str(HERE / '证据/validate_chat_contract.py')}
    exec((HERE / '证据/validate_chat_contract.py').read_text(encoding='utf-8'),namespace)
    def require(value, label):
        assert value, label
    author_cases = namespace['behavioral_models'](require)
    assert author_cases == 140
    live_path = HERE / '独审_IDA复读.json'
    live = None
    if live_path.exists():
        live = json.loads(live_path.read_text(encoding='utf-8'))
        assert not live['errors']
        for r in live['supplemental'] + live['get_int_arg']['chunks']:
            assert disk(int(r['va'],16),r['size']).hex() == r['ida_hex']
    result = dict(status='PASS', disk_sha256=digest, counters=counters, author_model_cases=author_cases,
                  independent_models=models, crt_state_path=supplemental, live_ida_recheck=live is not None,
                  declared_noninstruction_bytes=noninstruction,
                  scope='独立PE映射与边界模型；没有实机/线程/网络验证，虚拟区快照不声明磁盘初值')
    (HERE / '独审_离线结果.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=True))


def independent_models():
    cases = 0
    def u32(n):
        return n & 0xFFFFFFFF
    def signed(n):
        return u32(n)-(1<<32) if u32(n)&0x80000000 else u32(n)
    def gate(interval,last,ticks):
        first = u32(next(ticks))
        if first <= u32(last) or u32(first-last) < u32(interval):
            return False,last,1
        return True,u32(next(ticks)),2
    for row in [(0,0,0,1,False,0,1),(100,0,99,100,False,0,1),(100,0,100,101,True,101,2),
                (100,0xFFFFFFF0,32,33,False,0xFFFFFFF0,1),(300000,5,300005,300006,True,300006,2)]:
        interval,last,first,second,ok,final,reads = row
        assert gate(interval,last,iter([first,second])) == (ok,final,reads)
        cases += 1
    # 独立按分支访问轨迹检查96组：私聊不会调用短门，长门在外层。
    for mode,muted,long_ok,short_ok,same in itertools.product([0,1,2,3,4,0xFFFFFFFF],[0,1],[0,1],[0,1],[0,1]):
        trace=[]
        if muted:
            trace.append('long')
            if not long_ok:
                trace.append('101')
        if '101' not in trace:
            if mode != 2:
                trace.append('short')
                if not short_ok and same:
                    trace.extend(['strcmp','100','set_long_last','flag1'])
            if '100' not in trace:
                trace.extend(['cache','route'])
        assert ('short' in trace) == (mode!=2 and '101' not in trace)
        assert ('cache' in trace) == (not(muted and not long_ok) and (mode==2 or short_ok or not same))
        cases+=1
    # FILE写状态直接建模：cnt减1，负值拒写，错误计数=-1，包装尾NUL不能改变output返回。
    for value,expect in [(0,(b'0',1)),(9,(b'9',1)),(10,(b'1',-1)),(-1,(b'-',-1)),(-2147483648,(b'-',-1)),(2147483647,(b'2',-1))]:
        cnt,flag,output,total=1,0x42,bytearray(),0
        digits=[]
        magnitude=abs(value)
        while not digits or magnitude:
            digits.append(48+magnitude%10)
            magnitude//=10
        text=([45] if value<0 else [])+list(reversed(digits))
        for character in text:
            cnt-=1
            if cnt<0:
                flag|=0x20
                total=-1
                break
            output.append(character)
            total+=1
        original_result=total
        cnt-=1
        if cnt<0:
            flag|=0x20
        else:
            output.append(0)
        assert (bytes(output),original_result)==expect and flag==0x62
        cases+=1
    for cursor in list(range(16))+[-1,-2,-16,-17,-2147483648,2147483647]:
        n=u32(cursor+1)
        transformed=n&0x8000000F
        if transformed&0x80000000:
            transformed=u32((u32(transformed-1)|0xFFFFFFF0)+1)
        dividend=signed(n)
        remainder=abs(dividend)%16 * (-1 if dividend<0 else 1)
        assert signed(transformed)==remainder
        cases+=1
    assert 0x2A80C+340*16==0x2BD4C and 0xA76E70+272==0xA76F80
    assert 0xA77090+2+526==0xA772A0 and 2+525+1==528
    cases+=4
    return dict(cases=cases, gate_reads_and_effects=True, private_short_bypass=True,
                crt_file_effects=True, signed_ring_including_overflow=True,
                copied_original_before_recipient_validation=True)


if __name__ == '__main__':
    offline()
