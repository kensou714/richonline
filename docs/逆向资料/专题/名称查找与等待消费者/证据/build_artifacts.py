"""四新主体无损机械适配；旧记录精确复用，语义与导航分别登记。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '15be75a1ad6266da6a0df0010c3316ec45619f2e78f05ae691ddc50f4a50c1d6'
NETWORK_SHA = 'c609c740a3b6f9e01a6a849feb075a63499235d15bdcc3e040c3110938204b91'
SUPPLEMENT_SHA = '5211fcf04136f28f57a91453be58a22d8f01304f98393371726d06a4ef9770bf'
CONTAINER_SHA = '50b81df4ceb2447338eee2df17334ebc7cc75944b9cc725dc30db056d05071cc'
CONTAINER_NOTES = {
    '0x85b800': ('ECX容器；+4 DWORD为0返回0，否则返回32位(+8减+4)结果算术右移2，普通ret。', ['未验证end>=begin、差值整除4、指针来源或同步；不能据此推出取槽公式。']),
    '0x85b870': ('ECX容器和一个索引；预压索引和两个局部地址，串联85B740/85C660/85BB10，EAX原样返回，ret4。', ['三个下层helper具体参数消费和取槽映射未完全闭合；不能声明base+4*i，不证明数组第i项或所有权。']),
}
SUPPLEMENT_NOTES = {
    '0x858e50': ('无栈参数；以ACB8E8为ECX调用85B800并原样返回EAX，普通ret。', ['count精确字段公式见85B800；全局初始化、并发和清理契约未闭合。']),
    '0x858ea0': ('栈signed索引；负数或不小于再次读取的count返回NULL，否则ACB8E8对象调用85B870取得槽地址后解引用DWORD返回，普通ret。', ['没有slot或槽内指针NULL门；容器具体布局由85B870另核；返回有效期和所有权转移未证。']),
    '0x922830': ('两个字节串的无符号逐字节序比较；相同至NUL返回0，首个不等返回-1或+1；Str1有对齐WORD/DWORD预读。', ['不检查NULL和可读长度；物理宽读取可越过逻辑NUL；编码、对象容量和调用环境另证。']),
    '0x9228e0': ('n为零不读字串并返回0；DF=0时先在Str1最多n字节内扫描NUL，再比较扫描长度，返回无符号字节序的-1/0/+1。', ['不执行cld，依赖DF=0 ABI前提；先扫描可能读过较早的不匹配位置；不检查指针和外部容量。']),
}
REUSE = (
    ('邮件与礼物分组/证据/functions.json', '/functions/9', '0x6aebe0', '指定复用主体；仅本轮查找和分支消费局部审阅'),
    ('大厅玩家记录与装备字段/证据/record_access.json', '/functions/2', '0x64f0c0', '短契约：谓词通过取槽指针+70h，否则NULL'),
    ('4019系列事件/证据/tail_chunk_reexport.json', '/functions/0', '0x6279c0', '短契约：无栈参数getter及普通retn；构造深语义不展开'),
    ('高扇入界面操作辅助/证据/dependency_raw.json', '/functions/0', '0x6e4520', '短契约：slot+4非空及vtable+50h低BYTE谓词'),
    ('提示文本生命周期/证据/lifecycle.json', '/functions/9', '0x6e3b40', '短契约：ECX根、三栈参数、retn0Ch；不晋升完整深语义'),
    ('诊断消息与类型字典/证据/diagnostic_helpers.json', '/functions/13', '0x6e4640', '短契约：ECX根、两栈参数、retn8及vtable+10h转交'),
    ('控件树与对象生命周期/证据/创建与链表.json', '/functions/5', '0x8e2c10', '短契约：按DWORD编号递归查找，可返回NULL，retn8'),
    ('TeachMode状态与序号来源/证据/closure_raw.json', '/functions/0', '0x628270', '短契约：A76728根getter无栈参数；构造深语义不展开'),
)
NOTES = {
    '0x6b20a0': ('ECX对象、栈字串、retn4；先比较对象+42Ch地址，等值返回NULL；否则signed循环，候选与输入最多32字节比较，首个相等返回原候选指针。', ['未见归一化、复制、分配、NULL字串门；getter重新取count且可返回NULL，查找直接交比较；具体容器字段和返回生命周期另证。']),
    '0x6b81d0': ('仅返回ECX+42Ch地址，普通retn；没有读取该地址内容或取索引。', ['不检查ECX合法性，字串容量、终止、生产者及对象生命周期未闭合。']),
    '0x6ad9f0': ('ECX根、输入对象指针、retn4；编号120低BYTE谓词非零跳过；signed WORD输入+4取字串再查找，NULL与非NULL分别调用两组不同消费者。', ['输入长度和指针无本地门；6A8970、629E90深语义及等待/取消身份未知；局部栈地址转交不证明接收者异步持有安全。']),
    '0x73d560': ('ECX界面对象、输入三DWORD，保存输入+8于this+48h；查询编号2/3/6控件，调用vtable+C4h，第二和第三参数仅低BYTE归一化。', ['三个查询无本地NULL门；+C4签名和最终返回契约未知；DWORD高24位保留取反计算，表槽导航不证明已运行注册或用户触发。']),
}
OLD_NOTE = ('332字节条目首空槽更新后entry+10h查找；返回非NULL、返回+21h BYTE非零且entry+144h signed DWORD<=0才走6A8C20，否则重建和两组UI转交。', ['局部满槽未停、字串复制未见容量门；+21h业务生产者、深消费者、线上数据来源和动态触发未闭合。'])


def pointer(value, path):
    for part in path.strip('/').split('/'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def write(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def make_review(row, path, at, payload, note, fresh):
    conclusion, unknown = note
    return dict(va=row['va'], name=row['name'], status='局部语义已审阅', fresh_evidence=fresh,
        conclusion=conclusion, unknown=unknown,
        source_records=[dict(path=path, sha256=hashlib.sha256(payload).hexdigest(), pointer=at)],
        declared_chunks=row.get('declared_chunks', []),
        original_byte_ranges=row.get('chunk_byte_ranges', row.get('byte_ranges', [])),
        anchors=[dict(path=path, pointer=at+'/assembly/'+str(i)+'/text', site_va=x['va'], value=x['text'])
                 for i, x in enumerate(row['assembly']) if x.get('is_code', True)])


def build():
    payload = (HERE / 'bounded_raw.json').read_bytes()
    assert hashlib.sha256(payload).hexdigest() == RAW_SHA
    raw = json.loads(payload)
    assert [x['seed_va'] for x in raw['functions']] == list(NOTES)
    functions = []
    for i, row in enumerate(raw['functions']):
        ranges = [dict(va=c['start_va'], **{k:v for k,v in c.items() if k != 'start_va'}) for c in row['chunk_byte_ranges']]
        functions.append(dict(va=row['seed_va'], end_va=row['end_va'], name=row['name'],
            status='机械适配；语义见function_review.json', pseudocode=row['pseudocode'], decompile_error=row['decompile_error'],
            assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in row['assembly']],
            declared_chunks=[dict(start_va=c['va'], end_va=hex(int(c['va'],16)+c['size']), is_main=c['va']==row['seed_va']) for c in ranges],
            chunk_byte_ranges=ranges, bytes_match_disk=all(c['matching'] for c in ranges),
            source=dict(path='证据/bounded_raw.json', sha256=RAW_SHA, json_pointer='/functions/'+str(i))))
    write('formal_functions.json', dict(schema='richonline-formal-bounded-adaptation-1', disk_sha256=EXPECTED,
        source_sha256=RAW_SHA, functions=functions, scope='四新主体原文/完整声明块无损机械适配；格式转换不增加语义计数'))
    supplement_payload = (HERE/'supplement_raw.json').read_bytes()
    assert hashlib.sha256(supplement_payload).hexdigest()==SUPPLEMENT_SHA
    supplement = json.loads(supplement_payload)
    assert supplement['seeds']==list(SUPPLEMENT_NOTES)
    supplementary = []
    for i,row in enumerate(supplement['functions']):
        ranges = [dict(va=c['start_va'], **{k:v for k,v in c.items() if k!='start_va'}) for c in row['chunk_byte_ranges']]
        supplementary.append(dict(va=row['seed_va'],end_va=row['end_va'],name=row['name'],
            status='必要依赖无损机械适配；语义见function_review.json',pseudocode=row['pseudocode'],decompile_error=row['decompile_error'],
            assembly=[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in row['assembly']],
            declared_chunks=[dict(start_va=c['va'],end_va=hex(int(c['va'],16)+c['size']),is_main=c['va']==row['seed_va']) for c in ranges],
            chunk_byte_ranges=ranges,bytes_match_disk=all(c['matching'] for c in ranges),
            source=dict(path='证据/supplement_raw.json',sha256=SUPPLEMENT_SHA,json_pointer='/functions/'+str(i))))
    write('supplement_formal.json',dict(schema='richonline-formal-bounded-adaptation-1',disk_sha256=EXPECTED,
        source_sha256=SUPPLEMENT_SHA,functions=supplementary,scope='四个必要依赖完整声明块无损适配，保留922873非代码填充'))
    historical=[]
    for name,at,va,key in (
        ('聊天发送与重复提示契约/证据/chat_contract_discovery.json','/functions/29','0x922830','chunks'),
        ('文本过滤与字码转换/证据/functions_raw.json','/functions/28','0x9228e0','chunk_byte_ranges'),
        ('聊天发送与重复提示契约/独审_IDA复读.json','/functions/29','0x922830',None)):
        payload=(TOPICS/name).read_bytes()
        row=pointer(json.loads(payload),at)
        assert row['va']==va
        current=next(x for x in supplementary if x['va']==va)
        if key:
            assert [(c['va'],c['size'],c['disk_hex']) for c in row[key]]==[(c['va'],c['size'],c['disk_hex']) for c in current['chunk_byte_ranges']]
        historical.append(dict(source=dict(path='../../'+name,sha256=hashlib.sha256(payload).hexdigest(),pointer=at),
            original_record=row,comparison='旧完整块与本轮声明块字节相同' if key else '旧独审仅提供块/代码条数，不冒充原始字节',range_key=key))
    write('historical_crt_sources.json',dict(records=historical,
        counting_rule='922830与9228E0是已有全局原证的CRT，本轮重新采证及显式局部审阅，不计全局新入口；fresh_evidence只指本轮采证。'))
    container_payload=(HERE/'container_dependency/bounded_raw.json').read_bytes()
    assert hashlib.sha256(container_payload).hexdigest()==CONTAINER_SHA
    container_raw=json.loads(container_payload)
    container=[]
    for i,row in enumerate(container_raw['functions']):
        ranges=[dict(va=c['start_va'],**{k:v for k,v in c.items() if k!='start_va'}) for c in row['chunk_byte_ranges']]
        container.append(dict(va=row['seed_va'],end_va=row['end_va'],name=row['name'],
            status='必要容器依赖无损适配；下层模板语义限定',pseudocode=row['pseudocode'],decompile_error=row['decompile_error'],
            assembly=[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in row['assembly']],
            declared_chunks=[dict(start_va=c['va'],end_va=hex(int(c['va'],16)+c['size']),is_main=c['va']==row['seed_va']) for c in ranges],
            chunk_byte_ranges=ranges,bytes_match_disk=all(c['matching'] for c in ranges),
            source=dict(path='证据/container_dependency/bounded_raw.json',sha256=CONTAINER_SHA,json_pointer='/functions/'+str(i))))
    assert [x['va'] for x in container]==list(CONTAINER_NOTES)
    write('container_formal.json',dict(schema='richonline-formal-bounded-adaptation-1',disk_sha256=EXPECTED,
        source_sha256=CONTAINER_SHA,functions=container,scope='两必要依赖无损适配；85B870不外推取槽公式'))
    old_path='高扇入函数群筛选/证据/highfanout_raw.json'
    old_payload=(TOPICS/old_path).read_bytes()
    assert hashlib.sha256(old_payload).hexdigest()=='30f3513c2400dc786cc7f5366cef5aed55639e9cd6cd4cb765f5824c8e80b8b2'
    old=json.loads(old_payload)
    index=next(i for i,x in enumerate(old['targets']) if x['va']=='0x85bb10')
    write('container_template_navigation.json',dict(source=dict(path='../../'+old_path,sha256=hashlib.sha256(old_payload).hexdigest(),pointer='/targets/'+str(index)),
        original_record=old['targets'][index],navigation_status='85BB10完整旧原证精确导航，仅确认ECX转发60B7F6；不提升完整模板链'))
    records = []
    for name, at, va, role in REUSE:
        source = (TOPICS / name).read_bytes()
        row = pointer(json.loads(source), at)
        assert row['va'] == va, (name, at, va)
        records.append(dict(va=va, original_record=row, role=role,
            source=dict(path='../../'+name, sha256=hashlib.sha256(source).hexdigest(), pointer=at),
            limitation='原schema原样保存；指定旧主体与短依赖不重复算新入口，不补造原来源块。'))
    write('reused_raw.json', dict(schema='richonline-exact-reused-records-1', records=records))
    navigation = []
    for i, at, owner, site in ((3,42,'0x6aaef0','0x6aaf7d'),(4,101,'0x6ab0d0','0x6ab20c')):
        name = '大厅玩家记录与装备字段/证据/record_lifecycle.json'
        source = (TOPICS / name).read_bytes()
        row = pointer(json.loads(source), '/functions/'+str(i))
        assert row['va']==owner and row['assembly'][at]['va']==site
        navigation.append(dict(owner_va=owner, site_va=site,
            source=dict(path='../../'+name, sha256=hashlib.sha256(source).hexdigest(), pointer='/functions/'+str(i)),
            original_record=row, window_status='仅旧caller原证导航；本轮只核bounded窗口及查找实参局部',
            window_conclusion='call61149E；不将保存旧record或窗口自动晋升为完整owner审阅'))
    write('source_navigation.json', dict(schema='richonline-owner-source-navigation-1', owners=navigation,
        bounded_owner_windows=raw['explicit_owner_windows'], bounded_incoming=raw['incoming'],
        limitation='保留现有xref与字节窗口；无注册或运行可达性声明'))
    network_name = '四类型辅助请求与队列/证据/reused_network.json'
    network_payload = (TOPICS/network_name).read_bytes()
    assert hashlib.sha256(network_payload).hexdigest() == NETWORK_SHA
    network = json.loads(network_payload)
    assert [x['seed_va'] for x in network['functions']] == ['0x6bef20','0x858fb0','0x859980','0x859cc0']
    write('network_production_navigation.json', dict(schema='richonline-exact-network-production-navigation-1',
        source=dict(path='../../'+network_name, sha256=NETWORK_SHA, pointer=''),
        original_document=network,
        navigation_role='第21批旧四函数、嵌套来源、当前单区间与旧版本记录原样保留；不生成新函数审阅项。',
        limitation='858FB0的22h分配、20h复制、+21h写入及ACB8E8转交仅提供写者导航；同一容器关联和getter契约待有限补证。'))
    formal_bytes = (HERE/'formal_functions.json').read_bytes()
    new_reviews = [make_review(row,'证据/formal_functions.json','/functions/'+str(i),formal_bytes,NOTES[row['va']],True)
                   for i,row in enumerate(functions)]
    supplement_bytes=(HERE/'supplement_formal.json').read_bytes()
    new_reviews += [make_review(row,'证据/supplement_formal.json','/functions/'+str(i),supplement_bytes,SUPPLEMENT_NOTES[row['va']],True)
                    for i,row in enumerate(supplementary)]
    container_bytes=(HERE/'container_formal.json').read_bytes()
    new_reviews += [make_review(row,'证据/container_formal.json','/functions/'+str(i),container_bytes,CONTAINER_NOTES[row['va']],True)
                    for i,row in enumerate(container)]
    reused_bytes = (HERE/'reused_raw.json').read_bytes()
    old = make_review(records[0]['original_record'],'证据/reused_raw.json','/records/0/original_record',reused_bytes,OLD_NOTE,False)
    write('../function_review.json', dict(schema='richonline-function-review-1', topic='名称查找与等待消费者', disk_sha256=EXPECTED,
        functions=new_reviews, reused_reviews=[old],
        reused=[dict(va=x['va'], source=x['source'], status=x['role']) for x in records],
        scope='四全局新主本体、六本轮采证依赖（四全局新、两旧CRT重采）与一个指定旧主体局部静态语义；七旧短依赖限定契约，caller窗口、桥及表槽只导航',
        evidence_counting=dict(global_new_functions=8,reacquired_crt_functions=['0x922830','0x9228e0'],
            fresh_evidence_meaning='当前轮次重新采集原证；不等于全局首次出现',historical_sources='证据/historical_crt_sources.json')))
    return dict(fresh_functions=4, supplementary_functions=6, reused_subjects=1, reused_records=len(records), owner_navigation=len(navigation))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
