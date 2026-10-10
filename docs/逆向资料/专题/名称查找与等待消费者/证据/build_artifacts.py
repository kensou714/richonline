"""四新主体无损机械适配；旧记录精确复用，语义与导航分别登记。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = '15be75a1ad6266da6a0df0010c3316ec45619f2e78f05ae691ddc50f4a50c1d6'
NETWORK_SHA = 'c609c740a3b6f9e01a6a849feb075a63499235d15bdcc3e040c3110938204b91'
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
    '0x6b20a0': ('ECX对象、栈字串、retn4；先比较对象+42Ch地址，等值返回NULL；否则signed循环，候选与输入最多32字节比较，首个相等返回原候选指针。', ['未见归一化、复制、分配、NULL字串门；count/base/stride和比较深契约由有限补证另核，返回有效期不能由无free反推永久。']),
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
    reused_bytes = (HERE/'reused_raw.json').read_bytes()
    old = make_review(records[0]['original_record'],'证据/reused_raw.json','/records/0/original_record',reused_bytes,OLD_NOTE,False)
    write('../function_review.json', dict(schema='richonline-function-review-1', topic='名称查找与等待消费者', disk_sha256=EXPECTED,
        functions=new_reviews, reused_reviews=[old],
        reused=[dict(va=x['va'], source=x['source'], status=x['role']) for x in records],
        scope='四新主体与一个指定旧主体局部静态语义；七短依赖仅限定契约，caller窗口、桥及表槽只导航'))
    return dict(fresh_functions=4, reused_subjects=1, reused_records=len(records), owner_navigation=len(navigation))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
