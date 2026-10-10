"""第25批：三新主体机械适配，旧原记录原样保存，逐入口人工结论另列。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = {
    '邮件与礼物分组/证据/functions.json': ['0x69e600'],
    '游戏时间与计时调度/证据/functions.json': ['0x6ab5f0'],
    'TeachMode状态与序号来源/证据/producers_raw.json': ['0x69df50'],
    'TeachMode状态与序号来源/证据/closure_raw.json': ['0x628270'],
    'MapView配置记录与预览消费/证据/functions_raw.json': ['0x622d50'],
    '登录与大厅状态/证据/login_wait_completion.json': ['0x6a1190'],
    '大厅玩家记录与装备字段/证据/record_lifecycle.json': ['0x6a2350'],
    '大厅URL读取与缓冲契约/证据/short_helpers_raw.json': ['0x91bd80'],
    '短字符串与缓冲所有权/证据/string_allocation.json': ['0x91bd30'],
    '高扇入函数群筛选/证据/highfanout_raw.json': ['0x91f7e0'],
    '124字节共享记录与判断门/证据/formal_functions.json': ['0x6b7dc0'],
    '124字节共享记录内容写入/证据/formal_functions.json': ['0x6a4dc0', '0x6a4e70', '0x6a51a0'],
}
NOTES = {
    '0x6a4a80': (
        '先调用6A4860，再把DWORD[M+4D0]写N=M+5DC、current=M+5E0置-1；申请124*N主块，经622D50以stride124和callback60D34E初始化后写B=M+5D8；另申请11个4*N列表、清11计数，signed遍历写R(i)+00=i和+78=0。retn无BOOL。',
        'M+4D0上游值域、容量与32位乘移溢出无门；主NULL分支虽存在，但91BD30正常返回非0，异常深契约另限；列表无NULL门/内容初始化/局部EH回滚。5F4和608本重建主路径未释放即覆写，是局部配对缺口，非动态泄漏证明。'),
    '0x6a4860': (
        '依次对非0字段5D8、5E4、5E8、5EC、5F0、5F8、5FC、600、604、60C调用91F7E0并写0，共主数组+9列表。无元素遍历析构、无BOOL结果。',
        '未覆盖5F4/608；不清5DC/5E0/610..638。只有所覆盖指针的重复清理局部安全门；不称完整状态幂等，不推定R+04对象由此拥有或释放。'),
    '0x6b7cb0': (
        '以this为对象，EAX直接返回DWORD[this+4D0]，retn无栈参；6A4A80将结果写入N=+5DC。',
        '无NULL、数量符号、上界、状态门；+4D0写者与其合法值域尚未闭合，返回DWORD不等于BOOL。'),
}
OLD_NOTES = {
    '0x69e600': (
        '完整旧本体含异常尾已读；入口顺序调用6A1190、6A2350、6A76E0、6A4860，均ECX=M。后续释放780/770/77C与514..540等对象、清容器及销毁基类；本体无直接5F4/608释放。',
        '6A1190当前补证承担字节核验；6A76E0不涉及5F4/608，6B9AF0只转6BA4A0，6A1190先转82C4E0。后两深端点未递归审阅，不能由已读本体缺字段宣称全局泄漏。'),
    '0x6ab5f0': (
        'UI73/64查询与UI70(0,0)之后，6AB630以ECX=M无条件调用6A4A80；随后清其他记录及写+AB0=0、BYTE+AB4=0、GetTickCount到+AB8。retn4。',
        '本体未直接读输入arg，也无重建前N/索引/状态门；UI深算法与消息身份未闭合。只审此入口对数组重建的调用前提。'),
}
DEPENDENCY_NOTES = {
    '0x622d50': (
        '四栈参(base,stride,count,callback)，RET10h；count先减1、JS退出，否则ECX=base间接调callback、base+=stride后回环。callback结果不用；本次stride124、callback60D34E。',
        '无base/callback/容量门。count=0及除INT_MIN外负值首轮退出；INT_MIN减1回绕正数例外。回调6B7C60完整补证已审，但其+8深调用6B7BB0未展开，不能称清零全部124字节。'),
    '0x6a2350': (
        '完整291B本体按非0门释放并清4D4、4E0、4E4、4E8、4EC五字段；未读写5F4/608，无业务深调用。',
        '只限定该析构前置清理入口；这五字段与共享数组11列表不合并，未核全部其他owner。'),
    '0x91bd80': (
        'cdecl一参数Size，转调601274桥到91BD30，回传EAX；无NULL转换或本地异常恢复。',
        '只审薄包装ABI；不从自动MFC名字推断业务，newhandler/_Nomemory运行时行为未测试。'),
    '0x91bd30': (
        '重复malloc(Size)，仅malloc非0进入正常返回；malloc0时调用newhandler，handler0再调_Nomemory，若其返回仍回环。',
        '未展开malloc/newhandler/_Nomemory运行时及抛出类型；不能把调用者静态NULL分支说成已证实普通失败返回。'),
    '0x91f7e0': (
        'cdecl一参数指针，转调operator-delete入口后retn；包装无数组遍历或元素析构。',
        '只核包装字节与ABI，不由delete[]显示名推定元素析构/所有权，深层delete allocator不在本批完成清单。'),
}

SUPPLEMENT_NOTES = {
    '0x6b7c60': ('ECX=元素R，6B7C74以ECX=R+8调用60A99B桥到6B7BB0，再6B7C7C将DWORD[R+4]置0；EAX=R，retn无栈参。', '6B7BB0仅端点导航，+8子对象初始化范围未知；本体未写+00/+60..78，不等于全124字节清零或释放旧+04。'),
    '0x6a76e0': ('依次按非0门释放并清DWORD[M+640/644/648/64C/650]，随后无条件清DWORD[M+654/658/65C/660/664]；retn无栈参。', '本体无5F4/608访问；五列表与其后五计数的全部业务含义未展开，不能代替整个M释放图。'),
    '0x6b9af0': ('以ECX=M调用609BB8桥到6BA4A0，随后RTC检查和retn；本体无直接5F4/608访问或分配释放。', '6BA4A0仅已核桥端点导航；自动COleDispParams显示名不证明类型/析构所有权，深释放未闭合。'),
    '0x6a1190': ('当前69B完整补证：ECX=M在6A119E经608024调用82C4E0；返回后6A11A6写DWORD+5E0=-1、6A11B3写DWORD+4F0=-1、6A11C0写BYTE+258=0；retn无栈参。', '82C4E0仅端点导航；本体未直接free或读写5F4/608，深副作用仍未知；不将残留EAX当BOOL。'),
}


def write(name, value):
    (HERE/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def rows(source):
    if isinstance(source, list):
        yield from ((f'/{i}', r) for i, r in enumerate(source))
    elif 'targets' in source:
        yield from ((f'/targets/{i}/function', r['function']) for i, r in enumerate(source['targets']))
    else:
        items = source['functions']
        iterator = items.items() if isinstance(items, dict) else enumerate(items)
        yield from ((f'/functions/{i}', r) for i, r in iterator)


def review(row, path, pointer, payload, notes, level):
    assembly_key = 'assembly' if 'assembly' in row else 'instructions'
    assembly = row[assembly_key]
    assert all(isinstance(x, dict) and x.get('va') for x in assembly)
    anchors = [dict(path=path, pointer=pointer+f'/{assembly_key}/{i}/text', site_va=x['va'], value=x['text'])
               for i, x in enumerate(assembly) if x.get('is_code', True)]
    conclusion, unknown = notes[row['va']]
    return dict(va=row['va'], name=row.get('name', ''), status='局部语义已审阅', review_level=level,
                fresh_evidence=level in ('新主体', '新主体必要依赖补证'), conclusion=conclusion, unknown=[unknown], anchors=anchors,
                declared_chunks=row.get('declared_chunks', row.get('chunks', [])),
                original_byte_ranges=row.get('chunk_byte_ranges', row.get('byte_ranges', row.get('chunks', []))),
                source_records=[dict(path=path, sha256=hashlib.sha256(payload).hexdigest(), pointer=pointer)])


def build():
    raw_bytes = (HERE/'bounded_raw.json').read_bytes()
    raw = json.loads(raw_bytes)
    assert raw['disk_sha256'] == EXPECTED
    functions = []
    for i, row in enumerate(raw['functions']):
        ranges = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'}) for c in row['chunk_byte_ranges']]
        chunks = [dict(start_va=c['va'], end_va=hex(int(c['va'], 16)+c['size']), is_main=c['va'] == row['seed_va']) for c in ranges]
        functions.append(dict(va=row['seed_va'], end_va=row['end_va'], name=row['name'],
              status='机械适配；语义见function_review.json',
              assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in row['assembly']],
              pseudocode=row['pseudocode'], decompile_error=row['decompile_error'],
              declared_chunks=chunks, chunk_byte_ranges=ranges,
              bytes_match_disk=all(c['matching'] for c in ranges),
              source=dict(path='证据/bounded_raw.json', sha256=hashlib.sha256(raw_bytes).hexdigest(), json_pointer=f'/functions/{i}')))
    assert set(x['va'] for x in functions) == set(NOTES)
    write('formal_functions.json', dict(schema='richonline-formal-bounded-adaptation-1', disk_sha256=EXPECTED,
          source_sha256=hashlib.sha256(raw_bytes).hexdigest(), functions=functions,
          scope='3新完整主体含尾机械适配；格式转换不增加语义完成数'))
    records = []
    for name, wanted in SOURCES.items():
        payload = (TOPICS/name).read_bytes()
        source = json.loads(payload)
        found = set()
        for pointer, row in rows(source):
            va = row.get('va', row.get('address'))
            if va not in wanted:
                continue
            found.add(va)
            records.append(dict(va=va, original_record=row,
                source=dict(path='../../'+name, sha256=hashlib.sha256(payload).hexdigest(), pointer=pointer),
                role='旧无VA/无字节字符串汇编，仅导航' if va == '0x6a1190' else '旧原记录原样复用；新增导出主体0',
                limitation='保留原schema全部值；不补造旧元数据。'))
        assert found == set(wanted), (name, found, wanted)
    write('reused_raw.json', dict(schema='richonline-exact-reused-records-1', records=records))
    bridge_name = '大厅URL读取与缓冲契约/证据/short_helpers_raw.json'
    bridge_bytes = (TOPICS/bridge_name).read_bytes()
    bridge_source = json.loads(bridge_bytes)
    bridge_records = [dict(original_record=row,
        source=dict(path='../../'+bridge_name, sha256=hashlib.sha256(bridge_bytes).hexdigest(), pointer=f'/thunks/{i}'),
        role='旧辅助桥原样复用；新增主体0') for i, row in enumerate(bridge_source['thunks']) if row['va'] == '0x601274']
    assert len(bridge_records) == 1
    write('reused_auxiliary.json', dict(schema='richonline-exact-reused-auxiliary-1', records=bridge_records))
    formal_bytes = (HERE/'formal_functions.json').read_bytes()
    supplement_bytes = (HERE/'supplement_raw.json').read_bytes()
    assert hashlib.sha256(supplement_bytes).hexdigest() == 'ddbf83a1e09e062ebaf5dbe06e6418c5ae02b55cd723f0219d6fc93d91eda0b2'
    supplement = json.loads(supplement_bytes)
    supplement_functions = []
    for i, row in enumerate(supplement['functions']):
        ranges = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'}) for c in row['chunk_byte_ranges']]
        supplement_functions.append(dict(va=row['seed_va'], end_va=row['end_va'], name=row['name'],
            status='机械适配；补证语义见function_review.json',
            assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code']) for x in row['assembly']],
            pseudocode=row['pseudocode'], decompile_error=row['decompile_error'], chunk_byte_ranges=ranges,
            declared_chunks=[dict(start_va=c['va'], end_va=hex(int(c['va'], 16)+c['size']), is_main=c['va']==row['seed_va']) for c in ranges],
            bytes_match_disk=all(c['matching'] for c in ranges),
            source=dict(path='证据/supplement_raw.json', sha256=hashlib.sha256(supplement_bytes).hexdigest(), json_pointer=f'/functions/{i}')))
    write('supplement_formal.json', dict(schema='richonline-formal-bounded-adaptation-1', disk_sha256=EXPECTED,
        source_sha256=hashlib.sha256(supplement_bytes).hexdigest(), functions=supplement_functions,
        scope='4必要补证主体无损适配，其中6A1190为旧弱源当前补证；不重计基批'))
    supplement_formal_bytes = (HERE/'supplement_formal.json').read_bytes()
    supplement_reviews = [review(row, '证据/supplement_formal.json', f'/functions/{i}', supplement_formal_bytes,
        SUPPLEMENT_NOTES, '旧弱源当前补证' if row['va']=='0x6a1190' else '新主体必要依赖补证') for i, row in enumerate(supplement_functions)]
    new_reviews = [review(row, '证据/formal_functions.json', f'/functions/{i}', formal_bytes, NOTES, '新主体') for i, row in enumerate(functions)]
    reused_bytes = (HERE/'reused_raw.json').read_bytes()
    old_reviews, dependency_reviews = [], []
    for i, record in enumerate(records):
        va, row = record['va'], record['original_record']
        args = (row, '证据/reused_raw.json', f'/records/{i}/original_record', reused_bytes)
        if va in OLD_NOTES:
            old_reviews.append(review(*args, OLD_NOTES, '旧主体局部生命周期审阅'))
        elif va in DEPENDENCY_NOTES:
            dependency_reviews.append(review(*args, DEPENDENCY_NOTES, '有限依赖ABI与字段配对'))
    write('../function_review.json', dict(schema='richonline-function-review-1', topic='124字节共享数组生命周期',
          disk_sha256=EXPECTED, functions=new_reviews, reused_reviews=old_reviews, dependency_reviews=dependency_reviews,
          supplement_reviews=supplement_reviews,
          reused=[dict(va=r['va'], source=r['source'], status=r['role']) for r in records],
          scope='基批3新主体+2旧主体局部审阅+5旧有限依赖；补证3新必要依赖+1旧弱源当前补证。根及内容writer仅复用；深释放未强闭合。'))
    return dict(fresh=len(new_reviews), reused_reviews=len(old_reviews), dependency_reviews=len(dependency_reviews), reused_records=len(records))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
