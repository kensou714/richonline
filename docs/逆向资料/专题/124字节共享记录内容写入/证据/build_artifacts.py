"""保存五个新主体的机械适配、原样复用来源及逐入口人工结论。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
SOURCES = {
    '登录与大厅状态/证据/ui_wait_transitions.json': ['0x6aad70'],
    '大厅玩家记录与装备字段/证据/record_lifecycle.json': ['0x6adec0'],
    '角色1416字段来源/证据/functions.json': ['0x6a54f0', '0x693680', '0x63e1a0'],
    '随机地图候选与配置索引/证据/dependencies_raw.json': ['0x64f200'],
    'TeachMode状态与序号来源/证据/closure_raw.json': ['0x82b090'],
    'Pawn四档配置与业务消费/证据/functions_raw.json': ['0x7ba0b0'],
    '大厅玩家记录与装备字段/证据/record_access.json': ['0x629e30', '0x64f090'],
    '游戏分派桥接/证据/property_and_6021_handlers.json': ['0x629ea0', '0x64efd0'],
    '124字节共享记录与判断门/证据/formal_functions.json': ['0x6b7dc0'],
    '文本过滤与字码转换/证据/functions_raw.json': ['0x628ef0', '0x64cdc0'],
    '回合等待与自动选择/证据/pending_functions.json': ['0x627450'],
}
NOTES = {
    '0x6a4dc0': ('直接算B+124*i，清+04/+60/+78 DWORD，四个+64 DWORD置-1、四个+74 BYTE置0；retn4，没有BOOL契约。', 'B/N/索引及对象生命周期无本地门；不清+00及+08..5F，不释放+04。'),
    '0x6a4e70': ('先reset，kind5来源写+04，P+7C非零后复制22DWORD到+08；谓词及signed计数上限通过才填两个列表并把P+20 bit11归一后整DWORD写+78；AL成功结果。', 'P本身、列表指针、实际列表长度、四槽容量及sum溢出无门；失败不回滚已复制内容和外部副作用；DF须为0。'),
    '0x6a51a0': ('kind5来源写+04，直接从P+7C复制22DWORD到+08；不reset、不校验来源、不重建派生字段，retn4非BOOL。', '来源/目标有效性、DF=0及复制长度可读性由外部保证；派生+60/+64/+74/+78可能陈旧。'),
    '0x6ab280': ('signed输入WORD+2先无条件传直接刷新，随后与M+5E0比较决定UI79值4与文本579链；retn4非统一BOOL。', '输入长度、索引及UI深契约未闭合；当前状态比较不是writer前置条件。'),
    '0x6a6e00': ('仅以M+5E0!=-1作状态门，固定扫描四个+64 DWORD；匹配arg后比较当前与arg对象+2C，AL布尔、retn4。', '不看+60/+74/+78；-1哨兵命中可负索引，索引/对象合法性无本地门；owner只读保存窗口。'),
}
OLD_NOTES = {
    '0x6aad70': ('signed输入WORD+2调用完整writer，AL假退出；成功先UI74/75，WORD+4非-1且等M+4F0才写M+5E0、清BYTE+4F4并做后续UI/text链。', '输入长度、所有UI深调用和运行时事件身份未闭合；旧无VA文本仅导航，当前补证承担指令锚点。'),
    '0x6adec0': ('输入WORD+4低12位为1且WORD0当前时置BYTE+4F4；为4或12刷新WORD+2并改UI；随后按WORD0写M+4D4对象槽。', '6A71C0和全部type语义未闭合；输入长度/槽容量无本地门，不代表完整事件生命周期。'),
    '0x6a54f0': ('按M+64对象首DWORD0/1/2/3选择不同M字段逐组双门；否则分类3可通过；通过后比较R+28起16BYTE与7E71E0结果，AL并清局部。', 'callback603FC9、6AAA80和7E71E0深算法未知；不命名MD5/签名；比较不写R、不等于88B复制。'),
}


def write(name, value):
    (HERE/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def review(row, path, pointer, payload, notes, fresh):
    assembly = row['assembly']
    anchors = [dict(path=path, pointer=pointer+'/assembly/'+str(i)+'/text', site_va=x['va'], value=x['text'])
               for i, x in enumerate(assembly) if x.get('is_code', True)]
    conclusion, unknown = notes[row['va']]
    return dict(va=row['va'], name=row['name'], status='局部语义已审阅', fresh_evidence=fresh,
                conclusion=conclusion, unknown=[unknown], anchors=anchors,
                declared_chunks=row.get('declared_chunks', []),
                original_byte_ranges=row.get('chunk_byte_ranges', row.get('byte_ranges', [])),
                source_records=[dict(path=path, sha256=hashlib.sha256(payload).hexdigest(), pointer=pointer)])


def build():
    payload = (HERE/'bounded_raw.json').read_bytes()
    raw = json.loads(payload)
    functions = []
    for index, row in enumerate(raw['functions']):
        ranges = [dict(va=c['start_va'], **{k:v for k,v in c.items() if k!='start_va'}) for c in row['chunk_byte_ranges']]
        chunks = [dict(start_va=c['va'], end_va=hex(int(c['va'],16)+c['size']), is_main=c['va']==row['seed_va']) for c in ranges]
        functions.append(dict(va=row['seed_va'], end_va=row['end_va'], name=row['name'],
                              status='机械适配；语义见function_review.json',
                              assembly=[dict(va=x['site_va'],text=x['text'],is_code=x['is_code']) for x in row['assembly']],
                              pseudocode=row['pseudocode'], decompile_error=row['decompile_error'],
                              declared_chunks=chunks, chunk_byte_ranges=ranges,
                              bytes_match_disk=all(c['matching'] for c in ranges),
                              source=dict(path='证据/bounded_raw.json',sha256=hashlib.sha256(payload).hexdigest(),json_pointer='/functions/'+str(index))))
    write('formal_functions.json', dict(schema='richonline-formal-bounded-adaptation-1', disk_sha256=EXPECTED,
          source_sha256=hashlib.sha256(payload).hexdigest(), functions=functions,
          scope='五新主体原文/声明块机械适配；不计格式转换为新增语义'))
    records = []
    for name, wanted in SOURCES.items():
        source_bytes = (TOPICS/name).read_bytes()
        source = json.loads(source_bytes)
        rows = source if isinstance(source, list) else source['functions']
        iterable = rows.items() if isinstance(rows, dict) else enumerate(rows)
        found = set()
        for index, row in iterable:
            va = row.get('va', row.get('address'))
            if va not in wanted:
                continue
            found.add(va)
            pointer = ('/' if isinstance(source,list) else '/functions/')+str(index)
            records.append(dict(va=va, original_record=row,
                  source=dict(path='../../'+name,sha256=hashlib.sha256(source_bytes).hexdigest(),pointer=pointer),
                  role='旧无VA文本导航；当前补证另列' if va=='0x6aad70' else '旧原证复用；新增原证主体0',
                  limitation='原schema原样保存；不补造原来源声明块。'))
        assert found == set(wanted), (name, found, wanted)
    write('reused_raw.json', dict(schema='richonline-exact-reused-records-1',records=records))
    formal_bytes = (HERE/'formal_functions.json').read_bytes()
    new_reviews = [review(row,'证据/formal_functions.json','/functions/'+str(i),formal_bytes,NOTES,True) for i,row in enumerate(functions)]
    current_bytes = (HERE/'reused_6AAD70_current.json').read_bytes()
    current = json.loads(current_bytes)
    old_reviews = [review(current['functions'][0], '证据/reused_6AAD70_current.json','/functions/0',current_bytes,OLD_NOTES,False)]
    reused_bytes = (HERE/'reused_raw.json').read_bytes()
    for i, record in enumerate(records):
        if record['va'] in OLD_NOTES and record['va']!='0x6aad70':
            old_reviews.append(review(record['original_record'], '证据/reused_raw.json','/records/'+str(i)+'/original_record',reused_bytes,OLD_NOTES,False))
    write('../function_review.json',dict(schema='richonline-function-review-1',topic='124字节共享记录内容写入',
          disk_sha256=EXPECTED,functions=new_reviews,reused_reviews=old_reviews,
          reused=[dict(va=r['va'],source=r['source'],status=r['role']) for r in records],
          scope='5新入口+3旧入口局部语义；桥/owner/其余依赖仅导航或有限契约，未知项不强闭合'))
    return dict(fresh=len(new_reviews),reused_reviews=len(old_reviews),reused_records=len(records))


if __name__ == '__main__':
    print(json.dumps(build(),ensure_ascii=True))
