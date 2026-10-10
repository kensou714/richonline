"""绘制消费原证的无损适配与人工分级；不访问 IDA，不覆盖原证。"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOPICS = HERE.parents[1]
EXPECTED = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
RAW_SHA = 'da3aa15cabf76aa2ee3a30600dca3691491d1dedd57b62c23398e3fdf5fc3fd2'
SEEDS = ('0x8e41d0', '0x90c070', '0x902180', '0x90a430')
NOTES = {
    '0x8e41d0': ('五DWORD栈参、retn14h；mode1..4以固定四色向E+04六词回调提交两轮四边，其他返回mode-1；合法mode最后EAX=0。',
                 ['E本身无NULL门；回调目标、端点实现、颜色格式和实机效果未知；32位坐标运算无溢出/正向门。']),
    '0x90c070': ('普通/节点双路径按16位单元和unsigned BYTE宽度分行，四处提交8EA8D0后经C+238或C+23C十二词绘制，局部几何/颜色/多行门逐分支已核。',
                 ['表E与callback目标及暂存容量/所有权未闭合；+64只判非零；索引、width容量、节点环无门；f除0、signed除法溢出和32位回绕由外部保证。',
                  '8E0A00调用者push四词清10h，旧callee仅读三词；未知项不得由伪码补参数。']),
    '0x902180': ('写18C样式快照；仅mode==5走图索引/字符串，其他走颜色和边框；隐藏仍可执行250h内部fill，254h无颜色门，始终委派90C070。',
                 ['具体控件类别与标记生产者未恢复；表E、样式索引无NULL/范围门；图像/字符串附加参数、资源所有权和callback深目标未知。']),
    '0x90a430': ('写18C样式快照；signed mode>=5走图索引/字符串；其他颜色门决定边框，250h/254h通过才两对角线；可见路径委派90C070。',
                 ['具体控件类别与标记生产者未恢复；表E、样式索引无NULL/范围门；图像/字符串附加参数、资源所有权和callback深目标未知。']),
    '0x8e46e0': ('旧基础绘制可见/样式局部消费重核：mode>=5图索引/字符串，字符串指针及首BYTE门；mode<5颜色fill及mode>0边框。',
                 ['维持部分分析；完整注册、实例类别、资源所有权、回调深目标及实机效果未闭合；本批不升级旧完整语义。']),
}
REUSE = (
    ('控件回调与事件表/证据/基础消费者.json', '/functions/1', '0x8e46e0', '旧主体原证；当前块另重核'),
    ('文本宽度到字符位置/证据/width_position.json', '/functions/1', '0x924fc0', '仅复用16位单元NUL长度契约'),
    ('文本宽度到字符位置/证据/width_position.json', '/functions/4', '0x8e0a00', '仅复用三词宽度谓词消费契约'),
)


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def pointer(node, path):
    for part in path.strip('/').split('/'):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def write(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def review(row, path, where, blob, fresh, status):
    conclusion, unknown = NOTES[row['va']]
    return dict(va=row['va'], name=row['name'], status=status, fresh_evidence=fresh,
                conclusion=conclusion, unknown=unknown, full_dependency_closure=False,
                declared_chunks=row.get('declared_chunks', row.get('chunks', [])),
                original_byte_ranges=row.get('chunk_byte_ranges', row.get('byte_ranges', [])),
                anchors=[dict(path=path, pointer=where + '/assembly/' + str(i) + '/text',
                              site_va=x['va'], value=x['text']) for i, x in enumerate(row['assembly'])],
                source_records=[dict(path=path, sha256=sha(blob), pointer=where)])


def build():
    blob = (HERE / 'bounded_raw.json').read_bytes()
    assert sha(blob) == RAW_SHA
    raw = json.loads(blob)
    assert raw['disk_sha256'] == EXPECTED
    assert tuple(row['seed_va'] for row in raw['functions']) == SEEDS
    functions = []
    for i, row in enumerate(raw['functions']):
        ranges = [dict(va=c['start_va'], **{k: v for k, v in c.items() if k != 'start_va'})
                  for c in row['chunk_byte_ranges']]
        chunks = [dict(start_va=c['va'], end_va=hex(int(c['va'], 16) + c['size']),
                       is_main=c['va'] == row['seed_va']) for c in ranges]
        functions.append(dict(va=row['seed_va'], end_va=row['end_va'], name=row['name'],
                              status='机械适配；语义见function_review.json',
                              assembly=[dict(va=x['site_va'], text=x['text'], is_code=x['is_code'])
                                        for x in row['assembly']],
                              pseudocode=row['pseudocode'], decompile_error=row['decompile_error'],
                              declared_chunks=chunks, chunk_byte_ranges=ranges,
                              bytes_match_disk=all(c['matching'] is True for c in ranges),
                              source=dict(path='证据/bounded_raw.json', sha256=RAW_SHA,
                                          json_pointer='/functions/' + str(i))))
    write('formal_functions.json', dict(schema='richonline-formal-bounded-adaptation-1',
          disk_sha256=EXPECTED, source_sha256=RAW_SHA, functions=functions,
          scope='四新主体指令/伪码/声明块机械无损适配，不增加语义完成结论'))
    records = []
    for path, where, va, role in REUSE:
        source_bytes = (TOPICS / path).read_bytes()
        source = pointer(json.loads(source_bytes), where)
        assert source['va'] == va
        records.append(dict(va=va, original_record=source, role=role,
                            source=dict(path='../../' + path, sha256=sha(source_bytes), pointer=where),
                            limitation='原schema原样保存；没有补造源范围或新增主体'))
    write('reused_raw.json', dict(schema='richonline-exact-reused-records-1', records=records))
    formal_bytes = (HERE / 'formal_functions.json').read_bytes()
    reused_bytes = (HERE / 'reused_raw.json').read_bytes()
    reviews = [review(row, '证据/formal_functions.json', '/functions/' + str(i), formal_bytes,
                      True, '局部语义已审阅') for i, row in enumerate(functions)]
    old_review = review(records[0]['original_record'], '证据/reused_raw.json',
                        '/records/0/original_record', reused_bytes, False, '部分分析')
    write('../function_review.json', dict(schema='richonline-function-review-1',
          topic='基础边框与派生绘制消费', disk_sha256=EXPECTED,
          functions=reviews, reused_reviews=[old_review],
          scope='四新入口局部静态契约、旧8E46E0保持部分分析；caller/桥/辅助不升格完整语义'))
    return dict(fresh_functions=len(functions), reused_records=len(records),
                reused_subject_reviews=1, semantic_instruction_anchors=sum(len(r['anchors']) for r in reviews) + len(old_review['anchors']))


if __name__ == '__main__':
    print(json.dumps(build(), ensure_ascii=True))
