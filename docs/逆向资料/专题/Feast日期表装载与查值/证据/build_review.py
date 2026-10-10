"""生成 Feast 局部审阅清单与原证阅读视图；不增加 IDA 覆盖。"""
import collections
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
PREFIX = '专题/Feast日期表装载与查值/证据/'
NOTES = {
    '0x6288b0': ('单例槽 A766D4 为零时分配 340h，无可见构造或目标清零。', '分配失败与其他线程访问未闭合；全局别名不穷尽。'),
    '0x7080d0': ('日期存在门决定图集基号5或65；月日两位文字选资源组10并写控件81..84。', '控件绘制、刷新调度和85/86数值语义未闭合。'),
    '0x7d89d0': ('将首命中槽写C+10h，无匹配或模式门拒绝返回1，通过后13槽分派并传回EAX。', '13业务本体、前门模式意义、输出参数与等待状态未闭合。'),
    '0x7d8be0': ('容器读取成功后按容器长度memcpy，无本地806/832长度门；写两组13BYTE标志并返回1。', '容器长度接受域、故障到达性和异常中目标状态未闭合。'),
    '0x7d8de0': ('按(year-2004)*26查13对signed BYTE月日，返回首槽0..12或-1，无年份范围门。', '其他写入者与上游年份策略未穷尽；未实机验证错误年份。'),
    '0x7d8e60': ('以日期对象getter取年/月/日查表，AL为索引!=-1，不读取两组模式标志。', '所有调用调度与外部别名未穷尽。'),
    '0x7d8eb0': ('优先谓词P0时取326h+slot，否则P1时取333h+slot，均假返0；无slot范围门。', '更深谓词模式语义和其他调用者接受域未全审。'),
    '0x7d90e0': ('读取signed WORD[this+8]。', '全局字段写入者未穷尽。'),
    '0x7eff90': ('将两参数中的日期数据参数转发662DC0。', '注册表与完整网络调度沿用4050专题。'),
    '0x63e590': ('返回根对象this+0C44h内嵌日期状态地址。', '其他日期对象别名未穷尽。'),
    '0x727a70': ('读取signed BYTE[this+0Ah]月候选，由查值链确认用途。', '所有写入者未穷尽。'),
    '0x727a90': ('读取signed BYTE[this+0Bh]日候选，由查值链确认用途。', '所有写入者未穷尽。'),
    '0x63f420': ('读取DWORD[this+83804]，7080D0用于控件85/86。', '该数值的业务命名未恢复。'),
    '0x662dc0': ('包+2校验低BYTE非零后signed取+4/+6/+7并写根对象+0C44h的日期字段。', '校验完整接受域沿用4050；此处无包长和年月日合法性检查。'),
    '0x694320': ('窄写WORD[this+8]与BYTE[this+0Ah/+0Bh]，不修改其余日期状态。', '日期其他写入源和同步调度未穷尽。'),
    '0x63e210': ('返回根对象this+65Ch，日期分发将此地址传给模式门。', '该模式对象完整结构未恢复。'),
    '0x63eca0': ('短路组合63ED10/63ED50的低BYTE非零值，返回BYTE布尔值。', '两个深层谓词与模式编号未在本批展开。'),
    '0x63edf0': ('短路组合63EE90/63EED0/63E160/63E990低BYTE非零值。', '深层谓词与模式编号未在本批闭合。'),
}


def main():
    records, provenance, reused_sources = {}, collections.defaultdict(list), {}
    reused = json.loads((BASE / 'reused_evidence.json').read_text('utf-8'))
    for item in reused['reused']:
        records[item['va']] = item['record']
        provenance[item['va']].append(PREFIX + 'reused_evidence.json')
        reused_sources[item['va']] = item['source']
    for name in ('core_raw.json', 'supplemental_raw.json'):
        for row in json.loads((BASE / name).read_text('utf-8'))['functions']:
            records[row['va']] = row
            provenance[row['va']].append(PREFIX + name)
    if set(records) != set(NOTES):
        raise ValueError('逐函数语义注记与原证入口不一致')
    reviews = []
    for va, row in sorted(records.items(), key=lambda item: int(item[0], 16)):
        conclusion, unknown = NOTES[va]
        is_reused = va in reused_sources
        status = '复用已审阅' if is_reused else '局部语义已审阅'
        review = dict(va=va, name_from_idb=row['name'], status=status, review_status=status,
                      conclusion=conclusion, unknown=unknown, evidence=provenance[va],
                      full_dependency_closure=False, evidence_reused=is_reused,
                      reviewed_chunks=row.get('declared_chunks', []),
                      reviewed_evidence_ranges=row['byte_ranges'],
                      outgoing_functions=sorted({call['implementation'] for call in row['calls']}),
                      declared_chunk_boundary=('显式声明块原证；语义限正文所列路径'
                                               if row.get('declared_chunks')
                                               else '旧原证未独立枚举声明块，不补造尾块'),
                      scope='仅本体与正文所列日期契约，不代表所有依赖或全程序可达性闭合')
        if is_reused:
            review['reuse_reference'] = reused_sources[va]
            review['review_kind'] = '复用局部复核；6288B0/7080D0另重导声明块'
        reviews.append(review)
    context = json.loads((BASE / 'context_raw.json').read_text('utf-8'))
    for row in context['contexts']:
        call = row['owner'] == '0x7c0c50'
        reviews.append(dict(va=row['owner'], status='部分分析', review_status='部分分析',
                            conclusion=('仅7C19E0附近：以前门决定日期分派调用，非零继续，零跳7C2DE1。'
                                        if call else '仅624864附近：删除非零Feast单例槽并置零。'),
                            unknown='其余巨大主体、路径入口与目标语义未展开。',
                            evidence=[PREFIX + 'context_raw.json'], reviewed_chunks=[],
                            reviewed_evidence_ranges=row['instructions'],
                            full_dependency_closure=False,
                            scope='调用点局部，不算完整本体或新增完整函数覆盖'))
    output = dict(scope='Feast局部语义审阅；首次3本体、复用15入口、局部2调用者',
                  counts=dict(collections.Counter(row['status'] for row in reviews)), functions=reviews)
    (BASE / 'function_review.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    text = ['// Feast 逐入口审阅清单', '// 完整证据与未知见证据/function_review.json。']
    for row in reviews:
        text.extend(['//', '// ' + row['va'] + '  ' + row['status'],
                     '// 结论：' + row['conclusion'], '// 未知：' + row['unknown']])
    (BASE.parent / '05_逐入口审阅清单.txt').write_text('\n'.join(text) + '\n', encoding='utf-8')
    assembly, pseudocode = [], []
    for va, row in sorted(records.items(), key=lambda item: int(item[0], 16)):
        assembly.extend(['//', '// ' + va + '  原来源范围见JSON，不补造声明块。'])
        assembly.extend('// ' + ins['va'] + '  ' + ins['text'] for ins in row['assembly'])
        pseudocode.extend(['//', '// ' + va + '  伪码只作辅助，signed字段以汇编为准。'])
        pseudocode.extend('// ' + line for line in row['pseudocode'])
        pseudocode.extend('// 调用 ' + call['site'] + ' -> ' + call['target'] + ' -> ' + call['implementation']
                          for call in row['calls'])
    for row in context['contexts']:
        assembly.append('// 调用点局部 ' + row['site'] + '，不代表完整本体。')
        assembly.extend('// ' + ins['va'] + '  ' + ins['text'] for ins in row['assembly'])
    (BASE / '汇编阅读视图.txt').write_text('\n'.join(assembly) + '\n', encoding='utf-8')
    (BASE / '伪码与调用阅读视图.txt').write_text('\n'.join(pseudocode) + '\n', encoding='utf-8')
    print(json.dumps(output['counts'], ensure_ascii=False))


if __name__ == '__main__':
    main()
