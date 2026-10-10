"""将显式人工结论与原证关联；不从导出状态推算语义完成。"""
import json
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent
TOPICS = BASE.parent.parent
NOTES = {
    0x623CB0: ('部分分析', 'StockName/StockRace 启动邻域没有检查加载结果。', '其余资源启动、UI69 与整体返回契约未全审。'),
    0x6283E0: ('局部语义已审阅', 'A76744 懒分配 0xCA0 并调用 6284B0，正常结果缓存；无同步。', '全局释放、构造依赖、实际线程使用和分配器异常未闭合。'),
    0x6C0E50: ('局部语义已审阅', '调用 Name/Race 加载、867290 登记 606643，写 74 个回调槽并跳过四槽。', '回调本体、分派消费者、调用约定和业务消息未知。'),
    0x6284B0: ('部分分析', '核一处基类、十处成员构造 ECX 偏移、虚表及七个清理转交尾块。', '62A* 子构造/析构本体和完整 SEH 状态表未全审，字段类型保留未知。'),
    0x6285F0: ('局部语义已审阅', '向 this 委托 memset 零值 0x3D0 字节，返回 this。', '调用者内存有效性和 CRT 依赖未全审。'),
    0x628630: ('局部语义已审阅', '向 this 委托 memset 零值 0x0C 字节，返回 this。', '调用者内存有效性和 CRT 依赖未全审。'),
    0x6C1260: ('部分分析', '逐行 %u%s 加载名称到 +008；sscanf 返回未检查，RTC name 实际 64 字节。', '通用解析器空行/容量行为、字符串与异常析构本体未全审；未作畸形资源实机验证。'),
    0x6C14E0: ('部分分析', 'unit、三段 URL 与连续 RACE 节加载，0x484 记录按 +324 end 追加；首缺节即停。', '缺键默认值、复制/分配异常、业务消费者和加载失败后的可用性未闭合。'),
    0x6C1A60: ('部分分析', '核 28 字节值传字符串、首字节6/长度<=6、补零区间、缺键逐整数搜索和插入后十项检查。', '输出调用者前提、迭代器递增及全部树依赖未闭合；十项上限须空输出前提。'),
    0x6C5510: ('复用已审阅', '复核旧 S 的 EOF 契约：signed(this+94h-this+4)>=signed(this+88h)，AL 返回。', '对象初始化、指针跨度有效性和所有调用者未闭合；保留原 S 来源。'),
    0x6C5550: ('局部语义已审阅', '只将 ECX=this+4 转交 62B8A0 字符串子对象析构，不采信 MFC 自动名。', '字符串析构本体和全部 pair 所有权未全审。'),
    0x6C5580: ('局部语义已审阅', '向 this 委托 memset 零值 0x484 字节，返回 this。', 'CRT 本体与外部指针范围未全审。'),
    0x6C5CC0: ('局部语义已审阅', '有空间时委托复制一条并写回 end，满容量时委托插入包装；相对字段 +4/+8/+C。', '实际复制、容量增长、释放和异常回滚本体未闭合。'),
    0x6C55F0: ('局部语义已审阅', '长度读取 +14h；Size 非零且扩容成功才重复填字符并提交新长度，返回 this。', '最大长度全局常量、扩容失败与 CRT 异常实现未独立闭合。'),
    0x6C56B0: ('局部语义已审阅', 'cdecl 参数转交 memset，字符经 movsx 扩展；返回 memset 结果。', '不验证目标范围，不全审 CRT。'),
    0x6C56E0: ('局部语义已审阅', 'idx>=length 时调用错误依赖，随后返回 buffer+idx；索引返回地址而非字符值。', '错误依赖是否必然不返回及输入有效性未闭合。'),
    0x6C5730: ('局部语义已审阅', '返回字符串 +14h 的长度 DWORD。', '对象布局仅此字段，完整标准库 ABI 未恢复。'),
    0x6C5750: ('局部语义已审阅', '比较字符串 +14h 是否零，以 AL 返回。', '对象布局仅此字段，完整标准库 ABI 未恢复。'),
    0x6C5910: ('局部语义已审阅', '直接返回容器 +8 DWORD，前缀输出用于条目数；自动日期名误识别。', '容器维护 count 的全部链接/删除操作未全审。'),
    0x6C5930: ('部分分析', '无符号键 unique 插入：重复键返回原 iterator/false，新键委托 6C7470 链接。', '节点辅助、前驱遍历、链接/分配依赖未全审；不称红黑树全闭环。'),
    0x6C5BA0: ('局部语义已审阅', '取得 lower_bound，若 end 或 query<candidate 键返回 end，否则输出 candidate。', 'lower_bound 节点辅助和全树完整性未闭合。'),
    0x6C5D70: ('局部语义已审阅', 'begin==0 返回0，否则 signed(end-begin)/0x484，以 idiv 计算。', '依赖三指针处于同一有效存储区，未验证异常字段。'),
    0x6C66F0: ('局部语义已审阅', '复制首 DWORD 键，委托 62B7B0 构造 this+4 字符串，返回 this。', '字符串深复制、分配失败和输入生命周期未全审。'),
    0x6C6740: ('局部语义已审阅', 'thiscall 转交 6C82C0，返回 iterator 的 pair 指针。', '调用者 iterator 有效性未闭合。'),
    0x6C6770: ('局部语义已审阅', '转交 6C6740；pair 首 DWORD 键与 pair 同址。', '调用者 iterator 有效性未闭合。'),
    0x6C6C00: ('部分分析', '依次委托 62BC10/62BBD0/62BAD0，最后传零值和零长度，返回 this。', '空字符串完整初始化布局和分配器依赖未全审。'),
    0x6C6C60: ('局部语义已审阅', 'cdecl node 转交 6C88D0 再 6C7A00，实际返回 node+0x0C 的键地址。', '未验证 node 有效性；IDA Afx_clearerr_s 名称错误。'),
    0x6C6C90: ('部分分析', '读提示插入伪码及核心分支：满足局部键范围走链接，不合适提示回退 6C5930。', '524 条汇编尚未逐条闭合，不能填入完整 reviewed_chunks。'),
    0x6C7420: ('局部语义已审阅', '调用 6C8910 后委托 62DB30 写 iterator，返回输出地址。', '节点查找依赖保留部分分析，62DB30 ABI 只核转交。'),
    0x6C7A00: ('局部语义已审阅', 'cdecl 原样返回参数地址，无字符串或文件行为。', '键首字段语义来自 pair 使用邻域。'),
    0x6C7A10: ('局部语义已审阅', 'cmp/sbb/neg 将两 DWORD 键的无符号小于关系转换为0/1。', '参数地址有效性未验证。'),
    0x6C7A40: ('局部语义已审阅', 'begin==0 返回0，否则 signed(capacity_end-begin)/0x484。', '依赖三指针处于同一有效存储区，未验证异常字段。'),
    0x6C7AA0: ('局部语义已审阅', '取容器 +8 end，ECX=输出 iterator 转交 6CA540，返回输出地址。', '迭代器构造叶子未导出；不能把此包装误称扩容器。'),
    0x6C7AE0: ('部分分析', '保存插入位置相对 begin 的索引，委托 6C8B10 插入1条，再重建输出 iterator。', '搬移、分配、复制和异常回滚依赖未全审；MFC自动名错误。'),
    0x6C7BE0: ('局部语义已审阅', '复制参数转交 6CACF0，返回 dest+0x484*count。', '尚不证明底层实际复制尺寸与复制成功，未闭合异常路径。'),
    0x6C8200: ('局部语义已审阅', '与 6C66F0 同族，首 DWORD 键及 +4 字符串构造。', '字符串深复制、分配失败和输入生命周期未全审。'),
    0x6C8250: ('局部语义已审阅', '写输出首 DWORD iterator 和 +4 BYTE 成功标记，返回 this。', '不覆盖其余 padding；整体插入契约由调用者补充。'),
    0x6C82C0: ('局部语义已审阅', '取 iterator 首 DWORD node，转交 6C88D0 返回 pair=node+0x0C。', '没有 end/sentinel 有效性保护。'),
    0x6C88D0: ('局部语义已审阅', 'cdecl 返回参数+0x0C，node 数据区的最小偏移契约。', '未恢复完整节点结构或所有权。'),
    0x6C8910: ('部分分析', '节点键小于 query 则向一侧走，否则保存候选并向另一侧走，终止时返回候选。', '根/哨兵/左右指针辅助只核调用，未全审节点布局；lower_bound 名称为局部契约。'),
    0x867290: ('局部语义已审阅', '唯一业务写入为参数 DWORD 保存到 ACB970。', '867250 读取者和 6C2530 回调本体尚未审阅，不称网络协议。'),
}

REUSED = {
    '股票与交易流程/证据/stock_core.json': (0x623CB0, 0x6283E0, 0x6C0E50),
    '资源容器候选/证据/candidate_owners.json': (0x6C1260, 0x6C1A60),
    '文本过滤与字码转换/证据/functions_raw.json': (0x6C14E0,),
    '二进制读写游标/证据/cursor_family.json': (0x867290,),
}


def run():
    rows = []
    inputs = [(BASE / name, None) for name in
              ('core_raw.json', 'dependencies_raw.json', 'supplement_raw.json')]
    inputs += [(TOPICS / name, set(addresses)) for name, addresses in REUSED.items()]
    for path, selected in inputs:
        raw = json.loads(path.read_text('utf-8'))
        for f in raw['functions']:
            va = int(f['va'], 16)
            if selected is not None and va not in selected:
                continue
            status, conclusion, unknown = NOTES[va]
            evidence = '专题/' + path.relative_to(TOPICS).as_posix()
            row = dict(va=f['va'], name_from_idb=f['name'], status=status,
                       review_status=status, conclusion=conclusion, unknown=unknown,
                       evidence=[evidence], full_dependency_closure=False,
                       reviewed_chunks=f.get('declared_chunks', [])
                       if status in ('局部语义已审阅', '复用已审阅') else [],
                       outgoing_functions=sorted({c['implementation'] for c in f['calls']}),
                       scope='事实限于正文指明的字段与调用契约；不声明全业务或全库闭合')
            if 'declared_chunks' not in f:
                row['declared_chunk_boundary'] = '复用原证无显式声明块字段，不补造 IDA 声明'
                row['reviewed_evidence_ranges'] = [
                    dict(start_va=r['va'], end_va=hex(int(r['va'], 16) + r['size']))
                    for r in f['byte_ranges']] if va != 0x623CB0 else []
            if selected is not None:
                row['evidence_reused'] = True
                row['reuse_reference'] = evidence
                row['review_kind'] = '已有原证基础上的局部复核与补充'
            else:
                row['evidence_reused'] = va == 0x6C5510
                row['review_kind'] = '新增原证与局部审阅'
            if va == 0x6C5510:
                row['reuse_reference'] = '全量分析/首批人工审阅迁移.json / 0x6c5510 / S'
                row['review_kind'] = '旧 S 结论与声明块复核，不计首次语义审阅'
            rows.append(row)
    rows.sort(key=lambda r: int(r['va'], 16))
    assert len(rows) == len(NOTES) == len({r['va'] for r in rows}) == 41
    result = dict(scope='StockName/StockRace最小函数群；导出不等于分析完成',
                  counts=dict(Counter(r['status'] for r in rows)), functions=rows,
                  supporting_only=['6C5780已有原证仅导航，未新增逐函数审阅',
                                   '6C7470已有红黑链接原证仅依赖复用，未新增完整审阅',
                                   '74对象回调和606643登记桥仅字节导航，未审本体'])
    (BASE / 'function_review.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// ============================================================================',
             '// StockName 与 StockRace / 逐函数审阅清单',
             '// ============================================================================',
             '// 41 个唯一入口；33 个此前无原证/审阅的新增入口，8 个复用入口。',
             '// 本批导出 34 个本体，其中 6C5510 为旧 S 的声明块复核。',
             '// 状态：' + '；'.join(k + ' ' + str(v) for k, v in result['counts'].items()),
             '// 局部语义仅填原证实际声明块；旧 stock_core 无该字段，另列原证范围。',
             '// 部分分析不填完整审阅块；不能据旧原证范围补造 IDA 声明块。',
             '// 所有条目 full_dependency_closure=false；74 回调本体不进入此表。',
             '// 机器来源、未知项、声明块和复用记录见 证据/function_review.json。', '//']
    for row in rows:
        lines.extend(['// ' + row['va'].upper() + ' / ' + row['status'] + ' / ' + row['review_kind'],
                      '// ' + row['conclusion'], '// 未决：' + row['unknown'], '//'])
    (BASE.parent / '05_逐函数审阅清单.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(counts=result['counts'], unique=len(rows)), ensure_ascii=True))


if __name__ == '__main__':
    run()
