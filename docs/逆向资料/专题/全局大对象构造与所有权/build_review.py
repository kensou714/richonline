"""从显式原证集合生成逐函数清单，未映射地址保持仅导出。"""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = ['candidate_core', 'layout_seeds', 'accessors_and_consumers',
            'consumer_methods', 'record_users', 'text_contract', 'record_finalize']
LOCAL = {
    0x62A1D0: ('01', 'A76734 懒分配 179540 字节；构造和异常表仅局部核对。'),
    0x62A2A0: ('01', '512条与16条340字节数组构造；五DWORD不在构造范围。'),
    0x62A310: ('01', '仅 R+0 和 R+272 两个BYTE置零，不是整条清零。'),
    0x64A430: ('01', '五个元数据DWORD重置；外部副作用未闭合。'),
    0x6B8210: ('01', '全局非零时直接delete并置零，无逐条析构。'),
    0x64C340: ('01', '主数组174080字节memset及三个DWORD置零，尾区不清。'),
    0x6A21A0: ('01', '只闭合入口返回值至ECX和主记录清空调用。'),
    0x64BEA0: ('02', '前移一条，512槽有符号余数与W边界，负游标可达性未定。'),
    0x64BF30: ('02', '后移一条，五条窗口边界；不统一解释EAX返回值。'),
    0x7367B0: ('02', 'N/C从记录对象取出，再写独立控件+0x460/+0x46C。'),
    0x737130: ('02', '控件值与C比较，单步前后移动，返回BYTE1。'),
    0x6A8660: ('03', '只审格式化文本后通过607138追加记录的局部边界。'),
    0x6A87D0: ('03', '只审字符串格式化后通过607138追加记录的局部边界。'),
    0x736D10: ('03', '只审五行矩形命中、关联字符串借用和复制边界。'),
    0x64B880: ('04', '340字节记录字段、430像素分行、双字节推进及无容量检查。'),
    0x64BFE0: ('04', '最多五条文字与属性显示，首次索引无范围校验。'),
    0x64C0A0: ('04', '按五行索引返回借用R+272字符串，未命中返回常量。'),
    0x64BDF0: ('04', 'W环形推进，N饱和512，N超过5或已满时C推进。'),
}
BRIDGE = {
    0x7976F0: '直接读取 O+0x2A804 数量字段。',
    0x797720: '直接读取 O+0x2A808 游标字段。',
    0x796B10: '独立控件+0x460写入参数后转调601742。',
    0x727790: '独立控件+0x46C写入参数后转调601742。',
}


def main():
    funcs, sources = {}, {}
    for name in EVIDENCE:
        path = HERE / '证据' / (name + '.json')
        if not path.is_file():
            raise ValueError('原证缺失：' + str(path))
        for f in json.loads(path.read_text(encoding='utf-8'))['functions']:
            ea = int(f['va'], 16)
            if ea in funcs and funcs[ea] != f:
                raise ValueError('原证重复冲突：' + f['va'])
            funcs[ea] = f
            sources.setdefault(ea, []).append('证据/' + path.name)
    if (LOCAL.keys() | BRIDGE.keys()) - funcs.keys():
        raise ValueError('语义映射缺少原证')
    rows, lines = [], ['// ============================================================================',
        '// 逐函数审阅 / 导出不等于语义完成', '// ============================================================================', '//']
    for ea in sorted(funcs):
        status, note, doc = '仅导出', '上下文或邻近包装器，未新增语义覆盖。', None
        if ea in LOCAL:
            status, (prefix, note) = '局部语义审阅', LOCAL[ea]
            doc = next(p.name for p in HERE.glob(prefix + '_*.txt'))
        elif ea in BRIDGE:
            status, note = '仅桥接核对', BRIDGE[ea]
            doc = '02_游标与界面边界.txt'
        rows.append(dict(va=hex(ea), status=status, conclusion=note, document=doc,
                         review_sources=sources[ea], unresolved='业务全语义、异常表及实机行为未全部闭合。'))
        lines += [f'// {ea:08X} / {status}', '//   ' + note,
                  '//   原证：' + '；'.join(sources[ea]), '//']
    counts = dict(Counter(r['status'] for r in rows))
    result = dict(scope='显式局部审阅与桥接；不等于整函数完成率',
                  exported_functions=len(rows), status_counts=counts, functions=rows)
    (HERE / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (HERE / '逐函数审阅.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(exported_functions=len(rows), status_counts=counts), ensure_ascii=False))


if __name__ == '__main__':
    main()
