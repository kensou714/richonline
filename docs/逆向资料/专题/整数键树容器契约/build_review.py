"""依据显式审阅映射生成中文逐函数记录；未映射入口保持仅导出。"""
import json
from collections import Counter
from pathlib import Path
from export_supplement import GROUPS

HERE = Path(__file__).resolve().parent
LOCAL = {
    0x8BC3A0: ('01', '缺键默认插入，已有键保留原值，返回 mapped 地址。'),
    0x8BC6C0: ('01', 'lower_bound 后严格等价检查，缺键返回 end，不新增。'),
    0x8BE000: ('01', 'cmp/sbb/neg 核为无符号 DWORD 严格小于。'),
    0x8C0F70: ('01', '首个 >= key 节点，未命中返回 head，不分配。'),
    0x8BC4E0: ('01', '100 次36字节默认构造并 count=0。'),
    0x8BC550: ('01', '单条36字节清零。'),
    0x8C0390: ('01', '复制4字节键和3604字节值。'),
    0x8BBFA0: ('01', 'ACBD94 缺键返回0，已有键返回借用 mapped。'),
    0x8BC040: ('01', 'ACBD94 缺键0，已有键取 mapped+3600 count。'),
    0x8C0700: ('02', '机器码唯一键路径，等价返回旧节点不替换。'),
    0x8BD5E0: ('02', 'hint 区间检查与回退，仅局部插入契约。'),
    0x8C09C0: ('02', '容量检查、分配后链入和红黑插入修复，异常非全闭合。'),
    0x8C3DF0: ('02', '左旋更新根与父子连接，过滤 isNil 子节点。'),
    0x8C4000: ('02', '右旋更新根与父子连接，过滤 isNil 子节点。'),
    0x8C41B0: ('02', '单节点分配/构造，catch delete 后重抛。'),
    0x8C6AD0: ('01', '三个link及3608字节pair，两次独立BYTE写color参数和isNil=0。'),
    0x8C6DD0: ('02', 'operator new(3624*count)，本函数无乘法检查。'),
    0x8C59D0: ('02', '常量1190401等于UINT_MAX/3608，与节点尺寸有差异。'),
    0x8C1090: ('02', '释放传入指针，数量参数不参与 delete。'),
    0x8C7080: ('02', '存head，isNil=1，三link自指，size=0。'),
    0x8C7200: ('02', '分配head，三link零初始化，color=1/isNil=0。'),
    0x8BC610: ('02', '删除真实子树，重置head三link和size，保留head。'),
    0x8BDE10: ('02', 'isNil停止；右递归、左循环，值析构后delete。'),
    0x8BB180: ('02', '只闭合ACBD94 clear调用边界，其余连接清理另审。'),
    0x8C9030: ('02', '完整范围erase后head link清理和delete，T+4/T+8=0。'),
    0x8C9150: ('02', '完整范围选择clear；任意erase修复未闭合。'),
    0x8C76C0: ('02', 'placement构造单个DWORD link。'),
    0x8BA950: ('03', '仅type0 ACBD94 count存储/复制边界及100槽越界。'),
    0x8CC740: ('03', '当前游标直接DWORD读取后+4，无剩余检查。'),
    0x8BA830: ('03', '当前游标仅相加，无长度比较。'),
}
BRIDGE = {
    0x8BC5B0: 'end 输出迭代器包装。', 0x8BD380: '迭代器首DWORD节点相等。',
    0x8BD580: '键字段 N+12 桥接。', 0x8BDDA0: 'lower_bound 输出迭代器包装。',
    0x8C0030: '迭代器解引用至pair N+12。', 0x8C0080: '取迭代器首DWORD。',
    0x8C0510: 'N+3621 isNil 字段地址。', 0x8C0550: 'N+0 left字段地址。',
    0x8C0590: 'N+4 parent字段地址。', 0x8C05D0: 'N+8 right字段地址。',
    0x8C0610: 'N+12 pair字段地址。', 0x8C3FA0: 'head.parent字段地址。',
    0x8BDEE0: 'head.left字段地址。', 0x8BDF40: 'head.right字段地址。',
    0x8BDFA0: 'head.parent字段地址。', 0x8BFFD0: '迭代器构造桥。',
    0x8C06C0: 'T+8 节点数。', 0x8C1050: '输入身份转换。',
    0x8C3610: '单DWORD零包装，不是完整树clear。', 0x8C3730: '迭代器首DWORD赋节点。',
    0x8C3780: 'N+12 pair字段地址。', 0x8C3D50: 'N+3620 color字段地址。',
    0x8C3D90: 'max_size包装。', 0x8C5410: '单DWORD零初始化。',
    0x8C6F50: '树构造包装。', 0x8C6FC0: '构造包装至head初始化。',
    0x8C7040: 'this身份转换。', 0x8C71C0: 'this身份转换。',
    0x8C7140: '类型包装构造，未命名字段。', 0x8C7480: '类型包装构造，未命名字段。',
    0x8C7500: '类型包装构造局部转发，字段语义未定。',
    0x8C7420: 'link析构包装。', 0x8C7570: 'link placement构造包装。',
    0x8C7610: '空link析构。', 0x8C7640: 'this身份转换。',
    0x8C8F90: '析构包装。', 0x8C8FE0: '析构包装。',
    0x8C10F0: '值析构桥。', 0x8C6D10: '空值析构。',
    0x697780: '异常尾块调用的空包装清理。', 0x8BAF70: '返回reader+4当前指针。',
}


def main():
    functions, sources = {}, {}
    for name in sorted(GROUPS):
        path = HERE / '证据' / (name + '.json')
        for f in json.loads(path.read_text(encoding='utf-8')).get('functions', []):
            ea = int(f['va'], 16)
            functions[ea] = f
            sources.setdefault(ea, []).append('证据/' + path.name)
    missing = (LOCAL.keys() | BRIDGE.keys()) - functions.keys()
    if missing:
        raise ValueError('映射缺原证：' + repr(missing))
    rows, lines = [], ['// ============================================================================',
        '// 逐函数审阅 / 自动生成；等级不等于整函数完成率', '// ============================================================================', '//']
    for ea in sorted(functions):
        status, note, doc = '仅导出', '上下文原证；未新增语义覆盖。', None
        if ea in LOCAL:
            status, (prefix, note) = '局部语义审阅', LOCAL[ea]
            doc = next(p.name for p in HERE.glob(prefix + '_*.txt'))
        elif ea in BRIDGE:
            status, note = '仅桥接核对', BRIDGE[ea]
        row = dict(va=hex(ea), status=status, conclusion=note, document=doc,
                   review_sources=sources[ea], unresolved='仅限明确局部契约；业务全语义和实机验收未闭合。')
        rows.append(row)
        lines += [f'// {ea:08X} / {status}', '//   ' + note,
                  '//   原证：' + '；'.join(sources[ea]), '//']
    counts = dict(Counter(r['status'] for r in rows))
    data = dict(scope='只统计显式局部审阅及桥接；不等于整函数完成率',
                exported_functions=len(rows), status_counts=counts, functions=rows)
    (HERE / '函数审阅清单.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    (HERE / '逐函数审阅.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(exported_functions=len(rows), status_counts=counts), ensure_ascii=False))


if __name__ == '__main__':
    main()
