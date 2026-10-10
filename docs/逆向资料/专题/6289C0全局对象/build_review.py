"""从显式原证集合生成逐函数清单；不把导出当完整语义审阅。"""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = ['seed', 'lifetime', 'destructor', 'index', 'accessors']
LOCAL = {
    0x6289C0: ('01_对象布局与生命周期.txt', 'A766E8 懒创建 16 字节对象；异常尾块未完整审阅。'),
    0x7DBDA0: ('01_对象布局与生命周期.txt', '构造仅将 O+4 与 O+0xC 两个数组指针清零。'),
    0x6295C0: ('01_对象布局与生命周期.txt', '标量删除包装先析构，参数低位为 1 时释放对象。'),
    0x7DBDD0: ('01_对象布局与生命周期.txt', '分别 delete[] 两个非空数组，并将指针清零。'),
    0x7DBE50: ('02_Level资源与记录布局.txt', '加载 Level.kpd，填充 160 字节记录；循环界限及异常路径仅局部审阅。'),
    0x7DC330: ('03_VIP记录与访问接口.txt', '双遍读取 VipLev.kpd 的 ITEM，填充 136 字节记录；异常路径未闭合。'),
    0x6B78C0: ('03_VIP记录与访问接口.txt', '按等级索引直接返回 role，未作索引校验。'),
    0x797880: ('03_VIP记录与访问接口.txt', '按等级索引返回 title 缓冲区借用地址。'),
    0x7DC640: ('03_VIP记录与访问接口.txt', '根据本级与下级经验门槛计算进度，异常输入未闭合。'),
    0x7DC730: ('03_VIP记录与访问接口.txt', '按 VIP level 线性查找 icon；未命中返回 -1。'),
    0x7DC7A0: ('03_VIP记录与访问接口.txt', '按 VIP level 线性查找 name；未命中返回常量地址。'),
    0x7DC8A0: ('03_VIP记录与访问接口.txt', '末级取本级 exp，否则取下级 exp；未作索引校验。'),
}


def main():
    functions, sources = {}, {}
    for name in EVIDENCE:
        path = HERE / '证据' / (name + '.json')
        for function in json.loads(path.read_text(encoding='utf-8'))['functions']:
            ea = int(function['va'], 16)
            if ea in functions and functions[ea] != function:
                raise ValueError('函数原证冲突：' + function['va'])
            functions[ea] = function
            sources.setdefault(ea, []).append('证据/' + path.name)
    if functions.keys() != LOCAL.keys():
        raise ValueError('原证与语义清单集合不符')
    rows = []
    lines = ['// ============================================================================',
             '// 6289C0 全局等级配置对象 / 逐函数局部审阅',
             '// ============================================================================', '//']
    for ea in sorted(functions):
        document, conclusion = LOCAL[ea]
        row = dict(va=hex(ea), status='局部语义审阅', conclusion=conclusion,
                   document=document, review_sources=sources[ea],
                   unresolved='异常路径、外部调用与实机行为并未全部闭合。')
        rows.append(row)
        lines += [f'// {ea:08X} / 局部语义审阅', '//   ' + conclusion,
                  '//   原证：' + '；'.join(sources[ea]), '//']
    result = dict(scope='本对象 12 个函数的局部审阅；导航和外部依赖不计语义完成',
                  exported_functions=len(rows), status_counts=dict(Counter(r['status'] for r in rows)),
                  functions=rows)
    (HERE / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (HERE / '逐函数审阅.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(dict(exported_functions=len(rows), status_counts=result['status_counts']), ensure_ascii=False))


if __name__ == '__main__':
    main()
