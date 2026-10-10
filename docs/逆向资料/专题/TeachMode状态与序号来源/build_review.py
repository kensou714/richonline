"""显式登记函数审阅层级；偏移候选不进入函数完成计数。"""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
FULL = '完整函数静态审阅'
PART = '字段或调用路径局部审阅'
REUSE = '既有完整审阅复用'
REVIEWS = {
    '0x63e210': (FULL, '返回this+1628；不代表所有同偏移对象相同。'),
    '0x7284b0': (REUSE, '返回this+104的DWORD，复用既有完整审阅。'),
    '0x6a14b0': (REUSE, '非空、长度足够及字节2谓词，复用既有完整审阅。'),
    '0x69df50': (PART, '构造明确清this+604；其它成员不整体提升。'),
    '0x6a11e0': (FULL, '分派47返回值直接覆盖this+604，无本地复制/释放。'),
    '0x6a1660': (FULL, '按64F200返回地址首DWORD是否为2选175或5基数，检查状态串指针/长度/字节2。'),
    '0x6a18b0': (FULL, '110+7*参数起扫描最多7字节，遇1停止，默认4。'),
    '0x6a21a0': (PART, '源对象+104复制到this+1064，排除当前P+104写入。'),
    '0x728c10': (PART, '+104是频道数量来源及36*N分配路径；未提升全部UI逻辑。'),
    '0x72c050': (PART, '+104保存GetTickCount，排除序号字段。'),
    '0x72c2d0': (PART, '标志0x20分支更新+104计时，排除序号字段。'),
    '0x628270': (FULL, 'A76728首次分配0xABC并构造，返回单例。'),
    '0x6ac390': (PART, '恢复原ECX并刷新604；其余通知与UI链未知。'),
    '0x6afa40': (FULL, '恢复ECX后刷新604，返回清4字节实参。'),
    '0x82b090': (PART, '只核case47的对象/字符指针访问链。'),
    '0x82a900': (FULL, '返回DWORD[this+80]。'),
    '0x82ab80': (FULL, '返回DWORD[this+32]。'),
    '0x82bc80': (FULL, '保留this并以this+104调用字符串包装访问器。'),
    '0x8976e0': (FULL, '低位门控构造静态单例并登记atexit回调。'),
    '0x62b8e0': (FULL, '保存恢复ECX并调用62BB80。'),
    '0x897440': (PART, '构造中清+32；其它子对象助手未展开。'),
    '0xa205f0': (FULL, '退出回调以静态this调用8974F0。'),
    '0x62bb80': (FULL, '按无符号+24<16选择内嵌+4或堆指针。'),
    '0x8974f0': (PART, '循环对条目+28对象调用虚表首槽(1)；完整类型/容器未闭合。'),
}
UNKNOWNS = {
    '0x63e210': '根对象G的构造、反序列化及P整体复制尚未闭合。',
    '0x7284b0': 'P+104的写入者、初始化、有效范围及网络来源未知。',
    '0x6a14b0': '字节2的完整枚举、索引合法范围及状态内容生产未知。',
    '0x69df50': '只核H+604清零，其余成员构造及清理未整体审阅。',
    '0x6a11e0': '返回字符地址的有效寿命、刷新时序及状态内容生产未知。',
    '0x6a1660': '64F200返回地址的空值保障、条件对象来源、业务语义及参数范围未知。',
    '0x6a18b0': '底层容量与参数范围未知，静态边界不足以宣布实机越界。',
    '0x6a21a0': '源+104的类型和业务语义未知，未证明属于P。',
    '0x728c10': '仅审频道数量与分配路径，其余UI分支和管理器类型未审。',
    '0x72c050': '仅审+104计时写入，宿主完整状态与调用时序未审。',
    '0x72c2d0': '仅审0x20标志下计时更新，其余分支未整体审阅。',
    '0x628270': '单例的完整析构责任及H其它成员语义未知。',
    '0x6ac390': '其余通知/UI助手与实际刷新可达时序未知。',
    '0x6afa40': '外层调用方语义及刷新可达时序未知。',
    '0x82b090': '只审case47，其余分派分支未提升为完整审阅。',
    '0x82a900': 'A对象的建立、替换和析构责任未知。',
    '0x82ab80': 'U对象的建立、替换和析构责任未知。',
    '0x82bc80': 'S内容写入、重分配及精确字符串ABI未知。',
    '0x8976e0': 'M内部业务、线程同步性质及管理对象填充来源未知。',
    '0x62b8e0': '该包装器的外部调用语义与返回地址寿命未知。',
    '0x897440': '仅核M+32清零，外部构造助手未展开。',
    '0xa205f0': '仅闭合静态this到退出本体，容器与条目精确类型未知。',
    '0x62bb80': '只按汇编认定内嵌/堆选择，精确ABI及缓冲寿命未知。',
    '0x8974f0': '条目/容器类型及外部清理助手未完整恢复。',
}


def main():
    rows = []
    for file in sorted((HERE / '证据').glob('*_raw.json')):
        raw = json.loads(file.read_text(encoding='utf-8'))
        for index, function in enumerate(raw['functions']):
            status, conclusion = REVIEWS[function['va']]
            rows.append(dict(va=function['va'], status=status, conclusion=conclusion,
                             unknown=UNKNOWNS[function['va']],
                             evidence=f'证据/{file.name}#/functions/{index}',
                             document='01_状态串来源与对象边界.txt' if function['va'] not in {
                                 '0x6a14b0', '0x7284b0', '0x6a1660', '0x6a18b0',
                                 '0x6a21a0', '0x728c10', '0x72c050', '0x72c2d0'}
                             else '02_复合状态与序号未闭合项.txt'))
    assert {r['va'] for r in rows} == set(REVIEWS)
    assert set(UNKNOWNS) == set(REVIEWS)
    assert len(rows) == len(REVIEWS)
    result = dict(schema=1, scope='状态串字符地址来源；当前序号写入未闭合；显式偏移扫描仅候选',
                  functions=rows, status_counts=dict(Counter(r['status'] for r in rows)))
    (HERE / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result['status_counts'], ensure_ascii=False))


if __name__ == '__main__':
    main()
