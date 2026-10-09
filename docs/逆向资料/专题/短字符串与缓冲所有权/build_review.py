"""只从人工逐项结论生成清单，邻近导出和CRT依赖保留原等级。"""
import collections
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACTS = {
    0x62B7B0: '字符串复制构造；初始化短缓冲，再调用源对象子串复制。',
    0x62B830: 'NUL文本构造；初始化后strlen计字节长度再赋值。',
    0x62B8A0: '释放/reset包装，调用62BAD0(1,0)，不释放S自身；MFC自动名失真。',
    0x62B8E0: '保留当前ECX转入62BB80取得data；伪码缺失隐式this。',
    0x62B910: '目标与源子串复制；源pos检查、count裁剪、自赋值双删除、外部复制。',
    0x62BA10: '三参数CRT memcpy包装；不自行检查长度或所有权。',
    0x62BA40: '返回S+20长度字段；MFC自动标识不作库身份依据。',
    0x62BA60: 'strlen输入后62BC50显式字节长度赋值，ECX目标保留。',
    0x62BAB0: 'strlen包装，遇首NUL结束；无编码转换。',
    0x62BAD0: '可选释放堆缓冲并缩回S+4，容量15，重写长度和尾NUL。',
    0x62BB80: '按容量<16返回S+4，否则返回DWORD[S+4]。',
    0x62BBD0: '转入allocator无动作包装并返回this，不写本组长度容量。',
    0x62BC10: '无动作实例包装，返回ECX。',
    0x62BC30: '无动作带参数实例包装，返回ECX并弹参数。',
    0x62BC50: '裸字节赋值；源在现有data半开区间时改走内部子串，否则扩容复制。',
    0x62BD10: 'pos检查、count裁剪、移动尾部并缩长度；实际CRT重叠能力另审。',
    0x62BDE0: '转入CRT memcpy_0标名入口；不凭标名推标准库重叠契约。',
    0x62BE10: '写S+20长度并向真实data+length写单个零字节，不检查容量。',
    0x62BE70: 'char_traits单字节赋值，*dest=*src。',
    0x62BE90: '最大长度检查、容量与trim分流；返回AL为请求长度非零。',
    0x62BF70: '按容量<16返回S+4，否则返回DWORD[S+4]，与62BB80同型。',
    0x62BFC0: '释放传入指针；第二容量参数未被使用，不释放ECX。',
    0x62CA90: '检测Src处于[data,data+length)半开区间；无尾NUL包含。',
    0x62C850: '取62DD00值，无符号值>1时减一，本实例最大长度FFFFFFFE。',
    0x62C8C0: '舍入或1.5倍容量扩容；首次异常按精确长度重试，双失败清旧缓冲重抛。',
    0x62DD00: '返回FFFFFFFF常量；不是可分配内存量。',
    0x62DCC0: '向62E920传size及额外0；allocator包装不检查输入溢出。',
    0x62E920: '只消费size调用operator new，额外调用栈参数未在本函数消费。',
}
LOCAL = {
    0x91BE10: '构造invalid string position并抛out_of_range；异常对象依赖未展开。',
    0x91BDA0: '构造长度错误并抛length_error；异常对象依赖未展开。',
    0x79D3D0: '整源对象复制包装，pos=0、count=FFFFFFFF立即数；外层this保留。',
    0x88EE20: '字符串子串构造包装；初始化后复制源pos/count；完整外层业务未核。',
    0x691AB0: '28字节栈字符串构造与释放消费，调用期间保留对象；中间业务依赖未核。',
}


def main():
    rows = []
    for path in sorted((HERE / '证据').glob('string_*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        for f in data['functions']:
            va = int(f['va'], 16)
            status = ('静态契约已审阅' if va in CONTRACTS else
                      '局部消费契约已审阅' if va in LOCAL else '邻近或运行库仅导出')
            rows.append(dict(va=f['va'], status=status,
                             conclusion=CONTRACTS.get(va, LOCAL.get(va, '保存完整函数块与调用原证，未作完整语义审阅。')),
                             unknown=('没有实机/异常注入验证；本结论限定所列对象和函数。' if va in CONTRACTS else
                                      '调用依赖及外层完整语义不在本专题完成范围。'),
                             evidence=path.relative_to(HERE).as_posix()))
    assert len(rows) == len({r['va'] for r in rows})
    payload = dict(scope='静态函数契约、局部消费与邻近导出分别记录，不等价全程序完成',
                   counts=dict(collections.Counter(r['status'] for r in rows)), functions=rows)
    (HERE / '函数审阅清单.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(payload['counts'], ensure_ascii=False))


if __name__ == '__main__':
    main()
