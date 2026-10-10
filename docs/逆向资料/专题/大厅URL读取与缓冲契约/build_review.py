"""按实际阅读边界生成显式审阅清单，不提升短依赖的覆盖状态。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FACTS = {
    0x81E0C0: ('静态主体契约已审阅', '只清缓冲指针和两个句柄，不清容量/读数'),
    0x81E100: ('静态主体契约已审阅', '保存ECX并经60AE82清理，伪码this缺失以汇编纠正'),
    0x81E130: ('静态主体契约已审阅', '清五字段后InternetOpenA，返回句柄非零'),
    0x81E1C0: ('静态主体契约已审阅', '删除缓冲、清容量读数并关闭两个句柄；无统一BOOL成功返回'),
    0x81E290: ('静态主体契约已审阅', 'URL打开、估计容量、单次读取与可选写盘；无EOF循环或NUL追加'),
    0x6B7290: ('静态主体契约已审阅', '仅清频道记录+4 BYTE，非完整308字节初始化'),
    0x6B7610: ('静态主体契约已审阅', '返回对象+272实际读数'),
    0x6B7640: ('静态主体契约已审阅', '返回对象+264缓冲指针'),
    0x629070: ('静态主体契约已审阅', '返回区域数组基址+3452*选择索引，无本体范围检查'),
    0x627060: ('静态主体契约已审阅', 'A76740懒单例分配12字节；构造依赖内部未追'),
    0x8198E0: ('静态主体契约已审阅', 'LF行复制、双字节与反引号n转换，写NUL后才断言容量'),
    0x819250: ('局部契约已审阅', 'mode2按明确长度精确分配复制；后处理内部未知'),
    0x623030: ('局部装配契约已审阅', '3452字节区域槽、num/reg/win真实字符串及四端点格式'),
    0x82C470: ('局部依赖契约已审阅', '调用字符串助手并写ACB83C端口，return1不证明连网'),
    0x87DFE0: ('局部分支已审阅', '按60E325返回BYTE分支；失败提示58/-143'),
    0x69EEE0: ('既有专题复用', '复用频道记录；本篇补URL+256和返回/长度/指针门控'),
    0x69F750: ('既有专题复用', '复用频道记录；本篇补URL+516和parser后处理参数1'),
    0x6A0130: ('既有专题复用', '复用频道记录；本篇补URL+516和parser后处理参数1'),
    0x731A90: ('局部消费者已审阅', 'news URL+1556及RnNews标题门控；后半排版与UI未认领'),
}


def main():
    rows = {}
    for name in ('functions_raw.json', 'consumers_raw.json', 'short_helpers_raw.json'):
        raw = json.loads((HERE / '证据' / name).read_text('utf-8'))
        for f in raw['functions']:
            va = int(f['va'], 16)
            if va in rows:
                rows[va]['evidence'].append('证据/' + name)
                continue
            status, conclusion = FACTS.get(va, ('仅导出待审阅', '保留上下文，不认领完整业务语义'))
            rows[va] = dict(va=hex(va), status=status, conclusion=conclusion,
                            unknown='边界见正文；外部依赖、实机网络、畸形输入结果未验证',
                            evidence=['证据/' + name])
            if status == '既有专题复用':
                rows[va]['reuse_reference'] = '../大厅区域频道配置/函数审阅清单.json'
    out = dict(schema=1, scope='11主体、5局部、3复用、其余仅导出；不认领完整网络层',
               functions=[rows[va] for va in sorted(rows)])
    (HERE / '函数审阅清单.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), 'utf-8')
    print(len(rows))


if __name__ == '__main__':
    main()
