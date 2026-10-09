"""生成显式逐函数台账与既有初始化局部原证；不从导出状态自动推导审阅结论。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CONTRACTS = {
    0x691AB0: ('构造栈键，对this+0x2F0默认插入查询，释放键后返回V。', 'R的创建和根析构未核。'),
    0x6950D0: ('lower_bound后检查end/键顺序；缺失时构造空V和pair并提示插入，返回payload+28。', '键比较底层、树分配器及erase未完整恢复。'),
    0x695300: ('转6953E0构造V并返回this。', '首字段运行含义未明。'),
    0x695330: ('转695440析构V。', '最终分配器释放实现另核。'),
    0x695360: ('先析构this+28处V，再析构this处键字符串；含异常清理尾块。', '整树erase的接入未核。'),
    0x6953E0: ('调用分配器辅助后以0调用696190，建立空V。', '6962F0/696330辅助未采集。'),
    0x695440: ('转696250清理V。', '697070/697170内部另核。'),
    0x695520: ('验证提示位置后调用696660插入，不合适时转6963F0；保存编译期跳过分支原证。', '外部迭代器helper未全采；不把不可达分支当当前执行路径。'),
    0x695CB0: ('转696BF0查候选，包装输出迭代器。', '迭代器helper实现未全采。'),
    0x695D00: ('转698430比较两个键对象。', '6986F0最终比较细节未采。'),
    0x695E40: ('转696E80取得迭代器payload。', '不证明外部索引有效性。'),
    0x695EA0: ('直接返回*this，取迭代器持有的节点地址。', '无本地合法性校验。'),
    0x695EC0: ('分别复制键和this+28处V。', 'V元素复制下游另核。'),
    0x696010: ('转696050复制V并返回this。', '底层元素复制另核。'),
    0x696050: ('按源size分配目标V，复制源区间并设置end；含失败清理与重抛尾块。', '698460元素复制实现未采。'),
    0x696190: ('清begin/end/capacity_end；正条数分配136*n，begin=end。', '697040/6970B0/6971B0最大值与分配实现另核。'),
    0x696250: ('清理[begin,end)，按capacity释放begin，再清三个指针。', '697070/697170内部未采；整树生命周期未核。'),
    0x696370: ('返回传入node+12，即payload地址。', 'node合法性由调用者保证。'),
    0x6963F0: ('沿键比较定位，前驱检查排除重复，返回(iterator,bool)插入结果。', '外部字段getter/前驱迭代器helper未全采。'),
    0x696660: ('最大节点数门控、分配节点、更新根/极值/计数、红黑树旋转着色及异常尾块。', '697650分配和整树删除实现未采；不是资源读取。'),
    0x696BF0: ('lower_bound形态：node.key<key走右，否则保存候选走左，遇哨兵返回。', '字段getter和键比较最终实现另核。'),
    0x696E80: ('从*this取节点，再转696370返回payload。', '无本地end/空节点检查。'),
    0x696FE0: ('begin非空时返回(end-begin)/136，否则0。', '不核指针损坏输入。'),
    0x697CE0: ('复制已有payload的键及+28处V；含键清理尾块。', '节点分配完整实现另核。'),
    0x698430: ('以字符串比较返回值<0作为严格小于谓词。', '最终字节比较6986F0未采，不推断区域排序规则。'),
    0x698570: ('取右键长度/缓冲，将this键长度和右键交6986F0比较。', '6986F0边界和编码比较规则另核。'),
    0x7AFE70: ('打开、解包、逐行解析，记录清零后按地图名查V并追加；成功/失败析构路径已保存。', '读取器、转码及动画解析另核；无sscanf成功数校验。'),
    0x7B4B50: ('memset(this,0,136)，返回this。', '不包含业务字段验证。'),
    0x7B4B90: ('size<capacity时追加1条并改end，否则经7B4D60插入扩容。', '最终元素构造7B6A00另核。'),
    0x7B4CC0: ('begin非空时返回(capacity_end-begin)/136，否则0。', '无指针有效性校验。'),
    0x7B4D20: ('取end建立输出迭代器。', '696D10具体迭代器包装未采。'),
    0x7B4D60: ('保存插入位置下标，调用7B5000插入1条，再据新begin恢复结果迭代器。', '695470/695DB0/7B57A0辅助另核；IDA安全数组签名误识别。'),
    0x7B4E20: ('调用复制构造n条，返回start+136*n。', '7B6A00实际构造另核。'),
    0x7B5000: ('136字节栈临时保源、原地或扩容插入、1.5倍容量候选及异常清理；更新三个指针。', '区间复制/赋值/销毁底层未全采。'),
    0x7B6750: ('先调用类型辅助，再转7B6A00构造记录区间。', '6988A0/7B6A00内部未采。'),
    0x7B6980: ('先经7B69D0销毁payload，删除标志低位为1时operator delete(this)。', '树erase/根析构是否调用此包装未核。'),
    0x7B69D0: ('转695360销毁payload。', '调用者完整生命周期未核。'),
}


def main():
    data = json.loads((HERE / '证据/functions.json').read_text(encoding='utf-8'))
    actual = {int(row['va'], 16) for row in data['functions']}
    if actual != CONTRACTS.keys():
        raise ValueError('逐函数人工结论与导出集合不一致')
    review = dict(scope='完整函数字节已核验；各函数仅将所列局部语义纳入人工结论，外部依赖另核。',
                  functions=[dict(va=hex(va), status='局部语义已审阅，完整字节已核验',
                                  conclusion=CONTRACTS[va][0], unknown=CONTRACTS[va][1],
                                  evidence='证据/functions.json#' + hex(va)) for va in sorted(actual)])
    (HERE / '函数审阅清单.json').write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    source_path = ROOT / 'docs/逆向资料/专题/股票与交易流程/证据/stock_core.json'
    source = json.loads(source_path.read_text(encoding='utf-8'))
    function = next(row for row in source['functions'] if row['va'] == '0x64f2a0')
    start, end = 0x64F355, 0x64F3B7
    span = next(row for row in function['byte_ranges']
                if int(row['va'], 16) <= start and int(row['va'], 16) + row['size'] >= end)
    offset = start - int(span['va'], 16)
    identity = dict(va=hex(start), size=end-start,
                    idb_hex=bytes.fromhex(span['idb_hex'])[offset:offset+end-start].hex(),
                    disk_hex=bytes.fromhex(span['disk_hex'])[offset:offset+end-start].hex())
    calls = [row for row in function['calls'] if start <= int(row['site'], 16) < end]
    targets = {name for row in calls for name in row['thunks']}
    external = dict(disk_sha256=source['disk_sha256'],
                    provenance='股票与交易流程/证据/stock_core.json；64F2A0仅局部挂接，不计为新完整函数',
                    byte_ranges=[identity],
                    assembly=[row for row in function['assembly'] if start <= int(row['va'], 16) < end],
                    calls=calls, thunks=[row for row in source['thunks'] if row['va'] in targets])
    (HERE / '证据/外部挂接.json').write_text(json.dumps(external, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(reviewed_functions=len(actual), external_span_bytes=end-start)))


if __name__ == '__main__':
    main()
