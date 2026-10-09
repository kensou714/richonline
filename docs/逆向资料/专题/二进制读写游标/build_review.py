"""生成局部逐函数分级与中文说明；邻近候选不会自动提升为已审阅。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACTS = {
    '8673b0': '构造payloadSize+12自有包并追加原始正文；不是无头裸缓冲复制。',
    '867470': '有符号剩余量断言后memcpy，再做可抛出的写位置推进，返回this。',
    '867520': '返回this+14h减this+0Ch，即写limit减写位置。',
    '867570': '剩余可写量小于delta时抛异常，否则写位置加delta并返回旧值；没有拒绝负delta。',
    '867620': '以Buffer Overflow文本构造派生异常并设置虚表；不扩大为完整异常基类语义。',
    '867820': '返回this+1Ch基址加867880提供的写位置。',
    '867880': '返回this+0Ch的写位置。',
    '8678c0': '先调用867C40派生清理，再按删除标志低位决定是否delete对象this。',
    '867930': '析构薄包装到867980，继而抵达自有存储释放。',
    '867980': '析构薄包装到8679D0，不新增数据成员释放。',
    '8679d0': 'delete[]对象+20h保存的分配指针，再调用867A50基类清理。',
    '867a50': '重写基类虚表并调用867AB0，不释放+1Ch外部数据。',
    '867ab0': '只恢复基础虚表并返回this，不释放数据。',
    '867af0': '基础删除包装：清理后仅在标志低位为1时delete对象this。',
    '867b60': '视图层删除包装：基类清理后按标志决定delete对象this。',
    '867bd0': '自有层删除包装：先释放+20h数据，再按标志决定delete对象this。',
    '867c40': '派生析构薄包装，沿867930/867980到8679D0。',
    '867cd0': '分配正文+12字节，依次写10A1D85Fh、107、capacity-4；均为DWORD。',
    '867db0': '返回this+18h的完整32位capacity，不是AL字符。',
    '867df0': '构造自有缓冲并换派生虚表，容量由调用者Size传入。',
    '867e60': '分配Size字节到+20h，经868060接到基址+1Ch；分配前临时旧值不代表有效存储。',
    '867f50': '初始化位置/容量基类后借用外部base到+1Ch，不分配或复制。',
    '867fd0': '写虚表、r、w、limit、capacity，两标记置-1；没有范围校验。',
    '868060': '重置位置，更新capacity/limit及base；不分配、不改+20h拥有指针。',
    '8680e0': '两标记置-1，r/w置0，limit=capacity；不会清零数据区。',
    '868160': '仅当w<=新limit<=capacity时更新，否则抛位置范围异常。',
    '868200': '以Pos Out Of Range文本构造位置异常；异常基类资源细节另属专题。',
    '868390': '直接赋值capacity字段+18h，无范围验证。',
    '868450': '先调用867980释放数据层，再按标志低位释放this。',
    '8684c0': '先调用867930释放数据层，再按标志低位释放this。',
    '868530': '取第一个栈参数槽地址，固定复制4字节并返回this；char伪签名有误导。',
    '868590': '与868530同为4字节原始表示写入；未证明原始signed/unsigned重载名。',
    '868fb0': '构造type16正文4字节包，追加一个DWORD。',
    '869170': '构造type18正文16字节包，写四DWORD：0、1、参数、1。',
    '869b60': '12字节头模板：10A1D85Fh、16、capacity-4。',
    '869c40': '12字节头模板：10A1D85Fh、18、capacity-4。',
    '86be60': 'type48正文12字节，按传入顺序写三个DWORD。',
    '86c260': 'type56正文16字节，写1、两个参数、1四DWORD。',
    '86c440': '12字节头模板：10A1D85Fh、56、capacity-4。',
    '86c520': '12字节头模板：10A1D85Fh、48、capacity-4。',
    '871940': '先写NUL结尾字符串，再推进width-strlen-1；不补零、不截断，可能负向回退。',
    '8719c0': '按strlen+1写原始字符串及NUL，返回this。',
    '8795f0': '取第一个栈参数槽地址固定复制4字节；原始业务类型未恢复。',
    '879650': '固定复制相邻8个栈字节；调用者可传入浮点原始表示。',
    '87b080': '从参数缓冲取地址/可读长度，ECX调整为外层this+4后交内嵌socket对象发送。',
    '87b0f0': '返回w-r可读字节数，不是容量。',
    '87b140': '返回base+r裸读地址，不预检读取宽度。',
    '87b1a0': '返回读位置r字段+04。',
    '87b1e0': '从socket对象+08取SOCKET、+04取flags，调用send。',
    '87b260': 'socket对象flags访问器；与缓冲对象读位置虽偏移相同但对象不同。',
    '87bc60': '读外层type；1走虚表+4，其余消费第二DWORD，299交当前地址与剩余长度至虚表+8。',
    '87be40': '创建正文+8的type299包，再追加Src/Size原始正文。',
    '87c850': '返回基址加写位置，作为当前有效内容末地址。',
    '87c8b0': '从给定头指针+4取DWORD总长度，无独立范围或魔数检查。',
    '87c8f0': '只检查头+4长度<=1MiB；不检查正数、type或签名。',
    '87ca90': '构造8字节头：完整DWORD299与capacity；伪码43仅是低字节污染。',
    '87ccb0': '构造内嵌this+8的1MiB缓冲，limit=8，接收阶段+2Ch=0。',
    '87cd90': '重置内嵌缓冲、limit=8及阶段0。',
    '87ce00': '循环调用底层reader填满目标limit；非正返回立即传播，完成返回可读量。',
    '87d000': '取连续两个参数槽的8字节原始表示写入，返回this。',
    '87d060': '先从base+r读DWORD，再检查并推进4；成功返回DWORD。',
    '87d0d0': '可读量不足delta时抛异常，否则r+=delta并返回旧r；不拒绝负delta。',
    '87d180': '以Buffer Underflow文本构造派生异常并写虚表。',
    '87d380': 'DWORD读取与4字节推进；检查在读取之后，原始类型区分未知。',
    '87d3f0': '复制[sourceBegin,sourceEnd)到dest，返回dest+长度；没有目标容量参数。',
    '87e430': '正文144字节含三个DWORD、两段宽64字符串区和末DWORD。',
    '87e7d0': '正文136字节含两个DWORD及两段宽64字符串区。',
    '87f4d0': '把源缓冲当前可读区复制到目标；不推进源r，不转移源所有权。',
    '8929b0': '先读取8字节double，再推进8；以x87返回。',
    '892e60': '先读DWORD，再推进4；原始业务类型未知。',
    '893170': '先读WORD，再推进2；AX返回，符号扩展由调用者决定。',
    '8931e0': '读取两个DWORD组合64位结果，再推进8，EDX:EAX返回。',
    '91bd80': '分配薄包装转operator new；自动MFC函数名称不能作为事实。',
    '9234a0': 'CRT断言含Ignore返回路径，不能信任自动__noreturn签名或当成绝对安全门。',
}
PARTIAL = {
    '867040': '另一简单缓冲读DWORD；与本族+1Ch基址布局不同，未并入结构。',
    '867130': '另一简单缓冲显式memset后重置指针；不能给主缓冲器套用清零语义。',
    '86cff0': '确认批量写348字节栈结构，未闭合所有字段来源和有效初始化。',
    '871720': '确认DWORD、8字节浮点、32宽字符串及可变尾部组合；完整业务字段待解。',
    '87c660': '已复核两阶段长度接收及复制前后检查顺序；底层虚表所有实现未闭合。',
    '88ab00': '确认多DWORD、double、32/128字节游标消费；整体业务语义未完成。',
    '88acc0': '确认对应多字段读序列，传递业务参数的完整命名未恢复。',
    '8a56d0': '确认多宽度写与可变尾部，伪码浮点/整型污染需逐业务字段续查。',
    '8aa680': '确认从源可读量减4、写长度/0再复制源+4；短源边界需由调用者补证。',
    '8aa780': '与8AA680有同形拷贝序列；完整调用语境待补，不仅凭模板合并业务类型。',
    '8b9f50': '确认七DWORD前导及Size字节正文复制，正式消息名与数据来源尚未闭合。',
}


def main():
    entries = {}
    fingerprint = None
    for path in sorted((HERE / '证据').glob('cursor_*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        if 'functions' not in data:
            continue
        fingerprint = data['disk_sha256']
        for index, function in enumerate(data['functions']):
            key = function['va'][2:]
            entry = entries.setdefault(function['va'], dict(va=function['va'], status='', conclusion='', unknown='', evidence=[]))
            entry['evidence'].append('证据/' + path.name + '#/functions/' + str(index))
            if key in CONTRACTS:
                entry.update(status='静态契约已审阅', conclusion=CONTRACTS[key],
                             unknown='未执行实机异常或报文回归；正式源码类型、全部外部调用者约束不由本条证明。')
            elif key in PARTIAL:
                entry.update(status='局部消费契约已审阅', conclusion=PARTIAL[key],
                             unknown='仅本文指出的读写片段已审阅，不计为完整函数业务语义闭合。')
            else:
                entry.update(status='邻近候选仅导出', conclusion='已保存完整chunks与当前PE一致字节，尚未进行本专题逐路径语义审阅。',
                             unknown='邻近关系不证明所属同一类或协议，不能凭导出数累计语义完成量。')
    ordered = sorted(entries.values(), key=lambda r: int(r['va'], 16))
    output = dict(disk_sha256=fingerprint, scope='局部缓冲读写契约分级；不计为全部业务依赖闭合', functions=ordered)
    (HERE / '函数审阅清单.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['// ============================================================================',
             '// 二进制读写游标 / 逐函数结论', '// ============================================================================',
             '// 精确来源指针见函数审阅清单.json；正式导出包含完整chunks和块原始字节。',
             '// 未实机执行；仅导出的邻近项不在下方伪装成已审阅函数。', '//']
    for entry in ordered:
        if entry['status'] == '邻近候选仅导出':
            continue
        lines.extend(['// ' + entry['va'].upper() + ' / ' + entry['status'],
                      '//   ' + entry['conclusion'], '//   未知：' + entry['unknown'], '//'])
    (HERE / '04_逐函数结论.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return len(ordered)


if __name__ == '__main__':
    print(main())
