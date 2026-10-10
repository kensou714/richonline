"""固化人工结论与指令锚点；不生成未审函数的完成状态。"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
# 每项是人工逐读后的受限结论；锚点令复核者可直接返回关键机器指令。
ROWS = {
    '8ba7b0': ('完整声明块语义已审', '从全局发送reader重置、跳过2字节读取请求type；无空门。', 'reader取值契约复用；运行时有效性未验证。', [('8ba7db', ['push', '2'])]),
    '8ba8d0': ('完整声明块语义已审', '从全局发送reader重置、跳过6字节读取请求key。', '无容量门；调用会改变共享游标。', [('8ba8fb', ['push', '6'])]),
    '8bba00': ('完整声明块语义已审', '缓存命中返回1；否则构造type1/key10字节请求，替换44字节连接并append。', '容器深层与分配异常运行效果未验证。', [('8bbac3', ['push', '0x2c']), ('8bbb19', ['0xacbd64'])]),
    '8bbcd0': ('完整声明块语义已审', 'type2/key/Source42字节请求，替换单连接；append后清结果ACBD68。', 'Source业务身份、满32字符终止及运行效果未验证。', [('8bbd6b', ['push', '0x2c']), ('8bbe3c', ['0xacbd68', '0'])]),
    '8bc220': ('完整声明块语义已审', '用完整DWORD key查询ACBD70，未命中返回0，否则返回访问层指针。', '深层节点绝对地址与并发失效未闭合。', [('8bc271', ['je'])]),
    '8bc2c0': ('完整声明块语义已审', '用相同树/key门，未命中返回0，否则取访问层指针+4400的count。', '零count与未命中均可返回0；深层节点地址未闭合。', [('8bc325', ['0x1130'])]),
    '8ba510': ('完整声明块语义已审', '44字节连接初始化+8/+C/+10/+14/+28并构造+18容量8的reader。', '未初始化socket/event；reader末层初始化外依赖。', [('8ba547', ['0x10', '1']), ('8ba568', ['0x28', '0'])]),
    '8ba880': ('完整声明块语义已审', '将reader+0 base复制到+4读游标，返回this。', 'base有效性及全部调用场景未验证。', [('8ba8ab', ['[eax + 4]', 'edx'])]),
    '8bb270': ('完整声明块语义已审', '先调用成员析构8BA5B0，再按flags低位决定operator delete(this)。', '成员reader析构深层实现外依赖。', [('8bb29e', ['and', '1']), ('8bb2c5', ['ret', '4'])]),
    '8bb970': ('完整声明块语义已审', '构造0D0A/type0/keyFFFFFFFF及32字节预零区。', '请求业务名与Source编码未恢复。', [('8bb9a3', ['[eax + 2]', '0']), ('8bb9b4', ['0x20'])]),
    '8bbc60': ('完整声明块语义已审', '构造0D0A/type1/keyFFFFFFFF的10字节请求头。', '调用场景只取已保留窗口。', [('8bbc93', ['[eax + 2]', '1'])]),
    '8bbf10': ('完整声明块语义已审', '构造0D0A/type2/keyFFFFFFFF及32字节预零区。', 'Source身份与编码未知。', [('8bbf43', ['[eax + 2]', '2'])]),
    '8bcf20': ('完整块已读；依赖语义局部', '候选比较后缺键构造默认mapped/pair并hint插入；返回指针层结果+4。', 'lower_bound、hint插入及绝对节点地址仍外依赖。', [('8bcfa1', ['call', '0x5ffd43']), ('8bcfd7', ['add', '4'])]),
    '8bd130': ('完整声明块语义已审', '用树this+4构造end迭代器输出并返回输出地址。', '头节点全部字段及树生命周期未审。', [('8bd156', ['[eax + 4]'])]),
    '8bd240': ('完整块已读；依赖语义局部', '候选为end或比较返回1时输出end，否则复制候选首DWORD。', '候选搜索与key取址深层正文外依赖。', [('8bd290', ['jne']), ('8bd2ee', ['[eax]', 'edx'])]),
    '8bd430': ('完整声明块语义已审', '比较两个迭代器首DWORD，相等1否则0，ret4。', '指针有效性与容器失效边界未验证。', [('8bd45b', ['sub', '[ecx]']), ('8bd468', ['ret', '4'])]),
    '8bd480': ('完整声明块语义已审', '调用equality后对AL取反，得到不等布尔值。', '调用者迭代器有效性未验证。', [('8bd4aa', ['call', '0x60181e']), ('8bd4b6', ['inc'])]),
    '8cc5d0': ('完整块已读；依赖语义局部', '容量+0C，new(size)保存base+0，再调用初始化层8CC8A0。', '8CC920深层初始化与分配失败策略外依赖。', [('8cc5f9', ['[eax + 0xc]']), ('8cc61a', ['[edx]'])]),
    '8cc820': ('完整声明块语义已审', 'memcpy到reader+8，再推进+8游标Size；本体及已审助手无容量门。', '任意调用者的长度合法性未验证。', [('8cc854', ['call', '0x60e3e8']), ('8cc863', ['call', '0x60bfbc'])]),
    '8ba5b0': ('完整块已读；依赖语义局部', '对两动态reader调用flags1助手，+8非零时关闭event/socket，最后析构内嵌reader。', '8BA740/8CC660释放实现外依赖；实机句柄有效性未知。', [('8ba68a', ['je']), ('8ba695', ['0xad40cc']), ('8ba6aa', ['0xad40d0'])]),
    '8bafb0': ('完整声明块语义已审', '返回reader+8写游标。', '游标与分配容量关系由调用者维护。', [('8bafd6', ['[eax + 8]'])]),
    '8bb040': ('完整声明块语义已审', 'reader+8按参数相加，不校验容量，返回this。', '参数符号/有效范围依调用者。', [('8bb069', ['add'])]),
    '8bd060': ('完整块已读；依赖语义局部', '调用vector构造迭代器stride44/count100，随后mapped+4400 count置0。', '44字节元素构造和vector正文外依赖；不称全字段零。', [('8bd088', ['0x64']), ('8bd08a', ['0x2c']), ('8bd098', ['0x1130', '0'])]),
    '8bf550': ('完整块已读；依赖语义局部', '参数经8C2AD0再8C3510返回；用于候选key比较调用。', '两深层函数未在本批审阅，不能声称节点+12。', [('8bf572', ['call', '0x6094f6']), ('8bf57b', ['call', '0x612bd7'])]),
    '8bfd70': ('完整块已读；依赖语义局部', '调用8C3430取得候选并构造到输出迭代器。', '8C3430搜索规则、树布局未由此本体证明。', [('8bfd9a', ['call', '0x60e0be'])]),
    '8c00c0': ('完整声明块语义已审', '经8C3900将参数写迭代器首DWORD并返回this。', '传入节点指针有效性未验证。', [('8c00ea', ['call', '0x60551d'])]),
    '8c0120': ('完整块已读；依赖语义局部', '将this传8C3950并返回其结果。', '经8C2AD0所得绝对节点字段仍外依赖。', [('8c0146', ['call', '0x612beb'])]),
    '8c0170': ('完整声明块语义已审', '返回迭代器首DWORD。', '不推导其为已有效节点或pair。', [('8c0196', ['[eax]'])]),
    '8c04b0': ('完整声明块语义已审', '复制DWORD key到pair+0，复制4404字节mapped到pair+4。', 'pair源容量由调用者保证，节点分配总长未审。', [('8c04e6', ['0x44d']), ('8c04eb', ['rep movsd'])]),
    '8cc8a0': ('完整块已读；依赖语义局部', 'memset(base,0,capacity)，重置读游标，调用8CC920。', '8CC920末层写游标初始化外依赖。', [('8cc8d2', ['call', '0x60ffdb']), ('8cc8e5', ['call', '0x611895'])]),
    '8c3900': ('完整声明块语义已审', '将参数写this首DWORD，返回this，ret4。', '全部调用者指针身份未恢复。', [('8c3929', ['[eax]', 'ecx'])]),
    '8c3950': ('完整块已读；依赖语义局部', '取*this并传8C2AD0，返回其结果。', '8C2AD0本体未闭合，不推出N+12。', [('8c3976', ['[eax]']), ('8c3979', ['call', '0x6094f6'])]),
    '8bb2e0': ('历史复用主区间局部已审', '单连接非阻塞事件泵，失败回调后清全局；CLOSE错误字段读取READ下标。', '只复核主区间，完整异常尾块及实机回调重入未证。', []),
    '8bb090': ('历史复用主区间局部已审', 'WSAStartup2.2、地址端口和回调写入独立全局。', '只复核主区间，返回有效性与完整异常块未证。', []),
    '755de0': ('历史复用主区间局部已审', 'type0/1成功刷新UI105，type2按ACBD68范围显示文本，失败显示1055。', '真实业务中文文本及全部owner流程未恢复。', []),
    '8ba950': ('历史完整声明块复用已审', '响应type/L门，三类型正文消费，count数组循环及callback后阶段写入。', '数组count缺联合校验；静态风险未实机。', []),
    '8bb700': ('历史完整声明块复用已审', 'type0缓存门、42字节请求、单连接替换及32字节Source复制。', '缓存深层比较、Source业务名与异常运行效果未证。', []),
}


def main():
    names = ['formal_functions.json', 'dependency_raw.json', 'dependency_helpers_raw.json',
             'dependency_leaf_raw.json', 'reused_preparation.json']
    functions, source_hashes = [], {}
    for name in names:
        raw = (HERE / name).read_bytes()
        source_hashes[name] = hashlib.sha256(raw).hexdigest()
        for index, source in enumerate(json.loads(raw)['functions']):
            va = source['va']
            status, conclusion, unknown, anchors = ROWS[va[2:]]
            functions.append(dict(va=va, status=status, conclusion=conclusion, unknown=unknown,
                                  evidence='证据/' + name + '#/functions/' + str(index),
                                  evidence_refs=[dict(file=name, pointer='/functions/' + str(index))],
                                  semantic_anchors=[dict(va='0x' + at, tokens=tokens) for at, tokens in anchors]))
    windows = []
    for name, field in [('bounded_raw.json', 'explicit_owner_windows'), ('owner_context_raw.json', 'windows')]:
        data = json.loads((HERE / name).read_text('utf-8'))
        for index, window in enumerate(data[field]):
            first, last = window['assembly'][0], window['assembly'][-1]
            windows.append(dict(owner_va=window['owner_va'],
                                start_va=window.get('start_va', first['site_va']),
                                end_va=window.get('end_va', hex(int(last['site_va'], 16) + last['bytes']['size'])),
                                status='局部owner窗口；不计新函数',
                                evidence='证据/' + name + '#/' + field + '/' + str(index)))
    result = dict(disk_sha256=SHA, scope='32新入口本体+5历史业务复用；深层外依赖按局部限定',
                  source_sha256=source_hashes, functions=functions, owner_windows=windows,
                  historical_contracts='reused_preparation.json#/historical_contracts六项只作交叉引用，不新增计数')
    (HERE.parent / '函数审阅清单.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print('manual rows:', len(functions))


if __name__ == '__main__':
    main()
